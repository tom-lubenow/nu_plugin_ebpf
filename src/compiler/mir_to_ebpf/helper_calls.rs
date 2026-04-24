use super::*;
use crate::compiler::mir::AddressSpace;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn register_single_emit_schema(
        &mut self,
        data: VReg,
        size: usize,
    ) -> Result<(), CompileError> {
        let event_size = if size > 0 { size } else { 8 };
        if let Some(new_schema) = self
            .current_types
            .get(&data)
            .and_then(|ty| self.single_emit_struct_schema(ty, event_size))
        {
            if let Some(existing) = &self.event_schema {
                if existing != &new_schema {
                    return Err(CompileError::UnsupportedInstruction(
                        "emit schema mismatch: multiple event payload shapes in one program".into(),
                    ));
                }
            } else {
                self.event_schema = Some(new_schema);
            }
            return Ok(());
        }

        let field_type = self
            .current_types
            .get(&data)
            .map(|ty| self.single_emit_value_field_type(ty, event_size))
            .unwrap_or_else(|| {
                if event_size == 8 {
                    BpfFieldType::Int {
                        size: 8,
                        signed: true,
                    }
                } else {
                    BpfFieldType::Bytes(event_size)
                }
            });

        let new_schema = EventSchema {
            fields: vec![SchemaField {
                name: "value".to_string(),
                field_type,
                value_schema: self.single_emit_recursive_value_schema(data),
                offset: 0,
                bitfield: None,
            }],
            total_size: event_size,
        };

        if let Some(existing) = &self.event_schema {
            if existing != &new_schema {
                return Err(CompileError::UnsupportedInstruction(
                    "emit schema mismatch: multiple event payload shapes in one program".into(),
                ));
            }
        } else {
            self.event_schema = Some(new_schema);
        }

        Ok(())
    }

    fn single_emit_struct_schema(&self, ty: &MirType, event_size: usize) -> Option<EventSchema> {
        let fields = match ty {
            MirType::Struct { fields, .. } if ty.size() == event_size => fields,
            MirType::Ptr { pointee, .. } if pointee.size() == event_size => {
                match pointee.as_ref() {
                    MirType::Struct { fields, .. } => fields,
                    _ => return None,
                }
            }
            _ => return None,
        };

        if fields.len() == 1
            && fields[0].name == "__opaque"
            && !fields[0].synthetic
            && fields[0].offset == 0
        {
            return None;
        }

        let schema_fields: Vec<SchemaField> = fields
            .iter()
            .filter(|field| !field.synthetic)
            .map(|field| SchemaField {
                name: field.name.clone(),
                field_type: self.native_layout_bpf_field_type(&field.ty),
                value_schema: self.recursive_event_value_schema(&field.ty),
                offset: field.offset,
                bitfield: field.bitfield,
            })
            .collect();
        if schema_fields.is_empty() {
            return None;
        }

        Some(EventSchema {
            fields: schema_fields,
            total_size: event_size,
        })
    }

    fn single_emit_value_field_type(&self, ty: &MirType, event_size: usize) -> BpfFieldType {
        match ty {
            MirType::I64 | MirType::I32 | MirType::I16 | MirType::I8 => BpfFieldType::Int {
                size: event_size.min(8),
                signed: true,
            },
            MirType::Ptr { pointee, .. }
                if pointee.byte_array_len() == Some(16) && event_size == 16 =>
            {
                BpfFieldType::Comm
            }
            MirType::Ptr { pointee, .. }
                if pointee.byte_array_len().is_some() && pointee.size() == event_size =>
            {
                BpfFieldType::String
            }
            MirType::Ptr { pointee, .. }
                if matches!(
                    pointee.as_ref(),
                    MirType::Array { .. } | MirType::Struct { .. }
                ) && pointee.size() == event_size =>
            {
                BpfFieldType::Bytes(event_size)
            }
            MirType::U64
            | MirType::U32
            | MirType::U16
            | MirType::U8
            | MirType::Bool
            | MirType::Ptr { .. }
            | MirType::MapRef { .. } => BpfFieldType::Int {
                size: event_size.min(8),
                signed: false,
            },
            _ => {
                let (field_type, _) = self.mir_type_to_bpf_field(ty);
                match field_type {
                    BpfFieldType::Int { .. } if event_size == 8 => BpfFieldType::Int {
                        size: 8,
                        signed: matches!(
                            ty,
                            MirType::I64 | MirType::I32 | MirType::I16 | MirType::I8
                        ),
                    },
                    BpfFieldType::Int { .. } => BpfFieldType::Bytes(event_size),
                    other => other,
                }
            }
        }
    }

    fn native_layout_bpf_field_type(&self, ty: &MirType) -> BpfFieldType {
        match ty {
            MirType::I8 => BpfFieldType::Int {
                size: 1,
                signed: true,
            },
            MirType::I16 => BpfFieldType::Int {
                size: 2,
                signed: true,
            },
            MirType::I32 => BpfFieldType::Int {
                size: 4,
                signed: true,
            },
            MirType::I64 => BpfFieldType::Int {
                size: 8,
                signed: true,
            },
            MirType::U8 | MirType::Bool => BpfFieldType::Int {
                size: 1,
                signed: false,
            },
            MirType::U16 => BpfFieldType::Int {
                size: 2,
                signed: false,
            },
            MirType::U32 => BpfFieldType::Int {
                size: 4,
                signed: false,
            },
            MirType::U64
            | MirType::Ptr { .. }
            | MirType::MapRef { .. }
            | MirType::Subprogram { .. }
            | MirType::Unknown => BpfFieldType::Int {
                size: 8,
                signed: false,
            },
            ty if ty.byte_array_len() == Some(16) => BpfFieldType::Comm,
            ty if ty.byte_array_len().is_some() => BpfFieldType::String,
            MirType::Array { .. } | MirType::Struct { .. } => BpfFieldType::Bytes(ty.size().max(1)),
        }
    }

    fn recursive_event_value_schema(&self, ty: &MirType) -> Option<CounterKeySchema> {
        match ty {
            MirType::Array { .. } | MirType::Struct { .. } => {
                let schema = CounterKeySchema::from_mir_type(ty);
                match schema {
                    CounterKeySchema::Array { .. } | CounterKeySchema::Record { .. } => {
                        Some(schema)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn single_emit_recursive_value_schema(&self, data: VReg) -> Option<CounterKeySchema> {
        match self.current_types.get(&data) {
            Some(MirType::Ptr { pointee, .. }) => self.recursive_event_value_schema(pointee),
            Some(ty) => self.recursive_event_value_schema(ty),
            None => None,
        }
    }

    pub(super) fn vreg_stack_or_map_copy_size(
        &self,
        vreg: VReg,
        requested_size: usize,
    ) -> Option<usize> {
        match self.current_types.get(&vreg) {
            Some(MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            }) => Some(match pointee.as_ref() {
                MirType::Array { .. } | MirType::Struct { .. } => pointee.size().max(1),
                _ => requested_size.max(1),
            }),
            _ => None,
        }
    }

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
        self.relocations.push(SymbolRelocation {
            insn_offset: reloc_offset,
            symbol_name: map_name.to_string(),
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
        self.relocations.push(SymbolRelocation {
            insn_offset: reloc_offset,
            symbol_name: map_name.to_string(),
        });

        self.instructions.push(EbpfInsn::call(BpfHelper::TailCall));
        Ok(())
    }

    /// Compile emit event to ring buffer
    pub(super) fn compile_emit_event(
        &mut self,
        data_reg: EbpfReg,
        size: usize,
        data_copy_size: Option<usize>,
    ) -> Result<(), CompileError> {
        let event_size = if size > 0 { size } else { 8 };
        let aligned_event_size = event_size.div_ceil(8) * 8;
        self.check_stack_space(aligned_event_size as i16)?;
        // Stack grows downward - decrement first, then use offset
        self.stack_offset -= aligned_event_size as i16;
        let event_offset = self.stack_offset;

        if let Some(data_copy_size) = data_copy_size {
            let copy_size = event_size.min(data_copy_size);
            if copy_size > 0 {
                self.emit_copy_bytes(
                    data_reg,
                    0,
                    EbpfReg::R10,
                    event_offset,
                    copy_size,
                    EbpfReg::R0,
                )?;
            }
            if copy_size < event_size {
                let pad_offset = self.add_i16_offset(event_offset, copy_size)?;
                self.emit_zero_bytes(
                    EbpfReg::R10,
                    pad_offset,
                    event_size - copy_size,
                    EbpfReg::R0,
                )?;
            }
        } else if event_size <= 8 {
            // Store scalar data to stack
            self.emit_store(EbpfReg::R10, event_offset, data_reg, event_size)?;
        } else {
            return Err(CompileError::UnsupportedInstruction(
                "emit size larger than 8 bytes expects stack/map pointer input".into(),
            ));
        }

        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(SymbolRelocation {
            insn_offset: reloc_offset,
            symbol_name: RINGBUF_MAP_NAME.to_string(),
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
                value_schema: self.recursive_event_value_schema(&field.ty),
                offset,
                bitfield: None,
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
            let field_copy_size = self.vreg_stack_or_map_copy_size(field.value, size);

            if let Some(field_copy_size) = field_copy_size {
                let copy_size = size.min(field_copy_size);
                if copy_size > 0 {
                    self.emit_copy_bytes(
                        field_reg,
                        0,
                        EbpfReg::R10,
                        dest_offset,
                        copy_size,
                        EbpfReg::R0,
                    )?;
                }
                if copy_size < size {
                    let pad_offset = self.add_i16_offset(dest_offset, copy_size)?;
                    self.emit_zero_bytes(EbpfReg::R10, pad_offset, size - copy_size, EbpfReg::R0)?;
                }
            } else {
                self.emit_store(EbpfReg::R10, dest_offset, field_reg, size)?;
            }

            dest_offset += size as i16;
        }

        // Emit the buffer via ring buffer
        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(SymbolRelocation {
            insn_offset: reloc_offset,
            symbol_name: RINGBUF_MAP_NAME.to_string(),
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
            MirType::I64 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: true,
                },
                8,
            ),
            MirType::U64 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: false,
                },
                8,
            ),
            // I32 still uses 8 bytes for stack alignment
            MirType::I32 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: true,
                },
                8,
            ),
            MirType::U32 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: false,
                },
                8,
            ),
            MirType::I16 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: true,
                },
                8,
            ),
            MirType::U16 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: false,
                },
                8,
            ),
            MirType::I8 => (
                BpfFieldType::Int {
                    size: 8,
                    signed: true,
                },
                8,
            ),
            MirType::U8 | MirType::Bool => (
                BpfFieldType::Int {
                    size: 8,
                    signed: false,
                },
                8,
            ),
            ty if ty.byte_array_len() == Some(16) => (BpfFieldType::Comm, 16),
            ty if ty.byte_array_len().is_some() => {
                let len = ty
                    .byte_array_len()
                    .expect("byte-array length must exist after guard");
                // Round up to 8-byte alignment
                let aligned_len = (len + 7) & !7;
                (BpfFieldType::String, aligned_len)
            }
            MirType::Array { .. } | MirType::Struct { .. } => {
                (BpfFieldType::Bytes(ty.size().max(1)), ty.size().max(1))
            }
            _ => (
                BpfFieldType::Int {
                    size: 8,
                    signed: false,
                },
                8,
            ), // Default to 64-bit int
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
