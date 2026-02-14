use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Compile map update (specialized for `count` command semantics).
    pub(super) fn compile_counter_map_update(
        &mut self,
        map_name: &str,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        // For count: lookup key, increment, update
        let key_size = if map_name == STRING_COUNTER_MAP_NAME {
            16
        } else {
            8
        };
        let total_size = key_size + 8; // key + value
        self.check_stack_space(total_size as i16)?;
        // Stack grows downward - decrement first
        self.stack_offset -= total_size as i16;
        let val_offset = self.stack_offset; // value at lower address
        let key_offset = self.stack_offset + 8; // key at higher address

        if key_size == 8 {
            // Store key to stack
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, key_reg));
        } else {
            // Copy 16-byte key from pointer
            for chunk in 0..2 {
                let offset = (chunk * 8) as i16;
                self.instructions
                    .push(EbpfInsn::ldxdw(EbpfReg::R0, key_reg, offset));
                self.instructions.push(EbpfInsn::stxdw(
                    EbpfReg::R10,
                    key_offset + offset,
                    EbpfReg::R0,
                ));
            }
        }

        // bpf_map_lookup_elem(map, key) -> value ptr or null
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If null, initialize to 0; else load and increment
        let jmp_to_init = self.instructions.len();
        self.instructions.push(EbpfInsn::jeq_imm(EbpfReg::R0, 0, 0)); // Placeholder

        // Load current value, increment
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R3, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R3, 1));
        let jmp_to_update = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0)); // Skip init

        // init: value = 1
        let init_idx = self.instructions.len();
        self.instructions[jmp_to_init] =
            EbpfInsn::jeq_imm(EbpfReg::R0, 0, (init_idx - jmp_to_init - 1) as i16);
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R3, 1));

        // update:
        let update_idx = self.instructions.len();
        self.instructions[jmp_to_update] = EbpfInsn::jump((update_idx - jmp_to_update - 1) as i16);

        // Store new value to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, val_offset, EbpfReg::R3));

        // bpf_map_update_elem(map, key, value, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, val_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    pub(super) fn register_counter_map_kind(
        &mut self,
        map_name: &str,
        kind: MapKind,
    ) -> Result<(), CompileError> {
        if !matches!(kind, MapKind::Hash | MapKind::PerCpuHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map '{}' only supports Hash/PerCpuHash kinds, got {:?}",
                map_name, kind
            )));
        }

        let slot = if map_name == COUNTER_MAP_NAME {
            &mut self.counter_map_kind
        } else if map_name == STRING_COUNTER_MAP_NAME {
            &mut self.string_counter_map_kind
        } else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "internal error: '{}' is not a counter map",
                map_name
            )));
        };

        if let Some(existing) = *slot {
            if existing != kind {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map '{}' used with conflicting kinds: {:?} vs {:?}",
                    map_name, existing, kind
                )));
            }
        } else {
            *slot = Some(kind);
        }

        Ok(())
    }

    pub(super) fn build_counter_map_def(
        &self,
        map_name: &str,
        kind: MapKind,
    ) -> Result<BpfMapDef, CompileError> {
        let key_size = if map_name == STRING_COUNTER_MAP_NAME {
            16
        } else {
            8
        };
        let value_size = 8;
        let max_entries = 10240;

        match kind {
            MapKind::Hash => Ok(BpfMapDef::hash(key_size, value_size, max_entries)),
            MapKind::PerCpuHash => Ok(BpfMapDef::per_cpu_hash(key_size, value_size, max_entries)),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "map '{}' only supports Hash/PerCpuHash kinds, got {:?}",
                map_name, kind
            ))),
        }
    }

    fn is_builtin_map_name(name: &str) -> bool {
        matches!(
            name,
            RINGBUF_MAP_NAME
                | COUNTER_MAP_NAME
                | STRING_COUNTER_MAP_NAME
                | HISTOGRAM_MAP_NAME
                | TIMESTAMP_MAP_NAME
                | KSTACK_MAP_NAME
                | USTACK_MAP_NAME
        )
    }

    fn supported_generic_map_kind(kind: MapKind) -> bool {
        matches!(
            kind,
            MapKind::Hash | MapKind::Array | MapKind::PerCpuHash | MapKind::PerCpuArray
        )
    }

    fn map_operand_layout(
        &self,
        vreg: VReg,
        what: &str,
        default_size: usize,
    ) -> Result<MapOperandLayout, CompileError> {
        let ty = self.current_types.get(&vreg);
        match ty {
            Some(MirType::Ptr { pointee, .. }) => {
                let size = match pointee.size() {
                    0 => default_size,
                    n => n,
                };
                Ok(MapOperandLayout::Pointer { size })
            }
            Some(ty) => {
                let size = match ty.size() {
                    0 => default_size,
                    n => n,
                };
                if size > 8 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} v{} has size {} bytes and must be passed as a pointer",
                        what, vreg.0, size
                    )));
                }
                Ok(MapOperandLayout::Scalar { size })
            }
            None => Ok(MapOperandLayout::Scalar { size: default_size }),
        }
    }

    fn value_ptr_size_from_lookup_dst(&self, dst: VReg) -> usize {
        match self.current_types.get(&dst) {
            Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
            _ => 8,
        }
    }

    fn allocate_stack_temp(&mut self, size: usize) -> Result<i16, CompileError> {
        let aligned = size.div_ceil(8) * 8;
        self.check_stack_space(aligned as i16)?;
        self.stack_offset -= aligned as i16;
        Ok(self.stack_offset)
    }

    fn emit_store_scalar_to_stack(
        &mut self,
        src: EbpfReg,
        offset: i16,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self
                .instructions
                .push(EbpfInsn::stxb(EbpfReg::R10, offset, src)),
            2 => self
                .instructions
                .push(EbpfInsn::stxh(EbpfReg::R10, offset, src)),
            4 => self
                .instructions
                .push(EbpfInsn::stxw(EbpfReg::R10, offset, src)),
            8 => self
                .instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported scalar map operand size {} bytes",
                    size
                )));
            }
        }
        Ok(())
    }

    fn emit_map_fd_load(&mut self, map_name: &str) {
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });
    }

    fn setup_map_key_arg(
        &mut self,
        key_reg: EbpfReg,
        layout: MapOperandLayout,
    ) -> Result<(), CompileError> {
        match layout {
            MapOperandLayout::Pointer { .. } => {
                if key_reg != EbpfReg::R2 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R2, key_reg));
                }
            }
            MapOperandLayout::Scalar { size } => {
                let key_offset = self.allocate_stack_temp(size)?;
                self.emit_store_scalar_to_stack(key_reg, key_offset, size)?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
            }
        }
        Ok(())
    }

    fn setup_map_value_arg(
        &mut self,
        value_reg: EbpfReg,
        layout: MapOperandLayout,
    ) -> Result<(), CompileError> {
        match layout {
            MapOperandLayout::Pointer { .. } => {
                if value_reg != EbpfReg::R3 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R3, value_reg));
                }
            }
            MapOperandLayout::Scalar { size } => {
                let value_offset = self.allocate_stack_temp(size)?;
                self.emit_store_scalar_to_stack(value_reg, value_offset, size)?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
            }
        }
        Ok(())
    }

    fn register_generic_map_spec(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key_size: usize,
        value_size: Option<usize>,
    ) -> Result<(), CompileError> {
        if Self::is_builtin_map_name(&map.name) {
            return Ok(());
        }
        if !Self::supported_generic_map_kind(map.kind) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map operations do not support map kind {:?} for '{}'",
                map.kind, map.name
            )));
        }

        let mut inferred_key_size = key_size.max(1) as u32;
        if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
            inferred_key_size = 4;
        }
        let (inferred_value_size, defaulted) = match value_size {
            Some(size) => (size.max(1) as u32, false),
            None => (8, true),
        };

        match self.generic_map_specs.get_mut(&map.name) {
            Some(spec) => {
                if spec.kind != map.kind {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map '{}' used with conflicting kinds: {:?} vs {:?}",
                        map.name, spec.kind, map.kind
                    )));
                }
                if spec.key_size != inferred_key_size {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map '{}' used with conflicting key sizes: {} vs {}",
                        map.name, spec.key_size, inferred_key_size
                    )));
                }
                if spec.value_size != inferred_value_size {
                    if spec.value_size_defaulted && !defaulted {
                        spec.value_size = inferred_value_size;
                        spec.value_size_defaulted = false;
                    } else if !(defaulted && !spec.value_size_defaulted) {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map '{}' used with conflicting value sizes: {} vs {}",
                            map.name, spec.value_size, inferred_value_size
                        )));
                    }
                }
            }
            None => {
                self.generic_map_specs.insert(
                    map.name.clone(),
                    MapLayoutSpec {
                        kind: map.kind,
                        key_size: inferred_key_size,
                        value_size: inferred_value_size,
                        value_size_defaulted: defaulted,
                    },
                );
            }
        }

        Ok(())
    }

    pub(super) fn build_generic_map_def(
        &self,
        spec: MapLayoutSpec,
    ) -> Result<BpfMapDef, CompileError> {
        let max_entries = 10240;
        let map_def = match spec.kind {
            MapKind::Hash => BpfMapDef::hash(spec.key_size, spec.value_size, max_entries),
            MapKind::Array => BpfMapDef::array(spec.value_size, max_entries),
            MapKind::PerCpuHash => {
                BpfMapDef::per_cpu_hash(spec.key_size, spec.value_size, max_entries)
            }
            MapKind::PerCpuArray => BpfMapDef::per_cpu_array(spec.value_size, max_entries),
            other => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map kind {:?} is not supported for generic map operations",
                    other
                )));
            }
        };
        Ok(map_def)
    }

    pub(super) fn compile_generic_map_lookup(
        &mut self,
        dst: VReg,
        dst_reg: EbpfReg,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        let value_size = self.value_ptr_size_from_lookup_dst(dst);
        self.register_generic_map_spec(map, key_size, Some(value_size))?;

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));
        if dst_reg != EbpfReg::R0 {
            self.instructions
                .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R0));
        }
        Ok(())
    }

    pub(super) fn compile_generic_map_update(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
        val: VReg,
        val_reg: EbpfReg,
        flags: u64,
    ) -> Result<(), CompileError> {
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let val_layout = self.map_operand_layout(val, "map value", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        let value_size = match val_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        self.register_generic_map_spec(map, key_size, Some(value_size))?;
        if flags > i32::MAX as u64 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map update flags {} exceed supported 32-bit immediate range",
                flags
            )));
        }

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.setup_map_value_arg(val_reg, val_layout)?;
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R4, flags as i32));
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));
        Ok(())
    }

    pub(super) fn compile_generic_map_delete(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for array map kind {:?} ('{}')",
                map.kind, map.name
            )));
        }
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        self.register_generic_map_spec(map, key_size, None)?;

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapDeleteElem));
        Ok(())
    }
}
