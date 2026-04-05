use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn named_program_global_symbol(name: &str) -> String {
        format!("__nu_global_{}", name)
    }

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

    pub(super) fn named_program_global(&self, name: &str) -> Option<&MutableCaptureGlobal> {
        self.named_program_globals.get(name)
    }

    fn infer_mutable_global_layout(
        &self,
        symbol: String,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        if let Some(meta) = self.get_metadata(src) {
            if let Some((_, max_len)) = meta.list_buffer {
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: max_len.saturating_add(1),
                    },
                    list_max_len: Some(max_len),
                    string_slot_len: None,
                });
            }

            if let Some(slot) = meta.string_slot {
                let slot_len = self.stack_slot_size(slot).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "string slot not found during mutable global layout inference".into(),
                    )
                })?;
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 8 + slot_len,
                    },
                    list_max_len: None,
                    string_slot_len: Some(slot_len),
                });
            }

            if let Some(field_ty) = meta.field_type.clone() {
                let stored_ty = self.stored_generic_map_value_type(&field_ty);
                if matches!(
                    stored_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                        | MirType::Array { .. }
                        | MirType::Struct { .. }
                ) {
                    return Ok(MutableCaptureGlobal {
                        symbol,
                        ty: stored_ty,
                        list_max_len: None,
                        string_slot_len: None,
                    });
                }
            }
        }

        let fallback_ty = self
            .vreg_type_hints
            .get(&src_vreg)
            .cloned()
            .map(|ty| self.stored_generic_map_value_type(&ty))
            .or_else(|| {
                self.get_metadata(src)
                    .and_then(|m| m.literal_int.map(|_| MirType::I64))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "global-set requires a value with a known fixed layout".into(),
                )
            })?;

        match fallback_ty {
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::Bool
            | MirType::Array { .. }
            | MirType::Struct { .. } => Ok(MutableCaptureGlobal {
                symbol,
                ty: fallback_ty,
                list_max_len: None,
                string_slot_len: None,
            }),
            _ => Err(CompileError::UnsupportedInstruction(
                "global-set requires a scalar, string, fixed binary, numeric list, or representable aggregate value".into(),
            )),
        }
    }

    pub(super) fn ensure_named_program_global(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let inferred = self.infer_mutable_global_layout(symbol.clone(), src, src_vreg)?;

        if let Some(existing) = self.named_program_globals.get(name) {
            if existing != &inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            return Ok(existing.clone());
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        self.bss_globals.push(BssGlobal { name: symbol, size });
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        Ok(inferred)
    }

    pub(super) fn load_mutable_global_value(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        global: &MutableCaptureGlobal,
    ) -> Result<(), CompileError> {
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        let global_ptr_ty = MirType::Ptr {
            pointee: Box::new(global.ty.clone()),
            address_space: crate::compiler::mir::AddressSpace::Map,
        };
        self.vreg_type_hints
            .insert(global_ptr, global_ptr_ty.clone());

        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        if let Some(max_len) = global.list_max_len {
            let buffer_size = (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
            let slot = self
                .func
                .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
            self.record_list_buffer_slot_type(slot, max_len);
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(slot),
            });
            let stack_list_ptr_ty = MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_list_ptr_ty);
            self.emit_ptr_copy(dst_vreg, global_ptr, global.ty.size())?;
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
            meta.list_buffer = Some((slot, max_len));
        } else if let Some(slot_len) = global.string_slot_len {
            let slot = self
                .func
                .alloc_stack_slot(slot_len, 8, StackSlotKind::StringBuffer);
            self.record_stack_slot_type(
                slot,
                MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                },
            );
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(slot),
            });
            let stack_string_ptr_ty = MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_string_ptr_ty);
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Load {
                dst: len_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: MirType::U64,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);
            self.emit_ptr_copy_with_offsets(dst_vreg, 0, global_ptr, 8, slot_len)?;
            let meta = self.get_or_create_metadata(dst);
            meta.string_slot = Some(slot);
            meta.string_len_vreg = Some(len_vreg);
            meta.string_len_bound = Some(slot_len.saturating_sub(1));
            meta.field_type = Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: slot_len,
            });
        } else if matches!(global.ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(global_ptr),
            });
            self.vreg_type_hints.insert(dst_vreg, global_ptr_ty);
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        } else {
            self.emit(MirInst::Load {
                dst: dst_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: global.ty.clone(),
            });
            self.vreg_type_hints.insert(dst_vreg, global.ty.clone());
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        }

        Ok(())
    }

    pub(super) fn store_into_mutable_global(
        &mut self,
        context: &str,
        global: &MutableCaptureGlobal,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<(), CompileError> {
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        self.vreg_type_hints.insert(
            global_ptr,
            MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Map,
            },
        );

        if let Some(max_len) = global.list_max_len {
            let Some((slot, src_max_len)) = self.get_metadata(src).and_then(|m| m.list_buffer)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized numeric list value",
                    context
                )));
            };

            if src_max_len != max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing numeric list of capacity {} into {} with capacity {} is not supported",
                    src_max_len, context, max_len
                )));
            }

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(global.ty.clone()),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy(global_ptr, src_ptr, global.ty.size())?;
        } else if let Some(slot_len) = global.string_slot_len {
            let src_meta = self.get_metadata(src).cloned();
            let Some(meta) = src_meta else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(slot) = meta.string_slot else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(len_vreg) = meta.string_len_vreg else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a tracked string length",
                    context
                )));
            };
            let src_slot_size = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during mutable global store".into(),
                )
            })?;
            if src_slot_size > slot_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing string buffer of size {} into {} with capacity {} is not supported",
                    src_slot_size, context, slot_len
                )));
            }

            self.emit(MirInst::Store {
                ptr: global_ptr,
                offset: 0,
                val: MirValue::VReg(len_vreg),
                ty: MirType::U64,
            });

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: src_slot_size,
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy_with_offsets(global_ptr, 8, src_ptr, 0, src_slot_size)?;
            if src_slot_size < slot_len {
                self.emit_ptr_zero(global_ptr, 8 + src_slot_size, slot_len - src_slot_size)?;
            }
        } else {
            match &global.ty {
                MirType::Array { .. } | MirType::Struct { .. } => {
                    let Some(src_runtime_ty) = self.vreg_type_hints.get(&src_vreg).cloned() else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a materialized aggregate pointer value",
                            context
                        )));
                    };

                    let Some(MirType::Ptr {
                        pointee,
                        address_space:
                            crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                    }) = Some(src_runtime_ty)
                    else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a stack/map aggregate pointer value",
                            context
                        )));
                    };

                    if pointee.as_ref() != &global.ty {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing type {:?} into {} of type {:?} is not supported",
                            pointee, context, global.ty
                        )));
                    }

                    self.emit_ptr_copy(global_ptr, src_vreg, global.ty.size())?;
                }
                _ => {
                    self.emit(MirInst::Store {
                        ptr: global_ptr,
                        offset: 0,
                        val: MirValue::VReg(src_vreg),
                        ty: global.ty.clone(),
                    });
                }
            }
        }

        Ok(())
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
