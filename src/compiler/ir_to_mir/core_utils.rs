use super::*;
use crate::compiler::mir::AddressSpace;

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

    pub(super) fn emit_ptr_to_slot_copy(
        &mut self,
        dst_slot: StackSlotId,
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
            self.emit(MirInst::StoreSlot {
                slot: dst_slot,
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

    pub(super) fn materialize_context_pointer_arg(&mut self) -> VReg {
        let ctx_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadCtxField {
            dst: ctx_vreg,
            field: CtxField::Context,
            slot: None,
        });
        self.vreg_type_hints.insert(
            ctx_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        ctx_vreg
    }

    pub(super) fn invalidate_reg_value(&mut self, reg: RegId) {
        self.reg_map.remove(&reg.get());
        self.reg_metadata.remove(&reg.get());
    }

    pub(super) fn clear_source_var(&mut self, reg: RegId) {
        if let Some(meta) = self.reg_metadata.get_mut(&reg.get()) {
            meta.source_var = None;
        }
    }

    fn constant_literal_int(value: &Value) -> Option<i64> {
        match value {
            Value::Int { val, .. } => Some(*val),
            Value::Filesize { val, .. } => Some(val.get()),
            Value::Duration { val, .. } => Some(*val),
            _ => None,
        }
    }

    fn constant_literal_string(value: &Value) -> Option<String> {
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } => Some(val.clone()),
            Value::Binary { val, .. } => String::from_utf8(val.clone()).ok(),
            _ => None,
        }
    }

    pub(super) fn set_reg_constant_value(&mut self, reg: RegId, value: Option<Value>) {
        let meta = self.get_or_create_metadata(reg);
        meta.literal_int = value.as_ref().and_then(Self::constant_literal_int);
        meta.literal_string = value.as_ref().and_then(Self::constant_literal_string);
        meta.constant_value = value;
    }

    pub(super) fn bind_variable_to_src_value(
        &mut self,
        var_id: VarId,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<(), CompileError> {
        if let Some(src_meta) = self.get_metadata(src).cloned()
            && let Some((materialized_vreg, materialized_meta)) =
                self.materialize_metadata_record_value(&src_meta)?
        {
            self.var_mappings.insert(var_id, materialized_vreg);
            self.var_metadata.insert(var_id, materialized_meta);
            return Ok(());
        }

        let preserved = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved,
            src: MirValue::VReg(src_vreg),
        });
        self.var_mappings.insert(var_id, preserved);
        if let Some(meta) = self.get_metadata(src).cloned() {
            self.var_metadata.insert(var_id, meta);
        } else {
            self.var_metadata.remove(&var_id);
        }
        if let Some(ty) = self.vreg_type_hints.get(&src_vreg).cloned() {
            self.vreg_type_hints.insert(preserved, ty);
        }

        Ok(())
    }

    pub(super) fn direct_scalar_var_out_arg_type(
        &self,
        reg: RegId,
        vreg: VReg,
        fixed_size: usize,
    ) -> Option<MirType> {
        let ty = self
            .get_metadata(reg)
            .and_then(|meta| meta.field_type.clone())
            .or_else(|| self.vreg_type_hints.get(&vreg).cloned())?;
        let exact_match = match &ty {
            MirType::Bool => fixed_size == 1,
            MirType::I8 | MirType::U8 => fixed_size == 1,
            MirType::I16 | MirType::U16 => fixed_size == 2,
            MirType::I32 | MirType::U32 => fixed_size == 4,
            MirType::I64 | MirType::U64 => fixed_size == 8,
            _ => false,
        };
        exact_match.then_some(ty)
    }

    pub(super) fn write_back_direct_scalar_var(
        &mut self,
        var_id: VarId,
        scalar_ty: MirType,
        value_vreg: VReg,
    ) -> Result<(), CompileError> {
        if let Some(global) = self.annotated_mut_globals.get(&var_id).cloned() {
            if global.ty != scalar_ty
                || global.list_max_len.is_some()
                || global.string_slot_len.is_some()
            {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "kfunc out-arg write-back for annotated mutable variable {} requires matching scalar global storage",
                    var_id.get()
                )));
            }
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
            self.emit(MirInst::Store {
                ptr: global_ptr,
                offset: 0,
                val: MirValue::VReg(value_vreg),
                ty: scalar_ty,
            });
            return Ok(());
        }

        if let Some(global) = self.mutable_capture_globals.get(&var_id).cloned() {
            if global.ty != scalar_ty
                || global.list_max_len.is_some()
                || global.string_slot_len.is_some()
            {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "kfunc out-arg write-back for captured variable {} requires matching scalar global storage",
                    var_id.get()
                )));
            }
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
            self.emit(MirInst::Store {
                ptr: global_ptr,
                offset: 0,
                val: MirValue::VReg(value_vreg),
                ty: scalar_ty,
            });
            return Ok(());
        }

        let preserved = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved,
            src: MirValue::VReg(value_vreg),
        });
        self.vreg_type_hints.insert(preserved, scalar_ty.clone());
        self.var_mappings.insert(var_id, preserved);
        self.var_metadata.insert(
            var_id,
            RegMetadata {
                field_type: Some(scalar_ty),
                source_var: Some(var_id),
                ..Default::default()
            },
        );
        Ok(())
    }

    /// Get the current block being built
    pub(super) fn current_block_mut(&mut self) -> &mut BasicBlock {
        self.func.block_mut(self.current_block)
    }

    /// Add an instruction to the current block
    pub(super) fn emit(&mut self, inst: MirInst) {
        self.current_block_mut().instructions.push(inst);
    }

    pub(super) fn propagate_passthrough_reg_metadata(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        src_reg: RegId,
        src_vreg: VReg,
    ) {
        if let Some(meta) = self.get_metadata(src_reg).cloned() {
            self.reg_metadata.insert(dst_reg.get(), meta);
        }
        if let Some(ty) = self.vreg_type_hints.get(&src_vreg).cloned() {
            self.vreg_type_hints.insert(dst_vreg, ty);
        }
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

    pub(super) fn metadata_record_layout(meta: &RegMetadata) -> Option<MirType> {
        if meta.record_fields.is_empty() {
            return None;
        }

        let field_layouts: Vec<_> = meta
            .record_fields
            .iter()
            .map(|field| (field.name.clone(), field.ty.clone()))
            .collect();
        Some(Self::record_type_from_fields(&field_layouts))
    }

    pub(super) fn subfunction_arg_seed_for_value(
        &self,
        vreg: VReg,
        source_reg: Option<RegId>,
    ) -> SubfunctionArgSeed {
        let metadata = source_reg.and_then(|reg| self.get_metadata(reg).cloned());
        let type_hint = self.vreg_type_hints.get(&vreg).cloned().or_else(|| {
            metadata.as_ref().and_then(|meta| {
                meta.field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(meta))
            })
        });
        SubfunctionArgSeed {
            type_hint,
            metadata,
            synthetic_stack_slot: None,
        }
    }

    pub(super) fn metadata_record_semantics(meta: &RegMetadata) -> Option<AnnotatedValueSemantics> {
        if meta.record_fields.is_empty() {
            return None;
        }

        let field_semantics: Vec<_> = meta
            .record_fields
            .iter()
            .filter_map(|field| {
                field
                    .semantics
                    .clone()
                    .map(|semantics| (field.name.clone(), semantics))
            })
            .collect();
        (!field_semantics.is_empty()).then_some(AnnotatedValueSemantics::Record(field_semantics))
    }

    pub(super) fn materialize_metadata_record_value(
        &mut self,
        meta: &RegMetadata,
    ) -> Result<Option<(VReg, RegMetadata)>, CompileError> {
        let Some(record_ty) = Self::metadata_record_layout(meta) else {
            return Ok(None);
        };
        let size = record_ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(
                "storing an empty record value is not supported in eBPF".into(),
            ));
        }

        let slot = self
            .func
            .alloc_stack_slot(align_to_eight(size), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, record_ty.clone());

        let record_ptr = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: record_ptr,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            record_ptr,
            MirType::Ptr {
                pointee: Box::new(record_ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            },
        );

        let MirType::Struct { fields, .. } = &record_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "metadata-backed record materialization produced a non-struct type".into(),
            ));
        };

        for (record_field, layout_field) in meta
            .record_fields
            .iter()
            .zip(fields.iter().filter(|field| !field.synthetic))
        {
            match &record_field.ty {
                MirType::Array { .. } | MirType::Struct { .. } => {
                    let aggregate_field_vreg =
                        self.materialized_record_field_value_vreg(record_field)?;
                    let field_runtime_ty = self
                        .vreg_type_hints
                        .get(&aggregate_field_vreg)
                        .cloned()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "record field '{}' requires a materialized aggregate pointer value",
                                record_field.name
                            ))
                        })?;
                    let MirType::Ptr {
                        pointee,
                        address_space:
                            crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                    } = field_runtime_ty
                    else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "record field '{}' requires a materialized aggregate pointer value",
                            record_field.name
                        )));
                    };
                    if pointee.as_ref() != &record_field.ty {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "record field '{}' cannot store type {:?} into field of type {:?}",
                            record_field.name, pointee, record_field.ty
                        )));
                    }
                    self.emit_ptr_copy_with_offsets(
                        record_ptr,
                        layout_field.offset,
                        aggregate_field_vreg,
                        0,
                        record_field.ty.size(),
                    )?;
                }
                _ => {
                    self.emit(MirInst::StoreSlot {
                        slot,
                        offset: layout_field.offset as i32,
                        val: MirValue::VReg(record_field.value_vreg),
                        ty: record_field.ty.clone(),
                    });
                }
            }
        }

        let materialized_meta = RegMetadata {
            field_type: Some(record_ty),
            annotated_semantics: Self::metadata_record_semantics(meta),
            ..Default::default()
        };
        Ok(Some((record_ptr, materialized_meta)))
    }

    pub(super) fn materialized_record_field_value_vreg(
        &mut self,
        record_field: &RecordField,
    ) -> Result<VReg, CompileError> {
        let err = || {
            CompileError::UnsupportedInstruction(format!(
                "record field '{}' requires a materialized aggregate pointer value",
                record_field.name
            ))
        };

        let aggregate_vreg = if self.vreg_type_hints.contains_key(&record_field.value_vreg) {
            record_field.value_vreg
        } else if let Some(source_reg) = record_field.source_reg {
            let source_meta = self.get_metadata(source_reg).cloned().ok_or_else(err)?;
            self.materialize_metadata_record_value(&source_meta)?
                .map(|(materialized_vreg, _materialized_meta)| materialized_vreg)
                .ok_or_else(err)?
        } else {
            return Err(err());
        };

        let field_runtime_ty = self
            .vreg_type_hints
            .get(&aggregate_vreg)
            .cloned()
            .ok_or_else(err)?;
        let MirType::Ptr {
            pointee,
            address_space:
                crate::compiler::mir::AddressSpace::Stack | crate::compiler::mir::AddressSpace::Map,
        } = field_runtime_ty
        else {
            return Err(err());
        };

        if pointee.as_ref() != &record_field.ty {
            return Err(CompileError::UnsupportedInstruction(format!(
                "record field '{}' cannot store type {:?} into field of type {:?}",
                record_field.name, pointee, record_field.ty
            )));
        }

        Ok(aggregate_vreg)
    }

    pub(super) fn materialized_metadata_aggregate_vreg(
        &mut self,
        src_reg: RegId,
        src_vreg: VReg,
    ) -> Result<VReg, CompileError> {
        if let Some(src_meta) = self.get_metadata(src_reg).cloned()
            && let Some((materialized_vreg, _materialized_meta)) =
                self.materialize_metadata_record_value(&src_meta)?
        {
            return Ok(materialized_vreg);
        }

        Ok(src_vreg)
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

    pub(super) fn validate_named_map_value_type_for_map(
        map: &MapRef,
        ty: &MirType,
        context: &str,
    ) -> Result<(), CompileError> {
        #[derive(Clone)]
        struct ManagedField {
            path: String,
            offset: usize,
            depth: usize,
            in_array: bool,
            repeat: usize,
            pointee_name: Option<String>,
        }

        #[derive(Clone)]
        struct GraphField {
            path: String,
            offset: usize,
            depth: usize,
            in_array: bool,
            repeat: usize,
            type_name: &'static str,
            has_contains_metadata: bool,
        }

        fn collect_managed_fields(
            ty: &MirType,
            path: String,
            offset: usize,
            depth: usize,
            in_array: bool,
            repeat: usize,
            timers: &mut Vec<ManagedField>,
            spin_locks: &mut Vec<ManagedField>,
            wqs: &mut Vec<ManagedField>,
            refcounts: &mut Vec<ManagedField>,
            kptrs: &mut Vec<ManagedField>,
            graph_roots: &mut Vec<GraphField>,
            graph_nodes: &mut Vec<GraphField>,
        ) {
            if ty.is_bpf_timer_struct() {
                timers.push(ManagedField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    pointee_name: None,
                });
                return;
            }
            if ty.is_bpf_spin_lock_struct() {
                spin_locks.push(ManagedField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    pointee_name: None,
                });
                return;
            }
            if ty.is_bpf_wq_struct() {
                wqs.push(ManagedField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    pointee_name: None,
                });
                return;
            }
            if ty.is_bpf_refcount_struct() {
                refcounts.push(ManagedField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    pointee_name: None,
                });
                return;
            }
            if let Some(pointee_name) = ty.bpf_kptr_pointee_name() {
                kptrs.push(ManagedField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    pointee_name: Some(pointee_name.to_string()),
                });
                return;
            }
            if let Some(root) = ty.bpf_graph_root_info() {
                graph_roots.push(GraphField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    type_name: root.kind.root_struct_name(),
                    has_contains_metadata: true,
                });
                return;
            }
            if ty.is_bpf_list_head_struct() {
                graph_roots.push(GraphField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    type_name: "bpf_list_head",
                    has_contains_metadata: false,
                });
                return;
            }
            if ty.is_bpf_rb_root_struct() {
                graph_roots.push(GraphField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    type_name: "bpf_rb_root",
                    has_contains_metadata: false,
                });
                return;
            }
            if ty.is_bpf_list_node_struct() {
                graph_nodes.push(GraphField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    type_name: "bpf_list_node",
                    has_contains_metadata: false,
                });
                return;
            }
            if ty.is_bpf_rb_node_struct() {
                graph_nodes.push(GraphField {
                    path,
                    offset,
                    depth,
                    in_array,
                    repeat,
                    type_name: "bpf_rb_node",
                    has_contains_metadata: false,
                });
                return;
            }

            match ty {
                MirType::Struct { fields, .. } => {
                    for field in fields {
                        let field_path = if path.is_empty() {
                            field.name.clone()
                        } else {
                            format!("{}.{}", path, field.name)
                        };
                        collect_managed_fields(
                            &field.ty,
                            field_path,
                            offset.saturating_add(field.offset),
                            depth + 1,
                            in_array,
                            repeat,
                            timers,
                            spin_locks,
                            wqs,
                            refcounts,
                            kptrs,
                            graph_roots,
                            graph_nodes,
                        );
                    }
                }
                MirType::Array { elem, len } => {
                    collect_managed_fields(
                        elem,
                        format!("{path}[]"),
                        offset,
                        depth + 1,
                        true,
                        repeat.saturating_mul(*len),
                        timers,
                        spin_locks,
                        wqs,
                        refcounts,
                        kptrs,
                        graph_roots,
                        graph_nodes,
                    );
                }
                _ => {}
            }
        }

        fn total_occurrences(fields: &[ManagedField]) -> usize {
            fields.iter().map(|field| field.repeat.max(1)).sum()
        }

        fn total_graph_occurrences(fields: &[GraphField]) -> usize {
            fields.iter().map(|field| field.repeat.max(1)).sum()
        }

        let mut timers = Vec::new();
        let mut spin_locks = Vec::new();
        let mut wqs = Vec::new();
        let mut refcounts = Vec::new();
        let mut kptrs = Vec::new();
        let mut graph_roots = Vec::new();
        let mut graph_nodes = Vec::new();
        collect_managed_fields(
            ty,
            "value".to_string(),
            0,
            0,
            false,
            1,
            &mut timers,
            &mut spin_locks,
            &mut wqs,
            &mut refcounts,
            &mut kptrs,
            &mut graph_roots,
            &mut graph_nodes,
        );

        let spin_lock_count = total_occurrences(&spin_locks);
        if spin_lock_count > 0 {
            if !matches!(map.kind, MapKind::Hash | MapKind::Array) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains bpf_spin_lock, which is only supported for hash and array maps",
                    map.name
                )));
            }
            if spin_lock_count != 1 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must contain exactly one bpf_spin_lock field, got {}",
                    map.name, spin_lock_count
                )));
            }
            let lock = &spin_locks[0];
            if lock.depth == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must wrap bpf_spin_lock in a map-value record field",
                    map.name
                )));
            }
            if lock.depth != 1 || lock.in_array {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_spin_lock at '{}', but bpf_spin_lock must be a top-level map-value record field",
                    map.name, lock.path
                )));
            }
            if lock.offset % 4 != 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_spin_lock at byte offset {}, but bpf_spin_lock must be 4-byte aligned",
                    map.name, lock.offset
                )));
            }
        }

        let kptr_count = total_occurrences(&kptrs);
        if kptr_count > 0 {
            if !matches!(map.kind, MapKind::Hash | MapKind::Array | MapKind::LruHash) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains kptr fields, which are currently supported for hash, array, and lru-hash maps",
                    map.name
                )));
            }
            for kptr in &kptrs {
                let pointee_name = kptr.pointee_name.as_deref().unwrap_or("kernel object");
                if kptr.depth == 0 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' must wrap kptr:{} in a map-value record field",
                        map.name, pointee_name
                    )));
                }
                if kptr.depth != 1 || kptr.in_array {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' has kptr:{} at '{}', but kptr slots must be top-level map-value record fields",
                        map.name, pointee_name, kptr.path
                    )));
                }
                if kptr.offset % 8 != 0 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' has kptr:{} at byte offset {}, but kptr slots must be 8-byte aligned",
                        map.name, pointee_name, kptr.offset
                    )));
                }
            }
        }

        let timer_count = total_occurrences(&timers);
        if timer_count > 0 {
            if !matches!(map.kind, MapKind::Hash | MapKind::Array | MapKind::LruHash) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains bpf_timer, which is only supported for hash, array, and lru-hash maps",
                    map.name
                )));
            }
            let timer = &timers[0];
            if timer.depth == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must wrap bpf_timer in a map-value record field",
                    map.name
                )));
            }
            if let Some(timer) = timers.iter().find(|timer| timer.in_array) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_timer at '{}', but arrays of verifier-managed bpf_timer fields are not supported",
                    map.name, timer.path
                )));
            }
            if timer_count != 1 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must contain exactly one bpf_timer field, got {}",
                    map.name, timer_count
                )));
            }
            if timer.offset % 8 != 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_timer at byte offset {}, but bpf_timer must be 8-byte aligned",
                    map.name, timer.offset
                )));
            }
        }

        let wq_count = total_occurrences(&wqs);
        if wq_count > 0 {
            if !matches!(map.kind, MapKind::Hash | MapKind::Array | MapKind::LruHash) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains bpf_wq, which is only supported for hash, array, and lru-hash maps",
                    map.name
                )));
            }
            let wq = &wqs[0];
            if wq.depth == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must wrap bpf_wq in a map-value record field",
                    map.name
                )));
            }
            if let Some(wq) = wqs.iter().find(|wq| wq.in_array) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_wq at '{}', but arrays of verifier-managed bpf_wq fields are not supported",
                    map.name, wq.path
                )));
            }
            if wq_count != 1 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must contain exactly one bpf_wq field, got {}",
                    map.name, wq_count
                )));
            }
            if wq.offset % 8 != 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_wq at byte offset {}, but bpf_wq must be 8-byte aligned",
                    map.name, wq.offset
                )));
            }
        }

        let refcount_count = total_occurrences(&refcounts);
        if refcount_count > 0 {
            if !matches!(map.kind, MapKind::Hash | MapKind::Array | MapKind::LruHash) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains bpf_refcount, which is currently supported for hash, array, and lru-hash maps",
                    map.name
                )));
            }
            let refcount = &refcounts[0];
            if refcount.depth == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must wrap bpf_refcount in a map-value record field",
                    map.name
                )));
            }
            if let Some(refcount) = refcounts.iter().find(|refcount| refcount.in_array) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_refcount at '{}', but arrays of verifier-managed bpf_refcount fields are not supported",
                    map.name, refcount.path
                )));
            }
            if refcount_count != 1 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' must contain exactly one bpf_refcount field, got {}",
                    map.name, refcount_count
                )));
            }
            if refcount.depth != 1 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_refcount at '{}', but bpf_refcount must be a top-level map-value record field",
                    map.name, refcount.path
                )));
            }
            if refcount.offset % 4 != 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' has bpf_refcount at byte offset {}, but bpf_refcount must be 4-byte aligned",
                    map.name, refcount.offset
                )));
            }
        }

        let graph_node_count = total_graph_occurrences(&graph_nodes);
        if graph_node_count > 0 {
            let node = &graph_nodes[0];
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} for '{}' contains {} at '{}', but bpf_list_node/bpf_rb_node fields must live in named graph object schemas referenced by bpf_list_head/bpf_rb_root roots",
                map.name, node.type_name, node.path
            )));
        }

        let graph_root_count = total_graph_occurrences(&graph_roots);
        if graph_root_count > 0 {
            if let Some(root) = graph_roots.iter().find(|root| !root.has_contains_metadata) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} for '{}' contains {} at '{}', but graph roots require named object schema metadata so the compiler can emit a BTF contains:TYPE:FIELD declaration tag",
                    map.name, root.type_name, root.path
                )));
            }
            for root in &graph_roots {
                if root.depth == 0 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' must wrap {} in a map-value record field",
                        map.name, root.type_name
                    )));
                }
                if root.depth != 1 || root.in_array {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' has {} at '{}', but graph roots must be top-level map-value record fields",
                        map.name, root.type_name, root.path
                    )));
                }
                if root.offset % 8 != 0 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} for '{}' has {} at byte offset {}, but graph roots must be 8-byte aligned",
                        map.name, root.type_name, root.offset
                    )));
                }
            }
        }

        Ok(())
    }

    pub(super) fn register_named_map_key_type(&mut self, map: &MapRef, ty: &MirType) {
        let ty = self.stored_generic_map_value_type(ty);
        if self.conflicting_map_key_types.contains(map) {
            return;
        }

        match self.map_key_types.get(map) {
            Some(existing) if existing != &ty => {
                self.map_key_types.remove(map);
                self.conflicting_map_key_types.insert(map.clone());
            }
            Some(_) => {}
            None => {
                self.map_key_types.insert(map.clone(), ty);
            }
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

    pub(super) fn register_named_map_max_entries(&mut self, map: &MapRef, max_entries: u32) {
        if self.conflicting_map_max_entries.contains(map) {
            return;
        }

        match self.map_max_entries.get(map) {
            Some(existing) if *existing != max_entries => {
                self.map_max_entries.remove(map);
                self.conflicting_map_max_entries.insert(map.clone());
            }
            Some(_) => {}
            None => {
                self.map_max_entries.insert(map.clone(), max_entries);
            }
        }
    }

    pub(super) fn register_named_map_value_semantics(
        &mut self,
        map: &MapRef,
        semantics: &AnnotatedValueSemantics,
    ) {
        if self.conflicting_map_value_semantics.contains(map) {
            return;
        }

        match self.map_value_semantics.get(map) {
            Some(existing) if existing != semantics => {
                self.map_value_semantics.remove(map);
                self.conflicting_map_value_semantics.insert(map.clone());
            }
            Some(_) => {}
            None => {
                self.map_value_semantics
                    .insert(map.clone(), semantics.clone());
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

    pub(super) fn validated_named_map_value_type(
        &self,
        map: &MapRef,
        context: &str,
    ) -> Result<Option<MirType>, CompileError> {
        let Some(ty) = self.named_map_value_type(map) else {
            return Ok(None);
        };
        if self.externally_seeded_map_value_types.contains(map)
            || self.declared_map_value_types.contains(map)
        {
            Self::validate_named_map_value_type_for_map(map, ty, context)?;
        }
        Ok(Some(ty.clone()))
    }

    pub(super) fn named_map_key_type(&self, map: &MapRef) -> Option<&MirType> {
        if self.conflicting_map_key_types.contains(map) {
            None
        } else {
            self.map_key_types.get(map)
        }
    }

    pub(super) fn named_map_max_entries(&self, map: &MapRef) -> Option<u32> {
        if self.conflicting_map_max_entries.contains(map) {
            None
        } else {
            self.map_max_entries.get(map).copied()
        }
    }

    pub(super) fn named_map_value_semantics(
        &self,
        map: &MapRef,
    ) -> Option<&AnnotatedValueSemantics> {
        if self.conflicting_map_value_semantics.contains(map) {
            None
        } else {
            self.map_value_semantics.get(map)
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
