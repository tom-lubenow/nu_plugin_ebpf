use super::user_functions::UserFunctionCallArg;
use super::*;

#[derive(Debug, Clone, Copy)]
struct SharedInlinedStringReturn {
    slot: StackSlotId,
    len_vreg: VReg,
    slot_len: usize,
    content_cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct SharedInlinedListReturn {
    slot: StackSlotId,
    max_len: usize,
}

impl<'a> HirToMirLowering<'a> {
    fn captured_value(&self, var_id: nu_protocol::VarId) -> Option<&Value> {
        self.captures
            .iter()
            .find_map(|(captured_var_id, value)| (*captured_var_id == var_id).then_some(value))
    }

    fn normalize_inlined_string_return(
        &mut self,
        dst_vreg: VReg,
        meta: &RegMetadata,
        shared_return: &mut Option<SharedInlinedStringReturn>,
    ) -> Result<(VReg, RegMetadata), CompileError> {
        let src_slot = meta.string_slot.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "inlined string return requires a tracked string slot".into(),
            )
        })?;
        let src_len_vreg = meta.string_len_vreg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "inlined string return requires a tracked string length".into(),
            )
        })?;
        let src_slot_len = self.stack_slot_size(src_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "string slot not found during inlined return normalization".into(),
            )
        })?;
        let src_content_cap = meta
            .string_len_bound
            .unwrap_or(src_slot_len.saturating_sub(1));

        let shared = if let Some(shared) = shared_return {
            if src_slot_len > shared.slot_len || src_content_cap > shared.content_cap {
                return Err(CompileError::UnsupportedInstruction(
                    "multiblock inlined string returns currently require compatible capacities"
                        .into(),
                ));
            }
            *shared
        } else {
            let slot = self
                .func
                .alloc_stack_slot(src_slot_len, 8, StackSlotKind::StringBuffer);
            self.record_stack_slot_type(
                slot,
                MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: src_slot_len,
                },
            );
            let len_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(len_vreg, MirType::U64);
            let shared = SharedInlinedStringReturn {
                slot,
                len_vreg,
                slot_len: src_slot_len,
                content_cap: src_content_cap,
            };
            *shared_return = Some(shared);
            shared
        };

        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::StackSlot(shared.slot),
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: shared.slot_len,
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            },
        );
        self.emit(MirInst::Copy {
            dst: shared.len_vreg,
            src: MirValue::VReg(src_len_vreg),
        });

        let src_ptr = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: src_ptr,
            src: MirValue::StackSlot(src_slot),
        });
        self.vreg_type_hints.insert(
            src_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: src_slot_len,
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            },
        );
        self.emit_ptr_to_slot_copy(shared.slot, 0, src_ptr, 0, src_slot_len)?;
        if src_slot_len < shared.slot_len {
            let shared_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: shared_ptr,
                src: MirValue::StackSlot(shared.slot),
            });
            self.vreg_type_hints.insert(
                shared_ptr,
                MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: shared.slot_len,
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_zero(shared_ptr, src_slot_len, shared.slot_len - src_slot_len)?;
        }

        Ok((
            dst_vreg,
            RegMetadata {
                string_slot: Some(shared.slot),
                string_len_vreg: Some(shared.len_vreg),
                string_len_bound: Some(shared.content_cap),
                field_type: Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: shared.slot_len,
                }),
                annotated_semantics: meta.annotated_semantics.clone(),
                ..Default::default()
            },
        ))
    }

    fn normalize_inlined_list_return(
        &mut self,
        dst_vreg: VReg,
        meta: &RegMetadata,
        shared_return: &mut Option<SharedInlinedListReturn>,
    ) -> Result<(VReg, RegMetadata), CompileError> {
        let (src_slot, src_max_len) = meta.list_buffer.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "inlined list return requires a tracked list buffer".into(),
            )
        })?;
        let src_buffer_size = 8 + (src_max_len * 8);

        let shared = if let Some(shared) = shared_return {
            if src_max_len > shared.max_len {
                return Err(CompileError::UnsupportedInstruction(
                    "multiblock inlined list returns currently require compatible capacities"
                        .into(),
                ));
            }
            *shared
        } else {
            let slot = self
                .func
                .alloc_stack_slot(src_buffer_size, 8, StackSlotKind::ListBuffer);
            self.record_list_buffer_slot_type(slot, src_max_len);
            let shared = SharedInlinedListReturn {
                slot,
                max_len: src_max_len,
            };
            *shared_return = Some(shared);
            shared
        };

        let src_ptr = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: src_ptr,
            src: MirValue::StackSlot(src_slot),
        });
        self.vreg_type_hints.insert(
            src_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: src_max_len.saturating_add(1),
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            },
        );
        self.emit_ptr_to_slot_copy(shared.slot, 0, src_ptr, 0, src_buffer_size)?;

        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::StackSlot(shared.slot),
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: shared.max_len.saturating_add(1),
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            },
        );

        Ok((
            dst_vreg,
            RegMetadata {
                list_buffer: Some((shared.slot, shared.max_len)),
                field_type: Some(MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: shared.max_len.saturating_add(1),
                }),
                annotated_semantics: meta.annotated_semantics.clone(),
                ..Default::default()
            },
        ))
    }

    fn lower_inlined_user_function_return(
        &mut self,
        src: RegId,
        dst_vreg: VReg,
        continuation_block: BlockId,
        materialize_record_return: bool,
        shared_string_return: &mut Option<SharedInlinedStringReturn>,
        shared_list_return: &mut Option<SharedInlinedListReturn>,
    ) -> Result<(Option<RegMetadata>, Option<MirType>), CompileError> {
        let mut result_vreg = self.reg_map.get(&src.get()).copied();
        let mut result_meta = self.get_metadata(src).cloned();
        if let Some(meta) = result_meta.as_mut()
            && let Some(source_var) = meta.source_var
            && !self.annotated_mut_globals.contains_key(&source_var)
            && !self.mutable_capture_globals.contains_key(&source_var)
        {
            meta.source_var = None;
        }

        if let Some(meta) = result_meta.as_ref() {
            if meta.string_slot.is_some() {
                let (normalized_vreg, normalized_meta) =
                    self.normalize_inlined_string_return(dst_vreg, meta, shared_string_return)?;
                result_vreg = Some(normalized_vreg);
                result_meta = Some(normalized_meta);
            } else if meta.list_buffer.is_some() {
                let (normalized_vreg, normalized_meta) =
                    self.normalize_inlined_list_return(dst_vreg, meta, shared_list_return)?;
                result_vreg = Some(normalized_vreg);
                result_meta = Some(normalized_meta);
            } else if materialize_record_return
                && !meta.record_fields.is_empty()
                && let Some((materialized_vreg, materialized_meta)) =
                    self.materialize_metadata_record_value(meta)?
            {
                result_vreg = Some(materialized_vreg);
                result_meta = Some(materialized_meta);
            }
        }

        let result_type_hint = result_vreg
            .and_then(|vreg| self.vreg_type_hints.get(&vreg).cloned())
            .or_else(|| {
                result_meta
                    .as_ref()
                    .and_then(|meta| meta.field_type.clone())
            });

        if let Some(result_vreg) = result_vreg {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(result_vreg),
            });
        }

        let seed = result_meta
            .as_ref()
            .map(|meta| SubfunctionReturnSeed {
                type_hint: result_type_hint.clone(),
                field_type: meta
                    .field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(meta))
                    .or_else(|| {
                        result_type_hint
                            .as_ref()
                            .map(|ty| self.stored_generic_map_value_type(ty))
                    }),
                annotated_semantics: meta
                    .annotated_semantics
                    .clone()
                    .or_else(|| Self::metadata_record_semantics(meta)),
            })
            .or_else(|| {
                result_type_hint.clone().map(|ty| SubfunctionReturnSeed {
                    type_hint: Some(ty.clone()),
                    field_type: Some(self.stored_generic_map_value_type(&ty)),
                    annotated_semantics: None,
                })
            });
        self.note_return_seed(seed);
        self.terminate(MirInst::Jump {
            target: continuation_block,
        });
        Ok((result_meta, result_type_hint))
    }

    #[allow(dead_code)]
    pub(super) fn inline_user_function(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
        dst_vreg: VReg,
        call_args: &[UserFunctionCallArg],
    ) -> Result<(), CompileError> {
        if !self.subfunction_in_progress.insert(decl_id) {
            return Err(CompileError::UnsupportedInstruction(
                "Recursive user-defined functions are not supported in eBPF".into(),
            ));
        }
        let result = self.inline_user_function_inner(decl_id, src_dst, dst_vreg, call_args);
        self.subfunction_in_progress.remove(&decl_id);
        result
    }

    fn inline_user_function_inner(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
        dst_vreg: VReg,
        call_args: &[UserFunctionCallArg],
    ) -> Result<(), CompileError> {
        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;

        let sig = self.decl_signatures.get(&decl_id);
        let param_vars = self.subfunction_params(decl_id, hir);
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let param_count = sig.map(Self::sig_param_count).unwrap_or(param_vars.len());
        let expected_args = param_count + usize::from(needs_input);
        if call_args.len() != expected_args {
            return Err(CompileError::UnsupportedInstruction(format!(
                "inlined user function expected {} args, got {}",
                expected_args,
                call_args.len()
            )));
        }

        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_var_mappings = std::mem::take(&mut self.var_mappings);
        let old_var_metadata = std::mem::take(&mut self.var_metadata);
        let old_type_hints = std::mem::replace(
            &mut self.current_type_hints,
            self.decl_type_hints
                .get(&decl_id)
                .cloned()
                .unwrap_or_default(),
        );
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_return_seed_state = std::mem::replace(
            &mut self.current_return_seed_state,
            CurrentReturnSeedState::Unset,
        );

        let mut next_arg = 0usize;
        if needs_input {
            let input_arg = call_args.get(next_arg).copied().ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "inlined user function missing pipeline input".into(),
                )
            })?;
            if let Some(reg) = input_reg {
                self.reg_map.insert(reg.get(), input_arg.vreg);
                if let Some(meta) = input_arg
                    .source_reg
                    .and_then(|reg| old_reg_metadata.get(&reg.get()).cloned())
                {
                    self.reg_metadata.insert(reg.get(), meta.clone());
                    if uses_in {
                        self.var_metadata.insert(nu_protocol::IN_VARIABLE_ID, meta);
                    }
                }
            }
            if uses_in {
                self.var_mappings
                    .insert(nu_protocol::IN_VARIABLE_ID, input_arg.vreg);
            }
            next_arg += 1;
        }

        let param_base = Self::infer_param_base_var_id(hir)
            .or_else(|| sig.and_then(|_| Self::infer_referenced_var_base_var_id(hir)));
        if let Some(base) = param_base {
            let base = base.get();
            for i in 0..param_count {
                let Some(arg) = call_args.get(next_arg + i).copied() else {
                    return Err(CompileError::UnsupportedInstruction(
                        "inlined user function missing positional arguments".into(),
                    ));
                };
                let var_id = VarId::new(base + i);
                self.var_mappings.insert(var_id, arg.vreg);
                if let Some(meta) = arg
                    .source_reg
                    .and_then(|reg| old_reg_metadata.get(&reg.get()).cloned())
                {
                    self.var_metadata.insert(var_id, meta);
                }
            }
        } else {
            for (idx, var_id) in param_vars.iter().enumerate() {
                let Some(arg) = call_args.get(next_arg + idx).copied() else {
                    return Err(CompileError::UnsupportedInstruction(
                        "inlined user function missing positional arguments".into(),
                    ));
                };
                self.var_mappings.insert(*var_id, arg.vreg);
                if let Some(meta) = arg
                    .source_reg
                    .and_then(|reg| old_reg_metadata.get(&reg.get()).cloned())
                {
                    self.var_metadata.insert(*var_id, meta);
                }
            }
        }

        let mut result_meta = None;
        let mut result_type_hint = None;
        let mut saw_multiple_returns = false;

        if hir.blocks.len() == 1
            && let [block] = hir.blocks.as_slice()
            && let HirTerminator::Return { src } = block.terminator
        {
            for stmt in &block.stmts {
                self.lower_stmt(stmt)?;
            }

            let result_vreg = self.reg_map.get(&src.get()).copied();
            result_meta = self.get_metadata(src).cloned();
            if let Some(meta) = result_meta.as_mut()
                && let Some(source_var) = meta.source_var
                && !self.annotated_mut_globals.contains_key(&source_var)
                && !self.mutable_capture_globals.contains_key(&source_var)
            {
                meta.source_var = None;
            }
            result_type_hint = result_vreg
                .and_then(|vreg| self.vreg_type_hints.get(&vreg).cloned())
                .or_else(|| {
                    result_meta
                        .as_ref()
                        .and_then(|meta| meta.field_type.clone())
                });

            if let Some(result_vreg) = result_vreg {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(result_vreg),
                });
            }
        } else {
            let continuation_block = self.func.alloc_block();
            let entry_block = self.current_block;
            let materialize_record_return = true;
            let mut shared_string_return = None;
            let mut shared_list_return = None;
            let mut saw_return = false;

            self.hir_block_map = HashMap::new();
            self.loop_contexts = Vec::new();
            self.loop_body_inits = HashMap::new();

            for block in &hir.blocks {
                let mir_block = if block.id == hir.entry {
                    entry_block
                } else {
                    self.func.alloc_block()
                };
                self.hir_block_map.insert(block.id, mir_block);
            }

            for block in &hir.blocks {
                self.current_block = *self.hir_block_map.get(&block.id).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("HIR block mapping missing".into())
                })?;

                if let Some(inits) = self.loop_body_inits.remove(&self.current_block) {
                    for inst in inits {
                        self.emit(inst);
                    }
                }

                for stmt in &block.stmts {
                    self.lower_stmt(stmt)?;
                }

                if let HirTerminator::Goto { target } | HirTerminator::Jump { target } =
                    &block.terminator
                    && let Some(src) = Self::cleanup_return_src(hir, *target)
                {
                    let (inline_meta, inline_type_hint) = self.lower_inlined_user_function_return(
                        src,
                        dst_vreg,
                        continuation_block,
                        materialize_record_return,
                        &mut shared_string_return,
                        &mut shared_list_return,
                    )?;
                    if saw_return {
                        saw_multiple_returns = true;
                    } else {
                        saw_return = true;
                        result_meta = inline_meta;
                        result_type_hint = inline_type_hint;
                    }
                    continue;
                }

                if let HirTerminator::BranchIf {
                    cond,
                    if_true,
                    if_false,
                } = &block.terminator
                {
                    let if_true = if let Some(src) = Self::cleanup_return_src(hir, *if_true) {
                        let return_block = self.func.alloc_block();
                        let old_block = self.current_block;
                        self.current_block = return_block;
                        let (inline_meta, inline_type_hint) = self
                            .lower_inlined_user_function_return(
                                src,
                                dst_vreg,
                                continuation_block,
                                materialize_record_return,
                                &mut shared_string_return,
                                &mut shared_list_return,
                            )?;
                        if saw_return {
                            saw_multiple_returns = true;
                        } else {
                            saw_return = true;
                            result_meta = inline_meta;
                            result_type_hint = inline_type_hint;
                        }
                        self.current_block = old_block;
                        return_block
                    } else {
                        *self.hir_block_map.get(if_true).ok_or_else(|| {
                            CompileError::UnsupportedInstruction("Invalid branch target".into())
                        })?
                    };
                    let if_false = if let Some(src) = Self::cleanup_return_src(hir, *if_false) {
                        let return_block = self.func.alloc_block();
                        let old_block = self.current_block;
                        self.current_block = return_block;
                        let (inline_meta, inline_type_hint) = self
                            .lower_inlined_user_function_return(
                                src,
                                dst_vreg,
                                continuation_block,
                                materialize_record_return,
                                &mut shared_string_return,
                                &mut shared_list_return,
                            )?;
                        if saw_return {
                            saw_multiple_returns = true;
                        } else {
                            saw_return = true;
                            result_meta = inline_meta;
                            result_type_hint = inline_type_hint;
                        }
                        self.current_block = old_block;
                        return_block
                    } else {
                        *self.hir_block_map.get(if_false).ok_or_else(|| {
                            CompileError::UnsupportedInstruction("Invalid branch target".into())
                        })?
                    };
                    let cond_vreg = self.get_vreg(*cond);
                    self.terminate(MirInst::Branch {
                        cond: cond_vreg,
                        if_true,
                        if_false,
                    });
                    continue;
                }

                match &block.terminator {
                    HirTerminator::Return { src } | HirTerminator::ReturnEarly { src } => {
                        let (inline_meta, inline_type_hint) = self
                            .lower_inlined_user_function_return(
                                *src,
                                dst_vreg,
                                continuation_block,
                                materialize_record_return,
                                &mut shared_string_return,
                                &mut shared_list_return,
                            )?;
                        if saw_return {
                            saw_multiple_returns = true;
                        } else {
                            saw_return = true;
                            result_meta = inline_meta;
                            result_type_hint = inline_type_hint;
                        }
                    }
                    HirTerminator::Unreachable => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Encountered unreachable block".into(),
                        ));
                    }
                    term => {
                        self.lower_terminator(term)?;
                    }
                }
            }

            self.current_block = continuation_block;
            if saw_multiple_returns
                && shared_string_return.is_none()
                && shared_list_return.is_none()
            {
                result_meta = None;
                result_type_hint = None;
            }
        }

        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.var_mappings = old_var_mappings;
        self.var_metadata = old_var_metadata;
        self.current_type_hints = old_type_hints;
        self.hir_block_map = old_hir_block_map;
        self.loop_contexts = old_loop_contexts;
        self.loop_body_inits = old_loop_body_inits;

        let inline_return_seed_state =
            std::mem::replace(&mut self.current_return_seed_state, old_return_seed_state);

        self.reg_map.insert(src_dst.get(), dst_vreg);
        self.reg_metadata.remove(&src_dst.get());
        if let Some(ty) = result_type_hint {
            self.vreg_type_hints.insert(dst_vreg, ty);
        }
        if let Some(meta) = result_meta {
            self.reg_metadata.insert(src_dst.get(), meta);
        } else if let CurrentReturnSeedState::Known(Some(seed)) = inline_return_seed_state {
            if let Some(type_hint) = seed.type_hint.clone() {
                self.vreg_type_hints.insert(dst_vreg, type_hint);
            }
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = seed.field_type;
            meta.annotated_semantics = seed.annotated_semantics;
            meta.source_var = None;
        }
        Ok(())
    }

    /// Lower RecordInsert instruction
    pub(super) fn lower_record_insert(
        &mut self,
        src_dst: RegId,
        key: RegId,
        val: RegId,
    ) -> Result<(), CompileError> {
        // Get field name from key register's metadata
        let field_name = self
            .get_metadata(key)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Record key must be a literal string".into())
            })?;
        let constant_value = match (
            self.get_metadata(src_dst)
                .and_then(|meta| meta.constant_value.clone()),
            self.get_metadata(val)
                .and_then(|meta| meta.constant_value.clone()),
        ) {
            (Some(Value::Record { val: record, .. }), Some(field_value)) => {
                let mut record = record.into_owned();
                record.insert(field_name.clone(), field_value);
                Some(Value::record(record, Span::unknown()))
            }
            _ => None,
        };

        let val_vreg = self.get_vreg(val);
        let val_meta = self.get_metadata(val).cloned();

        // Preserve aggregate-pointer field layout as the underlying aggregate
        // so `{ path: $entry } | emit` serializes nested data instead of a raw pointer.
        let mut field_type = val_meta
            .as_ref()
            .and_then(|m| {
                m.field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(m))
            })
            .or_else(|| self.vreg_type_hints.get(&val_vreg).cloned())
            .map(|ty| self.stored_generic_map_value_type(&ty))
            .unwrap_or(MirType::I64);
        let field_constant = self
            .get_metadata(val)
            .and_then(|m| m.constant_value.clone());
        let field_semantics = self.tracked_value_semantics(val, field_constant.as_ref())?;

        // IMPORTANT: Create a fresh VReg and copy the value to preserve it.
        // The IR reuses registers, so val_vreg might be overwritten by subsequent operations.
        // By copying to a fresh VReg, we ensure the value is preserved until emit time.
        let preserved_vreg = self.func.alloc_vreg();
        if let Some(meta) = val_meta.as_ref()
            && let Some(slot) = meta.string_slot
        {
            let len_vreg = meta.string_len_vreg.ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "record string field requires a tracked string length".into(),
                )
            })?;
            let src_slot_size = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during record field materialization".into(),
                )
            })?;
            let stored_slot_len = 8usize.saturating_add(src_slot_size);
            let stored_ty = MirType::Array {
                elem: Box::new(MirType::U8),
                len: stored_slot_len,
            };
            let stored_slot =
                self.func
                    .alloc_stack_slot(stored_slot_len, 8, StackSlotKind::StringBuffer);
            self.record_stack_slot_type(stored_slot, stored_ty.clone());
            self.emit(MirInst::StoreSlot {
                slot: stored_slot,
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
            self.emit_ptr_to_slot_copy(stored_slot, 8, src_ptr, 0, src_slot_size)?;

            self.emit(MirInst::Copy {
                dst: preserved_vreg,
                src: MirValue::StackSlot(stored_slot),
            });
            self.vreg_type_hints.insert(
                preserved_vreg,
                MirType::Ptr {
                    pointee: Box::new(stored_ty.clone()),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            field_type = stored_ty;
        } else {
            self.emit(MirInst::Copy {
                dst: preserved_vreg,
                src: MirValue::VReg(val_vreg),
            });
            if let Some(ty) = self.vreg_type_hints.get(&val_vreg).cloned() {
                self.vreg_type_hints.insert(preserved_vreg, ty);
            }
        }

        // Add field to the record being built (using preserved VReg with inferred type)
        let field = RecordField {
            name: field_name,
            value_vreg: preserved_vreg,
            source_reg: Some(val),
            stack_offset: None,
            ty: field_type,
            semantics: field_semantics,
        };

        {
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.record_fields.push(field);
            meta.field_type = Self::metadata_record_layout(meta);
            meta.annotated_semantics = Self::metadata_record_semantics(meta);
            meta.source_var = None;
        }
        self.set_reg_constant_value(src_dst, constant_value);

        Ok(())
    }

    pub(super) fn lower_record_spread(
        &mut self,
        src_dst: RegId,
        items: RegId,
    ) -> Result<(), CompileError> {
        let source_meta = self.get_metadata(items).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Record spread requires a source record with compiler-known fields in eBPF".into(),
            )
        })?;

        if source_meta.record_fields.is_empty() {
            let source_is_known_empty = matches!(
                source_meta.constant_value.as_ref(),
                Some(Value::Record { val, .. }) if val.is_empty()
            );
            if !source_is_known_empty {
                return Err(CompileError::UnsupportedInstruction(
                    "Record spread requires a source record with compiler-known fields in eBPF"
                        .into(),
                ));
            }
        }

        let constant_value = match (
            self.get_metadata(src_dst)
                .and_then(|meta| meta.constant_value.clone()),
            source_meta.constant_value.clone(),
        ) {
            (
                Some(Value::Record { val: record, .. }),
                Some(Value::Record {
                    val: spread_record, ..
                }),
            ) => {
                let mut record = record.into_owned();
                for (key, value) in spread_record.iter() {
                    record.insert(key, value.clone());
                }
                Some(Value::record(record, Span::unknown()))
            }
            _ => None,
        };

        {
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;

            for field in source_meta.record_fields {
                if let Some(existing) = meta
                    .record_fields
                    .iter_mut()
                    .find(|existing| existing.name == field.name)
                {
                    *existing = field;
                } else {
                    meta.record_fields.push(field);
                }
            }

            meta.field_type = Self::metadata_record_layout(meta);
            meta.annotated_semantics = Self::metadata_record_semantics(meta);
            meta.source_var = None;
        }
        self.set_reg_constant_value(src_dst, constant_value);

        Ok(())
    }

    /// Inline a closure with $in bound to a specific value
    /// Returns the vreg containing the closure's result
    ///
    /// This is used for commands like `where` and `each` that take closure arguments.
    /// The closure's parameter is bound to the input value.
    pub(super) fn inline_closure_with_in(
        &mut self,
        block_id: NuBlockId,
        hir: &HirFunction,
        in_vreg: VReg,
    ) -> Result<VReg, CompileError> {
        // Collect all variable IDs that are loaded in this closure
        // These could be $in, closure parameters, or captured variables
        // Map all of them to the input value since this is a single-value transform
        let mut loaded_var_ids: Vec<VarId> = Vec::new();
        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if !loaded_var_ids.contains(var_id) {
                        loaded_var_ids.push(*var_id);
                    }
                }
            }
        }

        // Save old mappings to restore later
        use nu_protocol::IN_VARIABLE_ID;
        let old_in_mapping = self.var_mappings.get(&IN_VARIABLE_ID).copied();

        // Map $in variable to in_vreg
        self.var_mappings.insert(IN_VARIABLE_ID, in_vreg);

        // Map all loaded variables to in_vreg (they all represent the row/input)
        let mut param_var_ids: Vec<VarId> = Vec::new();
        for var_id in loaded_var_ids {
            // Don't override existing mappings (like captures from outer scope)
            if !self.var_mappings.contains_key(&var_id) && self.captured_value(var_id).is_none() {
                param_var_ids.push(var_id);
                self.var_mappings.insert(var_id, in_vreg);
            }
        }

        // Allocate a vreg for the result
        let result_vreg = self.func.alloc_vreg();
        let continuation_block = self.func.alloc_block();

        // Save current register mappings (closure has its own register space)
        // IMPORTANT: We start with an empty reg_map so the closure allocates fresh
        // vregs for all its internal registers. This is proper alpha-renaming -
        // without it, the closure would overwrite in_vreg during computation.
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_type_hints = std::mem::take(&mut self.current_type_hints);
        let entry_block = self.current_block;

        self.current_type_hints = self
            .closure_type_hints
            .get(&block_id)
            .cloned()
            .unwrap_or_default();

        self.hir_block_map = HashMap::new();
        self.loop_contexts = Vec::new();
        self.loop_body_inits = HashMap::new();

        for block in &hir.blocks {
            let mir_block = if block.id == hir.entry {
                entry_block
            } else {
                self.func.alloc_block()
            };
            self.hir_block_map.insert(block.id, mir_block);
        }

        for block in &hir.blocks {
            self.current_block = *self.hir_block_map.get(&block.id).ok_or_else(|| {
                CompileError::UnsupportedInstruction("HIR block mapping missing".into())
            })?;

            if let Some(inits) = self.loop_body_inits.remove(&self.current_block) {
                for inst in inits {
                    self.emit(inst);
                }
            }

            for stmt in &block.stmts {
                self.lower_stmt(stmt)?;
            }

            match &block.terminator {
                HirTerminator::Return { src } | HirTerminator::ReturnEarly { src } => {
                    let src_vreg = self.get_vreg(*src);
                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::VReg(src_vreg),
                    });
                    self.terminate(MirInst::Jump {
                        target: continuation_block,
                    });
                }
                HirTerminator::Unreachable => {
                    return Err(CompileError::UnsupportedInstruction(
                        "Encountered unreachable block".into(),
                    ));
                }
                term => {
                    self.lower_terminator(term)?;
                }
            }
        }

        // Restore register mappings
        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.hir_block_map = old_hir_block_map;
        self.loop_contexts = old_loop_contexts;
        self.loop_body_inits = old_loop_body_inits;
        self.current_type_hints = old_type_hints;

        // Restore old $in mapping (if any)
        if let Some(old) = old_in_mapping {
            self.var_mappings.insert(IN_VARIABLE_ID, old);
        } else {
            self.var_mappings.remove(&IN_VARIABLE_ID);
        }

        // Remove parameter mappings
        for var_id in param_var_ids {
            self.var_mappings.remove(&var_id);
        }

        self.current_block = continuation_block;
        Ok(result_vreg)
    }

    /// Lower LoadVariable instruction
    pub(super) fn lower_load_variable(
        &mut self,
        dst: RegId,
        var_id: nu_protocol::VarId,
    ) -> Result<(), CompileError> {
        let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
            self.assign_fresh_vreg(dst)
        } else {
            self.get_vreg(dst)
        };
        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        if let Some(&source_var) = self.subfunction_global_aliases.get(&var_id) {
            if let Some(global) = self.annotated_mut_globals.get(&source_var).cloned() {
                self.load_mutable_global_value(dst, dst_vreg, &global)?;
                if let Some(semantics) = self
                    .annotated_mut_global_semantics
                    .get(&source_var)
                    .cloned()
                {
                    self.get_or_create_metadata(dst).annotated_semantics = Some(semantics);
                }
                self.get_or_create_metadata(dst).source_var = Some(source_var);
                return Ok(());
            }

            if let Some(global) = self.mutable_capture_globals.get(&source_var).cloned() {
                self.load_mutable_global_value(dst, dst_vreg, &global)?;
                if let Some(semantics) = self
                    .mutable_capture_global_semantics
                    .get(&source_var)
                    .cloned()
                {
                    self.get_or_create_metadata(dst).annotated_semantics = Some(semantics);
                }
                self.get_or_create_metadata(dst).source_var = Some(source_var);
                return Ok(());
            }
        }

        // Context aliases are metadata-only; the ambient context register is
        // materialized by context-specific lowering when it is actually used.
        if let Some(mut meta) = self.var_metadata.get(&var_id).cloned()
            && meta.is_context
        {
            meta.source_var.get_or_insert(var_id);
            self.reg_metadata.insert(dst.get(), meta);
            return Ok(());
        }

        // Check if this is a parameter from an inlined function
        if let Some(&param_vreg) = self.var_mappings.get(&var_id) {
            // Copy the parameter value to the destination
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(param_vreg),
            });
            if let Some(mut meta) = self.var_metadata.get(&var_id).cloned() {
                meta.source_var.get_or_insert(var_id);
                self.reg_metadata.insert(dst.get(), meta);
            } else {
                self.get_or_create_metadata(dst).source_var = Some(var_id);
            }
            if let Some(ty) = self.vreg_type_hints.get(&param_vreg).cloned() {
                self.vreg_type_hints.insert(dst_vreg, ty);
            }
            return Ok(());
        }

        // Check if this is the context parameter variable
        if let Some(ctx_var) = self.ctx_param
            && var_id == ctx_var
        {
            // Mark this register as holding the context
            let meta = self.get_or_create_metadata(dst);
            meta.is_context = true;
            return Ok(());
        }

        if let Some(global) = self.annotated_mut_globals.get(&var_id).cloned() {
            self.load_mutable_global_value(dst, dst_vreg, &global)?;
            if let Some(semantics) = self.annotated_mut_global_semantics.get(&var_id).cloned() {
                self.get_or_create_metadata(dst).annotated_semantics = Some(semantics);
            }
            self.get_or_create_metadata(dst).source_var = Some(var_id);
            return Ok(());
        }

        if let Some(global) = self.mutable_capture_globals.get(&var_id).cloned() {
            self.load_mutable_global_value(dst, dst_vreg, &global)?;
            if let Some(semantics) = self.mutable_capture_global_semantics.get(&var_id).cloned() {
                self.get_or_create_metadata(dst).annotated_semantics = Some(semantics);
            }
            self.get_or_create_metadata(dst).source_var = Some(var_id);
            return Ok(());
        }

        // Check if this is a captured variable
        if let Some(value) = self.captured_value(var_id).cloned() {
            self.lower_constant_value(dst, &value)?;
            return Ok(());
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "Variable {} not found in captures or function parameters",
            var_id.get()
        )))
    }
}
