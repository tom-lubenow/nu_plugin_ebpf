use super::*;
use crate::compiler::elf::ProgramReturnAlias;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_fixed_array_iterate(
        &mut self,
        dst: RegId,
        stream: RegId,
        body_block: BlockId,
        exit_block: BlockId,
        initialize_exit_value: bool,
    ) -> Result<bool, CompileError> {
        let mut stream_vreg = self.get_vreg(stream);
        let mut base_runtime_ty = match self.typed_value_runtime_type(stream, stream_vreg) {
            Some(ty) => ty,
            None => return Ok(false),
        };
        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            stream_vreg = self.materialized_metadata_aggregate_vreg(stream, stream_vreg)?;
            base_runtime_ty = match self.typed_value_runtime_type(stream, stream_vreg) {
                Some(ty) => ty,
                None => return Ok(false),
            };
        }

        let MirType::Ptr {
            pointee,
            address_space: _,
        } = &base_runtime_ty
        else {
            return Ok(false);
        };
        let MirType::Array { len, .. } = pointee.as_ref() else {
            return Ok(false);
        };
        let dst_vreg = self.get_vreg(dst);
        let counter_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: counter_vreg,
            src: MirValue::Const(0),
        });

        let limit = i64::try_from(*len).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "Iterate fixed array length {} does not fit in i64 loop bounds",
                len
            ))
        })?;
        let load_block = self.func.alloc_block();
        self.terminate(MirInst::LoopHeader {
            counter: counter_vreg,
            start: 0,
            step: 1,
            limit,
            body: load_block,
            exit: exit_block,
        });

        let header_block = self.current_block;
        let root_ctx_field = self
            .get_metadata(stream)
            .and_then(|meta| meta.root_ctx_field.clone());
        self.current_block = load_block;
        self.lower_dynamic_typed_numeric_get(
            dst,
            stream_vreg,
            &base_runtime_ty,
            MirValue::VReg(counter_vreg),
            root_ctx_field.as_ref(),
        )?;
        self.terminate(MirInst::Jump { target: body_block });
        self.current_block = header_block;

        if initialize_exit_value {
            self.loop_body_inits
                .entry(exit_block)
                .or_default()
                .push(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
        }

        self.loop_contexts.push(LoopContext {
            header_block,
            exit_block,
            counter_vreg,
            step: 1,
        });
        Ok(true)
    }

    pub(super) fn cleanup_return_src(hir: &HirFunction, target: HirBlockId) -> Option<RegId> {
        fn cleanup_only_for_src(stmts: &[HirStmt], src: RegId) -> bool {
            stmts.iter().all(|stmt| {
                matches!(
                    stmt,
                    HirStmt::Drop { src: stmt_src }
                        | HirStmt::Drain { src: stmt_src }
                        | HirStmt::DrainIfEnd { src: stmt_src }
                        if *stmt_src == src
                )
            })
        }

        fn resolve_cleanup_return_src(
            hir: &HirFunction,
            target: HirBlockId,
            visited: &mut Vec<HirBlockId>,
        ) -> Option<RegId> {
            if visited.contains(&target) {
                return None;
            }
            visited.push(target);

            let candidate = hir.blocks.iter().find(|candidate| candidate.id == target)?;
            match &candidate.terminator {
                HirTerminator::Return { src } if cleanup_only_for_src(&candidate.stmts, *src) => {
                    Some(*src)
                }
                HirTerminator::Goto { target } | HirTerminator::Jump { target } => {
                    let src = resolve_cleanup_return_src(hir, *target, visited)?;
                    cleanup_only_for_src(&candidate.stmts, src).then_some(src)
                }
                _ => None,
            }
        }

        resolve_cleanup_return_src(hir, target, &mut Vec::new())
    }

    fn action_alias_return_value(&self, reg: RegId) -> Option<ProgramReturnAlias> {
        let program_type = self.probe_ctx.as_ref().map(|ctx| ctx.program_type())?;
        let alias = self.get_metadata(reg).and_then(|meta| {
            meta.literal_string.clone().or_else(|| {
                meta.constant_value.as_ref().and_then(|value| match value {
                    Value::String { val, .. } | Value::Glob { val, .. } => Some(val.clone()),
                    _ => None,
                })
            })
        })?;

        program_type.return_action_alias(&alias)
    }

    pub(super) fn note_return_seed(&mut self, seed: Option<SubfunctionReturnSeed>) {
        self.current_return_seed_state = match &self.current_return_seed_state {
            CurrentReturnSeedState::Unset => CurrentReturnSeedState::Known(seed),
            CurrentReturnSeedState::Known(existing) if *existing == seed => {
                CurrentReturnSeedState::Known(seed)
            }
            CurrentReturnSeedState::Known(_) | CurrentReturnSeedState::Conflict => {
                CurrentReturnSeedState::Conflict
            }
        };
    }

    fn current_block_has_real_terminator(&self) -> bool {
        !matches!(
            &self.func.block(self.current_block).terminator,
            MirInst::Placeholder
        )
    }

    fn is_terminal_cleanup_stmt(stmt: &HirStmt) -> bool {
        matches!(
            stmt,
            HirStmt::Drop { .. }
                | HirStmt::Drain { .. }
                | HirStmt::DrainIfEnd { .. }
                | HirStmt::DropVariable { .. }
        )
    }

    fn return_seed_for_reg(
        &self,
        reg: RegId,
        type_hint: Option<MirType>,
    ) -> Option<SubfunctionReturnSeed> {
        self.get_metadata(reg)
            .map(|meta| SubfunctionReturnSeed {
                type_hint: type_hint.clone(),
                field_type: meta
                    .field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(meta))
                    .or_else(|| {
                        type_hint
                            .as_ref()
                            .map(|ty| self.stored_generic_map_value_type(ty))
                    }),
                annotated_semantics: meta
                    .annotated_semantics
                    .clone()
                    .or_else(|| Self::metadata_record_semantics(meta)),
            })
            .or_else(|| {
                type_hint.clone().map(|ty| SubfunctionReturnSeed {
                    type_hint: Some(ty.clone()),
                    field_type: Some(self.stored_generic_map_value_type(&ty)),
                    annotated_semantics: None,
                })
            })
    }

    fn lower_active_subfunction_aggregate_return(
        &mut self,
        reg: RegId,
        src_vreg: VReg,
        src_runtime_ty: Option<MirType>,
        active_return: &ActiveSubfunctionAggregateReturn,
    ) -> Result<MirValue, CompileError> {
        match active_return {
            ActiveSubfunctionAggregateReturn::Record { ptr_vreg, ty } => {
                let mut source_ptr = src_vreg;
                let mut source_runtime_ty = src_runtime_ty;
                if !matches!(
                    source_runtime_ty,
                    Some(MirType::Ptr {
                        address_space: crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                        ..
                    })
                ) {
                    source_ptr = self.materialized_metadata_aggregate_vreg(reg, src_vreg)?;
                    source_runtime_ty = self
                        .vreg_type_hints
                        .get(&source_ptr)
                        .cloned()
                        .or_else(|| self.typed_value_runtime_type(reg, source_ptr));
                }

                let Some(MirType::Ptr {
                    pointee,
                    address_space:
                        crate::compiler::mir::AddressSpace::Stack
                        | crate::compiler::mir::AddressSpace::Map,
                }) = source_runtime_ty
                else {
                    return Err(CompileError::UnsupportedInstruction(
                        "record-returning subfunction requires a materialized aggregate pointer return value".into(),
                    ));
                };
                if pointee.as_ref() != ty {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record-returning subfunction cannot write {:?} into aggregate return slot {:?}",
                        pointee, ty
                    )));
                }

                self.emit_ptr_copy(*ptr_vreg, source_ptr, ty.size())?;
                Ok(MirValue::Const(0))
            }
            ActiveSubfunctionAggregateReturn::List { ptr_vreg, max_len } => {
                let (source_ptr, source_max_len) = if let Some((slot, source_max_len)) =
                    self.get_metadata(reg).and_then(|meta| meta.list_buffer)
                {
                    let source_ptr = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: source_ptr,
                        src: MirValue::StackSlot(slot),
                    });
                    self.vreg_type_hints.insert(
                        source_ptr,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::I64),
                                len: source_max_len.saturating_add(1),
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    (source_ptr, source_max_len)
                } else {
                    let Some(MirType::Ptr {
                        pointee,
                        address_space:
                            crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                    }) = src_runtime_ty
                    else {
                        return Err(CompileError::UnsupportedInstruction(
                            "list-returning subfunction requires a materialized list buffer return value".into(),
                        ));
                    };
                    let MirType::Array { elem, len } = pointee.as_ref() else {
                        return Err(CompileError::UnsupportedInstruction(
                            "list-returning subfunction requires an array-backed list return value"
                                .into(),
                        ));
                    };
                    if !matches!(elem.as_ref(), MirType::I64) || *len == 0 {
                        return Err(CompileError::UnsupportedInstruction(
                            "list-returning subfunction requires a numeric list return buffer"
                                .into(),
                        ));
                    }
                    (src_vreg, len - 1)
                };

                if source_max_len > *max_len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "list-returning subfunction cannot write list capacity {} into aggregate return slot {}",
                        source_max_len, max_len
                    )));
                }

                let source_size = 8 + (source_max_len * 8);
                self.emit_ptr_copy_with_offsets(*ptr_vreg, 0, source_ptr, 0, source_size)?;
                if source_max_len < *max_len {
                    self.emit_ptr_zero(*ptr_vreg, source_size, (*max_len - source_max_len) * 8)?;
                }
                Ok(MirValue::Const(0))
            }
            ActiveSubfunctionAggregateReturn::String { ptr_vreg, slot_len } => {
                let Some(meta) = self.get_metadata(reg).cloned() else {
                    return Err(CompileError::UnsupportedInstruction(
                        "string-returning subfunction requires tracked string metadata".into(),
                    ));
                };
                let Some(source_slot) = meta.string_slot else {
                    return Err(CompileError::UnsupportedInstruction(
                        "string-returning subfunction requires a tracked string slot".into(),
                    ));
                };
                let Some(source_len_vreg) = meta.string_len_vreg else {
                    return Err(CompileError::UnsupportedInstruction(
                        "string-returning subfunction requires a tracked string length".into(),
                    ));
                };
                let source_slot_len = self.stack_slot_size(source_slot).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "string slot not found during aggregate return lowering".into(),
                    )
                })?;
                if source_slot_len > *slot_len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "string-returning subfunction cannot write string capacity {} into aggregate return slot {}",
                        source_slot_len.saturating_sub(1),
                        slot_len.saturating_sub(1)
                    )));
                }

                let source_ptr = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: source_ptr,
                    src: MirValue::StackSlot(source_slot),
                });
                self.vreg_type_hints.insert(
                    source_ptr,
                    MirType::Ptr {
                        pointee: Box::new(MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: source_slot_len,
                        }),
                        address_space: crate::compiler::mir::AddressSpace::Stack,
                    },
                );
                self.emit_ptr_copy_with_offsets(*ptr_vreg, 0, source_ptr, 0, source_slot_len)?;
                if source_slot_len < *slot_len {
                    self.emit_ptr_zero(*ptr_vreg, source_slot_len, *slot_len - source_slot_len)?;
                }
                Ok(MirValue::VReg(source_len_vreg))
            }
        }
    }

    fn returned_value_for_reg(
        &mut self,
        reg: RegId,
    ) -> Result<(MirValue, Option<SubfunctionReturnSeed>), CompileError> {
        if let Some(alias) = self.action_alias_return_value(reg) {
            let value = match alias {
                ProgramReturnAlias::Const(value) => MirValue::Const(value),
                ProgramReturnAlias::PacketLen => {
                    let dst = self.func.alloc_vreg();
                    self.emit(MirInst::LoadCtxField {
                        dst,
                        field: CtxField::PacketLen,
                        slot: None,
                    });
                    MirValue::VReg(dst)
                }
            };
            return Ok((value, None));
        }

        let Some(src_vreg) = self.reg_map.get(&reg.get()).copied() else {
            return Ok((MirValue::Const(0), None));
        };

        let src_runtime_ty = self
            .vreg_type_hints
            .get(&src_vreg)
            .cloned()
            .or_else(|| self.typed_value_runtime_type(reg, src_vreg));
        let seed = self.return_seed_for_reg(reg, src_runtime_ty.clone());

        if let Some(active_return) = self.current_subfunction_aggregate_return.clone() {
            let scalar_return = self.lower_active_subfunction_aggregate_return(
                reg,
                src_vreg,
                src_runtime_ty,
                &active_return,
            )?;
            return Ok((scalar_return, seed));
        }

        if self.func.name.is_some()
            && !matches!(src_runtime_ty, Some(MirType::Ptr { .. }))
            && let Some(src_meta) = self.get_metadata(reg).cloned()
            && let Some((materialized_vreg, materialized_meta)) =
                self.materialize_metadata_record_value(&src_meta)?
        {
            return Ok((
                MirValue::VReg(materialized_vreg),
                Some(SubfunctionReturnSeed {
                    type_hint: self.vreg_type_hints.get(&materialized_vreg).cloned(),
                    field_type: materialized_meta.field_type,
                    annotated_semantics: materialized_meta.annotated_semantics,
                }),
            ));
        }

        Ok((MirValue::VReg(src_vreg), seed))
    }

    fn lower_cleanup_return_edge(&mut self, src: RegId) -> Result<BlockId, CompileError> {
        let return_block = self.func.alloc_block();
        let old_block = self.current_block;
        self.current_block = return_block;
        let (value, seed) = self.returned_value_for_reg(src)?;
        self.note_return_seed(seed);
        let val = Some(value);
        self.terminate(MirInst::Return { val });
        self.current_block = old_block;
        Ok(return_block)
    }

    fn lower_constant_return_edge(&mut self, value: MirValue) -> BlockId {
        let return_block = self.func.alloc_block();
        let old_block = self.current_block;
        self.current_block = return_block;
        self.note_return_seed(None);
        self.terminate(MirInst::Return { val: Some(value) });
        self.current_block = old_block;
        return_block
    }

    pub fn lower_block(&mut self, hir: &HirFunction) -> Result<(), CompileError> {
        self.hir_block_map.clear();
        for block in &hir.blocks {
            let mir_block = self.func.alloc_block();
            self.hir_block_map.insert(block.id, mir_block);
        }

        if let Some(entry) = self.hir_block_map.get(&hir.entry).copied() {
            self.func.entry = entry;
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
                if self.current_block_has_real_terminator() {
                    if Self::is_terminal_cleanup_stmt(stmt) {
                        continue;
                    }
                    return Err(CompileError::UnsupportedInstruction(
                        "terminal eBPF command must be the final expression in its block".into(),
                    ));
                }
                self.lower_stmt(stmt)?;
            }
            if self.current_block_has_real_terminator() {
                continue;
            }
            if let HirTerminator::Goto { target } | HirTerminator::Jump { target } =
                &block.terminator
                && let Some(src) = Self::cleanup_return_src(hir, *target)
            {
                let (value, seed) = self.returned_value_for_reg(src)?;
                self.note_return_seed(seed);
                let val = Some(value);
                self.terminate(MirInst::Return { val });
                continue;
            }
            if let HirTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } = &block.terminator
            {
                let if_true = if let Some(src) = Self::cleanup_return_src(hir, *if_true) {
                    self.lower_cleanup_return_edge(src)?
                } else {
                    *self.hir_block_map.get(if_true).ok_or_else(|| {
                        CompileError::UnsupportedInstruction("Invalid branch target".into())
                    })?
                };
                let if_false = if let Some(src) = Self::cleanup_return_src(hir, *if_false) {
                    self.lower_cleanup_return_edge(src)?
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
            if let HirTerminator::Iterate {
                dst,
                stream,
                body,
                end,
            } = &block.terminator
            {
                let body_block = *self.hir_block_map.get(body).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop body".into())
                })?;
                let cleanup_return_exit = Self::cleanup_return_src(hir, *end).is_some();
                let exit_block = if cleanup_return_exit {
                    self.lower_constant_return_edge(MirValue::Const(0))
                } else {
                    *self.hir_block_map.get(end).ok_or_else(|| {
                        CompileError::UnsupportedInstruction("Invalid loop exit".into())
                    })?
                };
                if let Some(range) = self.get_metadata(*stream).and_then(|m| m.bounded_range) {
                    let dst_vreg = self.get_vreg(*dst);
                    let counter_vreg = self.get_vreg(*stream);

                    let limit = if range.inclusive {
                        range.end + range.step.signum()
                    } else {
                        range.end
                    };

                    self.terminate(MirInst::LoopHeader {
                        counter: counter_vreg,
                        start: range.start,
                        step: range.step,
                        limit,
                        body: body_block,
                        exit: exit_block,
                    });

                    self.loop_body_inits
                        .entry(body_block)
                        .or_default()
                        .push(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(counter_vreg),
                        });
                    if !cleanup_return_exit {
                        self.loop_body_inits
                            .entry(exit_block)
                            .or_default()
                            .push(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::Const(0),
                            });
                    }

                    self.loop_contexts.push(LoopContext {
                        header_block: self.current_block,
                        exit_block,
                        counter_vreg,
                        step: range.step,
                    });
                    continue;
                }

                if let Some((_slot, max_len)) =
                    self.get_metadata(*stream).and_then(|m| m.list_buffer)
                {
                    let dst_vreg = self.get_vreg(*dst);
                    let list_vreg = self.get_vreg(*stream);
                    let counter_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: counter_vreg,
                        src: MirValue::Const(0),
                    });

                    let guard_block = self.func.alloc_block();
                    self.terminate(MirInst::LoopHeader {
                        counter: counter_vreg,
                        start: 0,
                        step: 1,
                        limit: max_len as i64,
                        body: guard_block,
                        exit: exit_block,
                    });

                    let old_block = self.current_block;
                    self.current_block = guard_block;
                    let len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListLen {
                        dst: len_vreg,
                        list: list_vreg,
                    });
                    let cmp_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::VReg(counter_vreg),
                        rhs: MirValue::VReg(len_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_vreg,
                        if_true: body_block,
                        if_false: exit_block,
                    });
                    self.current_block = old_block;

                    self.loop_body_inits
                        .entry(body_block)
                        .or_default()
                        .push(MirInst::ListGet {
                            dst: dst_vreg,
                            list: list_vreg,
                            idx: MirValue::VReg(counter_vreg),
                        });
                    if !cleanup_return_exit {
                        self.loop_body_inits
                            .entry(exit_block)
                            .or_default()
                            .push(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::Const(0),
                            });
                    }

                    self.loop_contexts.push(LoopContext {
                        header_block: old_block,
                        exit_block,
                        counter_vreg,
                        step: 1,
                    });
                    continue;
                }

                if self.lower_fixed_array_iterate(
                    *dst,
                    *stream,
                    body_block,
                    exit_block,
                    !cleanup_return_exit,
                )? {
                    continue;
                }

                return Err(CompileError::UnsupportedInstruction(
                    "Iterate requires a compile-time known range, bounded list, or fixed array"
                        .into(),
                ));
            }
            self.lower_terminator(&block.terminator)?;
        }

        Ok(())
    }

    /// Lower a single HIR statement to MIR
    pub(super) fn lower_stmt(&mut self, instruction: &HirStmt) -> Result<(), CompileError> {
        match instruction {
            // === Data Movement ===
            HirStmt::LoadLiteral { dst, lit } => {
                self.lower_load_literal(*dst, lit)?;
            }

            HirStmt::LoadValue { dst, val } => {
                self.lower_constant_value(*dst, val)?;
            }

            HirStmt::Move { dst, src } => {
                // Copy value and metadata
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
                    self.assign_fresh_vreg(*dst)
                } else {
                    self.get_vreg(*dst)
                };
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                // Copy metadata
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
                if let Some(ty) = self.vreg_type_hints.get(&src_vreg).cloned() {
                    self.vreg_type_hints.insert(dst_vreg, ty);
                }
            }

            HirStmt::Clone { dst, src } => {
                // Same as Move for our purposes
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
                    self.assign_fresh_vreg(*dst)
                } else {
                    self.get_vreg(*dst)
                };
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
                if let Some(ty) = self.vreg_type_hints.get(&src_vreg).cloned() {
                    self.vreg_type_hints.insert(dst_vreg, ty);
                }
            }

            // === Arithmetic ===
            HirStmt::BinaryOp { lhs_dst, op, rhs } => {
                self.lower_binary_op(*lhs_dst, *op, *rhs)?;
            }

            HirStmt::Not { src_dst } => {
                let constant_value = self.get_metadata(*src_dst).and_then(|meta| {
                    let Value::Bool { val, .. } = meta.constant_value.as_ref()? else {
                        return None;
                    };
                    Some(Value::bool(!val, Span::unknown()))
                });
                let vreg = self.get_vreg(*src_dst);
                self.emit(MirInst::UnaryOp {
                    dst: vreg,
                    op: crate::compiler::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(vreg),
                });
                self.clear_source_var(*src_dst);
                self.set_reg_constant_value(*src_dst, constant_value);
            }

            // === Field Access ===
            HirStmt::FollowCellPath { src_dst, path } => {
                self.lower_follow_cell_path(*src_dst, *path)?;
            }

            HirStmt::CloneCellPath { dst, src, path } => {
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
                    self.assign_fresh_vreg(*dst)
                } else {
                    self.get_vreg(*dst)
                };
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
                if let Some(ty) = self.vreg_type_hints.get(&src_vreg).cloned() {
                    self.vreg_type_hints.insert(dst_vreg, ty);
                }
                self.lower_follow_cell_path(*dst, *path)?;
            }

            HirStmt::UpsertCellPath {
                src_dst,
                path,
                new_value,
            } => {
                self.lower_upsert_cell_path(*src_dst, *path, *new_value)?;
            }

            // === Commands ===
            HirStmt::Call {
                decl_id,
                src_dst,
                args,
            } => {
                self.set_call_args(args)?;
                self.lower_call(*decl_id, *src_dst)?;
            }

            // === Records ===
            HirStmt::RecordInsert { src_dst, key, val } => {
                self.lower_record_insert(*src_dst, *key, *val)?;
            }

            HirStmt::RecordSpread { src_dst, items } => {
                self.lower_record_spread(*src_dst, *items)?;
            }

            // === Lists ===
            HirStmt::ListPush { src_dst, item } => {
                let constant_value = match (
                    self.get_metadata(*src_dst)
                        .and_then(|meta| meta.constant_value.clone()),
                    self.get_metadata(*item)
                        .and_then(|meta| meta.constant_value.clone()),
                ) {
                    (Some(Value::List { mut vals, .. }), Some(item_value)) => {
                        vals.push(item_value);
                        Some(Value::list(vals, Span::unknown()))
                    }
                    _ => None,
                };
                let list_vreg = self.get_vreg(*src_dst);
                let item_vreg = self.get_vreg(*item);

                // Emit ListPush instruction
                self.emit(MirInst::ListPush {
                    list: list_vreg,
                    item: item_vreg,
                });
                self.clear_source_var(*src_dst);
                self.set_reg_constant_value(*src_dst, constant_value);
            }

            HirStmt::ListSpread { src_dst, items } => {
                let constant_value = match (
                    self.get_metadata(*src_dst)
                        .and_then(|meta| meta.constant_value.clone()),
                    self.get_metadata(*items)
                        .and_then(|meta| meta.constant_value.clone()),
                ) {
                    (
                        Some(Value::List { mut vals, .. }),
                        Some(Value::List {
                            vals: spread_vals, ..
                        }),
                    ) => {
                        vals.extend(spread_vals);
                        Some(Value::list(vals, Span::unknown()))
                    }
                    _ => None,
                };
                // ListSpread adds all items from one list to another
                let dst_list = self.get_vreg(*src_dst);
                let src_list = self.get_vreg(*items);

                let (_slot, max_len) = self
                    .get_metadata(*items)
                    .and_then(|meta| meta.list_buffer)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "List spread requires a source list with compile-time known maximum length in eBPF"
                                .into(),
                        )
                    })?;

                if max_len == 0 {
                    return Ok(());
                }

                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: len_vreg,
                    list: src_list,
                });

                let continuation_block = self.func.alloc_block();
                for i in 0..max_len {
                    let copy_block = self.func.alloc_block();
                    let next_block = if i + 1 == max_len {
                        continuation_block
                    } else {
                        self.func.alloc_block()
                    };

                    let cmp_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::Const(i as i64),
                        rhs: MirValue::VReg(len_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_vreg,
                        if_true: copy_block,
                        if_false: next_block,
                    });

                    self.current_block = copy_block;
                    let item_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListGet {
                        dst: item_vreg,
                        list: src_list,
                        idx: MirValue::Const(i as i64),
                    });
                    self.emit(MirInst::ListPush {
                        list: dst_list,
                        item: item_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });

                    self.current_block = next_block;
                }

                self.clear_source_var(*src_dst);
                self.set_reg_constant_value(*src_dst, constant_value);
            }

            // === String Interpolation ===
            HirStmt::StringAppend { src_dst, val } => {
                let constant_value = self.get_metadata(*src_dst).and_then(|meta| {
                    let Value::String { val: mut dst, .. } = meta.constant_value.clone()? else {
                        return None;
                    };
                    let appended = self
                        .get_metadata(*val)
                        .and_then(|meta| meta.constant_value.clone())?
                        .coerce_into_string()
                        .ok()?;
                    dst.push_str(&appended);
                    Some(Value::string(dst, Span::unknown()))
                });
                let dst_slot = self.get_metadata(*src_dst).and_then(|m| m.string_slot);
                let val_meta = self.get_metadata(*val).cloned();

                // For string append, we need:
                // 1. A string buffer (from Literal::String or a built interpolation)
                // 2. A value to append (string, int, etc.)
                if let Some(slot) = dst_slot {
                    let len_vreg_existing =
                        self.get_metadata(*src_dst).and_then(|m| m.string_len_vreg);
                    let len_was_missing = len_vreg_existing.is_none();
                    let len_vreg = len_vreg_existing.unwrap_or_else(|| {
                        let len_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::Copy {
                            dst: len_vreg,
                            src: MirValue::Const(0),
                        });
                        len_vreg
                    });

                    if len_was_missing {
                        let meta = self.get_or_create_metadata(*src_dst);
                        meta.string_len_vreg = Some(len_vreg);
                    }

                    // Determine what type of value we're appending and its max length.
                    let (val_type, append_max) = if val_meta
                        .as_ref()
                        .map(|m| m.string_slot.is_some())
                        .unwrap_or(false)
                    {
                        let val_slot = val_meta.as_ref().unwrap().string_slot.unwrap();
                        let max_len = val_meta
                            .as_ref()
                            .and_then(|m| m.string_len_bound)
                            .or_else(|| self.stack_slot_size(val_slot).map(|s| s.saturating_sub(1)))
                            .unwrap_or(0);
                        let append_max = max_len.min(STRING_APPEND_COPY_CAP);
                        (
                            StringAppendType::StringSlot {
                                slot: val_slot,
                                max_len: append_max,
                            },
                            append_max,
                        )
                    } else if val_meta
                        .as_ref()
                        .map(|m| m.literal_string.is_some())
                        .unwrap_or(false)
                    {
                        let bytes = val_meta
                            .as_ref()
                            .unwrap()
                            .literal_string
                            .as_ref()
                            .unwrap()
                            .as_bytes()
                            .to_vec();
                        let append_max = bytes
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|idx| idx + 1)
                            .unwrap_or(0);
                        (StringAppendType::Literal { bytes }, append_max)
                    } else {
                        // Default to integer
                        (StringAppendType::Integer, MAX_INT_STRING_LEN)
                    };

                    let slot_size = self.stack_slot_size(slot).unwrap_or(0);
                    let current_bound = self
                        .get_metadata(*src_dst)
                        .and_then(|m| m.string_len_bound)
                        .unwrap_or_else(|| {
                            if len_was_missing {
                                0
                            } else {
                                slot_size.saturating_sub(1)
                            }
                        });
                    let new_bound = current_bound.saturating_add(append_max);
                    let new_size = self.ensure_string_slot_capacity(slot, new_bound)?;
                    let meta = self.get_or_create_metadata(*src_dst);
                    meta.string_len_bound = Some(new_bound);
                    meta.field_type = Some(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: new_size,
                    });

                    let val_vreg = self.get_vreg(*val);
                    self.emit(MirInst::StringAppend {
                        dst_buffer: slot,
                        dst_len: len_vreg,
                        val: MirValue::VReg(val_vreg),
                        val_type,
                    });
                    self.clear_source_var(*src_dst);
                    self.set_reg_constant_value(*src_dst, constant_value);
                }
            }

            HirStmt::GlobFrom { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Glob expansion is not supported in eBPF".into(),
                ));
            }

            // === Variables ===
            HirStmt::LoadVariable { dst, var_id } => {
                self.lower_load_variable(*dst, *var_id)?;
            }

            HirStmt::StoreVariable { var_id, src } => {
                if let Some(global) = self.annotated_mut_globals.get(var_id).cloned() {
                    if self.pending_annotated_mut_global_init_stores.remove(var_id) {
                        self.var_mappings.remove(var_id);
                        self.var_metadata.remove(var_id);
                        return Ok(());
                    }

                    let src_vreg = self.get_vreg(*src);
                    self.store_into_mutable_global(
                        &format!("annotated mutable variable {}", var_id.get()),
                        &global,
                        *src,
                        src_vreg,
                    )?;
                    self.var_mappings.remove(var_id);
                    self.var_metadata.remove(var_id);
                    return Ok(());
                }

                if let Some(global) = self.mutable_capture_globals.get(var_id).cloned() {
                    let src_vreg = self.get_vreg(*src);
                    self.store_into_mutable_global(
                        &format!("captured variable {}", var_id.get()),
                        &global,
                        *src,
                        src_vreg,
                    )?;
                    self.var_mappings.remove(var_id);
                    self.var_metadata.remove(var_id);
                    return Ok(());
                }

                if let Some(&source_var) = self.subfunction_global_aliases.get(var_id) {
                    let src_vreg = self.get_vreg(*src);
                    if let Some(global) = self.annotated_mut_globals.get(&source_var).cloned() {
                        self.store_into_mutable_global(
                            &format!("annotated mutable variable {}", source_var.get()),
                            &global,
                            *src,
                            src_vreg,
                        )?;
                        self.bind_variable_to_src_value(*var_id, *src, src_vreg)?;
                        return Ok(());
                    }

                    if let Some(global) = self.mutable_capture_globals.get(&source_var).cloned() {
                        self.store_into_mutable_global(
                            &format!("captured variable {}", source_var.get()),
                            &global,
                            *src,
                            src_vreg,
                        )?;
                        self.bind_variable_to_src_value(*var_id, *src, src_vreg)?;
                        return Ok(());
                    }
                }

                let src_vreg = self.get_vreg(*src);
                self.bind_variable_to_src_value(*var_id, *src, src_vreg)?;
            }

            HirStmt::DropVariable { var_id } => {
                if self.annotated_mut_globals.contains_key(var_id)
                    || self.mutable_capture_globals.contains_key(var_id)
                {
                    return Ok(());
                }
                self.var_mappings.remove(var_id);
                self.var_metadata.remove(var_id);
            }

            // === Environment Variables (not supported in eBPF) ===
            HirStmt::LoadEnv { key, .. } | HirStmt::LoadEnvOpt { key, .. } => {
                // Environment variables are not accessible from eBPF (kernel space)
                // Get the key name for a better error message
                let key_name = std::str::from_utf8(key).unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Environment variable access ($env.{}) is not supported in eBPF.                      eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            HirStmt::StoreEnv { key, .. } => {
                let key_name = std::str::from_utf8(key).unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Setting environment variable ($env.{}) is not supported in eBPF.                      eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            // === No-ops ===
            HirStmt::Span { .. }
            | HirStmt::Collect { .. }
            | HirStmt::CheckErrRedirected { .. }
            | HirStmt::OpenFile { .. }
            | HirStmt::WriteFile { .. }
            | HirStmt::CloseFile { .. }
            | HirStmt::RedirectOut { .. }
            | HirStmt::RedirectErr { .. }
            | HirStmt::OnError { .. }
            | HirStmt::OnErrorInto { .. }
            | HirStmt::PopErrorHandler
            | HirStmt::CheckMatchGuard { .. } => {
                // No-ops in eBPF (no spans/streams/redirection/files)
            }

            HirStmt::Drop { src } | HirStmt::Drain { src } | HirStmt::DrainIfEnd { src } => {
                self.invalidate_reg_value(*src);
            }
        }
        Ok(())
    }

    pub(super) fn lower_terminator(&mut self, term: &HirTerminator) -> Result<(), CompileError> {
        match term {
            HirTerminator::Goto { target } => {
                let target = *self
                    .hir_block_map
                    .get(target)
                    .ok_or_else(|| CompileError::UnsupportedInstruction("Invalid block".into()))?;
                self.terminate(MirInst::Jump { target });
            }
            HirTerminator::Jump { target } => {
                let target_block = *self
                    .hir_block_map
                    .get(target)
                    .ok_or_else(|| CompileError::UnsupportedInstruction("Invalid block".into()))?;
                if let Some(loop_ctx) = self.loop_contexts.last() {
                    if target_block == loop_ctx.header_block {
                        self.terminate(MirInst::LoopBack {
                            counter: loop_ctx.counter_vreg,
                            step: loop_ctx.step,
                            header: loop_ctx.header_block,
                        });
                        return Ok(());
                    }
                    if target_block == loop_ctx.exit_block {
                        self.loop_contexts.pop();
                        self.terminate(MirInst::Jump {
                            target: target_block,
                        });
                        return Ok(());
                    }
                }
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }
            HirTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } => {
                let if_true = *self.hir_block_map.get(if_true).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let if_false = *self.hir_block_map.get(if_false).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let cond_vreg = self.get_vreg(*cond);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
                    if_true,
                    if_false,
                });
            }
            HirTerminator::BranchIfEmpty {
                src,
                if_true,
                if_false,
            } => {
                let if_true = *self.hir_block_map.get(if_true).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let if_false = *self.hir_block_map.get(if_false).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let src_vreg = self.get_vreg(*src);
                let cmp_result = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: cmp_result,
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(src_vreg),
                    rhs: MirValue::Const(0),
                });
                self.terminate(MirInst::Branch {
                    cond: cmp_result,
                    if_true,
                    if_false,
                });
            }
            HirTerminator::Match {
                pattern,
                src,
                if_true,
                if_false,
            } => {
                let if_true = *self.hir_block_map.get(if_true).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid match target".into())
                })?;
                let if_false = *self.hir_block_map.get(if_false).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid match target".into())
                })?;
                self.lower_match(pattern, *src, if_true, if_false)?;
            }
            HirTerminator::Iterate {
                dst,
                stream,
                body,
                end,
            } => {
                let dst_vreg = self.get_vreg(*dst);
                let body_block = *self.hir_block_map.get(body).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop body".into())
                })?;
                let exit_block = *self.hir_block_map.get(end).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop exit".into())
                })?;

                if let Some(range) = self.get_metadata(*stream).and_then(|m| m.bounded_range) {
                    let counter_vreg = self.get_vreg(*stream);
                    let limit = if range.inclusive {
                        range.end + range.step.signum()
                    } else {
                        range.end
                    };

                    self.terminate(MirInst::LoopHeader {
                        counter: counter_vreg,
                        start: range.start,
                        step: range.step,
                        limit,
                        body: body_block,
                        exit: exit_block,
                    });

                    self.loop_body_inits
                        .entry(body_block)
                        .or_default()
                        .push(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(counter_vreg),
                        });
                    self.loop_body_inits
                        .entry(exit_block)
                        .or_default()
                        .push(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(0),
                        });

                    self.loop_contexts.push(LoopContext {
                        header_block: self.current_block,
                        exit_block,
                        counter_vreg,
                        step: range.step,
                    });
                } else if let Some((_slot, max_len)) =
                    self.get_metadata(*stream).and_then(|m| m.list_buffer)
                {
                    let list_vreg = self.get_vreg(*stream);
                    let counter_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: counter_vreg,
                        src: MirValue::Const(0),
                    });

                    let guard_block = self.func.alloc_block();
                    self.terminate(MirInst::LoopHeader {
                        counter: counter_vreg,
                        start: 0,
                        step: 1,
                        limit: max_len as i64,
                        body: guard_block,
                        exit: exit_block,
                    });

                    let old_block = self.current_block;
                    self.current_block = guard_block;
                    let len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListLen {
                        dst: len_vreg,
                        list: list_vreg,
                    });
                    let cmp_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::VReg(counter_vreg),
                        rhs: MirValue::VReg(len_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_vreg,
                        if_true: body_block,
                        if_false: exit_block,
                    });
                    self.current_block = old_block;

                    self.loop_body_inits
                        .entry(body_block)
                        .or_default()
                        .push(MirInst::ListGet {
                            dst: dst_vreg,
                            list: list_vreg,
                            idx: MirValue::VReg(counter_vreg),
                        });
                    self.loop_body_inits
                        .entry(exit_block)
                        .or_default()
                        .push(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(0),
                        });

                    self.loop_contexts.push(LoopContext {
                        header_block: old_block,
                        exit_block,
                        counter_vreg,
                        step: 1,
                    });
                } else if self
                    .lower_fixed_array_iterate(*dst, *stream, body_block, exit_block, true)?
                {
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "Iterate requires a compile-time known range, bounded list, or fixed array"
                            .into(),
                    ));
                }
            }
            HirTerminator::Return { src } | HirTerminator::ReturnEarly { src } => {
                let (value, seed) = self.returned_value_for_reg(*src)?;
                self.note_return_seed(seed);
                let val = Some(value);
                self.terminate(MirInst::Return { val });
            }
            HirTerminator::Unreachable => {
                return Err(CompileError::UnsupportedInstruction(
                    "Encountered unreachable block".into(),
                ));
            }
        }
        Ok(())
    }
}
