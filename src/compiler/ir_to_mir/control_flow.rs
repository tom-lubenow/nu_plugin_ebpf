use super::*;

impl<'a> HirToMirLowering<'a> {
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
                for (dst, src) in inits {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(src),
                    });
                }
            }

            for stmt in &block.stmts {
                self.lower_stmt(stmt)?;
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

            HirStmt::LoadValue { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "LoadValue is not supported in eBPF lowering".into(),
                ));
            }

            HirStmt::Move { dst, src } => {
                // Copy value and metadata
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                // Copy metadata
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            HirStmt::Clone { dst, src } => {
                // Same as Move for our purposes
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            // === Arithmetic ===
            HirStmt::BinaryOp { lhs_dst, op, rhs } => {
                self.lower_binary_op(*lhs_dst, *op, *rhs)?;
            }

            HirStmt::Not { src_dst } => {
                let vreg = self.get_vreg(*src_dst);
                self.emit(MirInst::UnaryOp {
                    dst: vreg,
                    op: crate::compiler::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(vreg),
                });
            }

            // === Field Access ===
            HirStmt::FollowCellPath { src_dst, path } => {
                self.lower_follow_cell_path(*src_dst, *path)?;
            }

            HirStmt::CloneCellPath { dst, src, path } => {
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
                self.lower_follow_cell_path(*dst, *path)?;
            }

            HirStmt::UpsertCellPath {
                src_dst,
                path,
                new_value,
            } => {
                // Cell path updates (like $record.field = 42) are not supported
                // in eBPF because:
                // 1. Records are stack-allocated with fixed layout
                // 2. Most eBPF programs build records once for emission
                // Get the path for a better error message
                let path_str = self
                    .get_metadata(*path)
                    .and_then(|m| {
                        m.cell_path.as_ref().map(|cp| {
                            cp.members
                                .iter()
                                .map(|m| match m {
                                    PathMember::String { val, .. } => val.clone(),
                                    PathMember::Int { val, .. } => val.to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join(".")
                        })
                    })
                    .unwrap_or_else(|| "<unknown>".to_string());

                let _ = (src_dst, new_value); // Silence unused warnings
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Cell path update (.{} = ...) is not supported in eBPF.                      Consider building the record with the correct value initially.",
                    path_str
                )));
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

            HirStmt::RecordSpread { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Record spread is not supported in eBPF".into(),
                ));
            }

            // === Lists ===
            HirStmt::ListPush { src_dst, item } => {
                let list_vreg = self.get_vreg(*src_dst);
                let item_vreg = self.get_vreg(*item);

                // Emit ListPush instruction
                self.emit(MirInst::ListPush {
                    list: list_vreg,
                    item: item_vreg,
                });

                // Copy metadata from source list
                if let Some(meta) = self.get_metadata(*src_dst).cloned() {
                    self.reg_metadata.insert(src_dst.get(), meta);
                }
            }

            HirStmt::ListSpread { src_dst, items } => {
                // ListSpread adds all items from one list to another
                // For now, we'll emit a bounded loop that copies elements
                let dst_list = self.get_vreg(*src_dst);
                let src_list = self.get_vreg(*items);

                // Get source list metadata for bounds
                let src_meta = self.get_metadata(*items).cloned();
                if let Some(meta) = src_meta {
                    if let Some((_slot, max_len)) = meta.list_buffer {
                        // Emit length load and bounded copy loop
                        let len_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListLen {
                            dst: len_vreg,
                            list: src_list,
                        });

                        // For each item in source list, push to destination
                        // This is done at compile time for known small lists
                        for i in 0..max_len {
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
                        }
                    }
                }
            }

            // === String Interpolation ===
            HirStmt::StringAppend { src_dst, val } => {
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
                let src_vreg = self.get_vreg(*src);
                let preserved = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: preserved,
                    src: MirValue::VReg(src_vreg),
                });
                self.var_mappings.insert(*var_id, preserved);
            }

            HirStmt::DropVariable { var_id } => {
                self.var_mappings.remove(var_id);
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
            | HirStmt::Drop { .. }
            | HirStmt::Drain { .. }
            | HirStmt::DrainIfEnd { .. }
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
            HirTerminator::BranchIfEmpty { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "BranchIfEmpty is not supported in eBPF".into(),
                ));
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
                let range = self
                    .get_metadata(*stream)
                    .and_then(|m| m.bounded_range)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Iterate requires a compile-time known range (e.g., 1..10)".into(),
                        )
                    })?;

                let dst_vreg = self.get_vreg(*dst);
                let counter_vreg = self.get_vreg(*stream);

                let limit = if range.inclusive {
                    range.end + range.step.signum()
                } else {
                    range.end
                };

                let body_block = *self.hir_block_map.get(body).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop body".into())
                })?;
                let exit_block = *self.hir_block_map.get(end).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop exit".into())
                })?;

                self.terminate(MirInst::LoopHeader {
                    counter: counter_vreg,
                    limit,
                    body: body_block,
                    exit: exit_block,
                });

                self.loop_body_inits
                    .entry(body_block)
                    .or_default()
                    .push((dst_vreg, counter_vreg));

                self.loop_contexts.push(LoopContext {
                    header_block: self.current_block,
                    exit_block,
                    counter_vreg,
                    step: range.step,
                });
            }
            HirTerminator::Return { src } => {
                let val = Some(MirValue::VReg(self.get_vreg(*src)));
                self.terminate(MirInst::Return { val });
            }
            HirTerminator::ReturnEarly { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Return early is not supported in eBPF".into(),
                ));
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
