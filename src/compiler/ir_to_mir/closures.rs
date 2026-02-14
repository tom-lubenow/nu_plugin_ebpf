use super::*;

impl<'a> HirToMirLowering<'a> {
    #[allow(dead_code)]
    pub(super) fn inline_user_function(
        &mut self,
        _decl_id: DeclId,
        _dst_vreg: VReg,
        _positional_args: &[(VReg, RegId)],
    ) -> Result<(), CompileError> {
        Err(CompileError::UnsupportedInstruction(
            "User-defined function inlining is not supported in plugin context".into(),
        ))
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

        let val_vreg = self.get_vreg(val);

        // Get the type from the value register's metadata, defaulting to I64
        let field_type = self
            .get_metadata(val)
            .and_then(|m| m.field_type.clone())
            .unwrap_or(MirType::I64);

        // IMPORTANT: Create a fresh VReg and copy the value to preserve it.
        // The IR reuses registers, so val_vreg might be overwritten by subsequent operations.
        // By copying to a fresh VReg, we ensure the value is preserved until emit time.
        let preserved_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved_vreg,
            src: MirValue::VReg(val_vreg),
        });

        // Add field to the record being built (using preserved VReg with inferred type)
        let field = RecordField {
            name: field_name,
            value_vreg: preserved_vreg,
            stack_offset: None,
            ty: field_type,
        };

        let meta = self.get_or_create_metadata(src_dst);
        meta.record_fields.push(field);

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
            if !self.var_mappings.contains_key(&var_id) {
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

            match &block.terminator {
                HirTerminator::Return { src } => {
                    let src_vreg = self.get_vreg(*src);
                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::VReg(src_vreg),
                    });
                    self.terminate(MirInst::Jump {
                        target: continuation_block,
                    });
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
        let dst_vreg = self.get_vreg(dst);

        // Check if this is a parameter from an inlined function
        if let Some(&param_vreg) = self.var_mappings.get(&var_id) {
            // Copy the parameter value to the destination
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(param_vreg),
            });
            return Ok(());
        }

        // Check if this is the context parameter variable
        if let Some(ctx_var) = self.ctx_param
            && var_id == ctx_var
        {
            // Mark this register as holding the context
            let meta = self.get_or_create_metadata(dst);
            meta.is_context = true;
            // Emit a placeholder - actual context access happens in FollowCellPath
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::Const(0), // Placeholder
            });
            return Ok(());
        }

        // Check if this is a captured variable
        for (name, value) in self.captures {
            // We'd need the variable name to match, but we only have var_id
            // For now, check if any capture matches by trying them all
            let _ = (name, value);
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "Variable {} not found in captures or function parameters",
            var_id.get()
        )))
    }
}
