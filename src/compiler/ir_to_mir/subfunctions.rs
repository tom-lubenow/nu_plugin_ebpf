use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn get_or_create_subfunction(
        &mut self,
        decl_id: DeclId,
    ) -> Result<SubfunctionId, CompileError> {
        if let Some(&subfn_id) = self.subfunction_registry.get(&decl_id) {
            return Ok(subfn_id);
        }

        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;

        if !self.subfunction_in_progress.insert(decl_id) {
            return Err(CompileError::UnsupportedInstruction(
                "Recursive user-defined functions are not supported in eBPF".into(),
            ));
        }

        let param_vars = self.subfunction_params(decl_id, hir);
        let sig = self.decl_signatures.get(&decl_id);
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        let mut subfn = MirFunction::with_name(name);
        let sig_param_count = sig.map(Self::sig_param_count);
        let param_count = sig_param_count.unwrap_or(param_vars.len());
        subfn.param_count = param_count + usize::from(needs_input);

        let old_func = std::mem::replace(&mut self.func, subfn);
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_current_block = self.current_block;
        let old_pipeline_input = self.pipeline_input.take();
        let old_pipeline_input_reg = self.pipeline_input_reg.take();
        let old_positional_args = std::mem::take(&mut self.positional_args);
        let old_named_flags = std::mem::take(&mut self.named_flags);
        let old_named_args = std::mem::take(&mut self.named_args);
        let old_var_mappings = std::mem::take(&mut self.var_mappings);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_type_hints = std::mem::replace(
            &mut self.current_type_hints,
            self.decl_type_hints
                .get(&decl_id)
                .cloned()
                .unwrap_or_default(),
        );
        let old_vreg_hints = std::mem::take(&mut self.vreg_type_hints);
        let old_ctx_param = self.ctx_param;

        self.ctx_param = None;

        let param_base = Self::infer_param_base_var_id(hir);
        if needs_input {
            let vreg = self.func.alloc_vreg();
            if let Some(reg) = input_reg {
                self.reg_map.insert(reg.get(), vreg);
            }
            if uses_in {
                self.var_mappings.insert(IN_VARIABLE_ID, vreg);
            }
        }

        if let Some(base) = param_base {
            let base = base.get();
            for i in 0..param_count {
                let vreg = self.func.alloc_vreg();
                let var_id = VarId::new(base + i);
                self.var_mappings.insert(var_id, vreg);
            }
        } else {
            for var_id in &param_vars {
                let vreg = self.func.alloc_vreg();
                self.var_mappings.insert(*var_id, vreg);
            }
            for _ in param_vars.len()..param_count {
                let _unused = self.func.alloc_vreg();
            }
        }

        let result = self.lower_block(hir);

        let subfn = std::mem::replace(&mut self.func, old_func);
        let subfn_hints = std::mem::replace(&mut self.vreg_type_hints, old_vreg_hints);

        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.current_block = old_current_block;
        self.pipeline_input = old_pipeline_input;
        self.pipeline_input_reg = old_pipeline_input_reg;
        self.positional_args = old_positional_args;
        self.named_flags = old_named_flags;
        self.named_args = old_named_args;
        self.var_mappings = old_var_mappings;
        self.loop_contexts = old_loop_contexts;
        self.hir_block_map = old_hir_block_map;
        self.loop_body_inits = old_loop_body_inits;
        self.current_type_hints = old_type_hints;
        self.ctx_param = old_ctx_param;

        self.subfunction_in_progress.remove(&decl_id);

        if let Err(err) = result {
            return Err(err);
        }

        let subfn_id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(subfn);
        self.subfunction_hints.push(subfn_hints);
        self.subfunction_registry.insert(decl_id, subfn_id);

        Ok(subfn_id)
    }
}
