use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn infer_param_vars(hir: &HirFunction) -> Vec<VarId> {
        let mut stored = HashSet::new();
        let mut params = HashSet::new();

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::StoreVariable { var_id, .. } = stmt {
                    stored.insert(*var_id);
                }
            }
        }

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id != IN_VARIABLE_ID && !stored.contains(var_id) {
                        params.insert(*var_id);
                    }
                }
            }
        }

        let mut vars: Vec<VarId> = params.into_iter().collect();
        vars.sort_by_key(|var_id| var_id.get());
        vars
    }

    pub(super) fn infer_param_base_var_id(hir: &HirFunction) -> Option<VarId> {
        let mut stored = HashSet::new();
        let mut min_var: Option<usize> = None;

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::StoreVariable { var_id, .. } = stmt {
                    stored.insert(*var_id);
                }
            }
        }

        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id != IN_VARIABLE_ID && !stored.contains(var_id) {
                        let id = var_id.get();
                        min_var = Some(min_var.map_or(id, |cur| cur.min(id)));
                    }
                }
            }
        }

        min_var.map(VarId::new)
    }

    pub(super) fn uses_in_variable(hir: &HirFunction) -> bool {
        for block in &hir.blocks {
            for stmt in &block.stmts {
                if let HirStmt::LoadVariable { var_id, .. } = stmt {
                    if *var_id == IN_VARIABLE_ID {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub(super) fn infer_pipeline_input_reg(hir: &HirFunction) -> Option<RegId> {
        for block in &hir.blocks {
            for stmt in &block.stmts {
                match stmt {
                    HirStmt::Collect { src_dst }
                    | HirStmt::Drain { src: src_dst }
                    | HirStmt::DrainIfEnd { src: src_dst } => {
                        return Some(*src_dst);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    pub(super) fn sig_param_count(sig: &UserFunctionSig) -> usize {
        sig.params
            .iter()
            .filter(|param| param.kind != UserParamKind::Input)
            .count()
    }

    pub(super) fn build_args_from_signature(
        &mut self,
        sig: &UserFunctionSig,
        src_dst: RegId,
        needs_input: bool,
    ) -> Result<Vec<VReg>, CompileError> {
        let mut args = Vec::new();
        let mut positional_idx = 0usize;
        let mut used_named = HashSet::new();
        let mut used_flags = HashSet::new();

        for param in &sig.params {
            match param.kind {
                UserParamKind::Input => {
                    if needs_input {
                        args.push(self.input_vreg_for_call(src_dst));
                    }
                }
                UserParamKind::Positional => {
                    if let Some((vreg, _)) = self.positional_args.get(positional_idx) {
                        args.push(*vreg);
                        positional_idx += 1;
                    } else if param.optional {
                        args.push(self.const_vreg(0));
                    } else {
                        return Err(CompileError::UnsupportedInstruction(
                            "User-defined function missing positional arguments".into(),
                        ));
                    }
                }
                UserParamKind::Named => {
                    let name = param
                        .name
                        .as_ref()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "User-defined function named parameter missing name".into(),
                            )
                        })?
                        .to_string();
                    if let Some((vreg, _)) = self.named_args.get(&name) {
                        used_named.insert(name);
                        args.push(*vreg);
                    } else if param.optional {
                        args.push(self.const_vreg(0));
                    } else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "User-defined function missing named argument '{}'",
                            name
                        )));
                    }
                }
                UserParamKind::Switch => {
                    let name = param
                        .name
                        .as_ref()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "User-defined function switch parameter missing name".into(),
                            )
                        })?
                        .to_string();
                    if self.named_flags.contains(&name) {
                        used_flags.insert(name);
                        args.push(self.const_vreg(1));
                    } else {
                        args.push(self.const_vreg(0));
                    }
                }
                UserParamKind::Rest => {
                    return Err(CompileError::UnsupportedInstruction(
                        "User-defined functions with rest parameters are not supported".into(),
                    ));
                }
            }
        }

        if positional_idx != self.positional_args.len() {
            return Err(CompileError::UnsupportedInstruction(
                "User-defined function argument count mismatch (too many positional args)".into(),
            ));
        }

        for name in self.named_args.keys() {
            if !used_named.contains(name) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "User-defined function does not accept named argument '{}'",
                    name
                )));
            }
        }

        for flag in &self.named_flags {
            if !used_flags.contains(flag) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "User-defined function does not accept flag '{}'",
                    flag
                )));
            }
        }

        Ok(args)
    }

    pub(super) fn subfunction_params(&mut self, decl_id: DeclId, func: &HirFunction) -> Vec<VarId> {
        if let Some(params) = self.subfunction_params.get(&decl_id) {
            return params.clone();
        }
        let params = Self::infer_param_vars(func);
        self.subfunction_params.insert(decl_id, params.clone());
        params
    }

    pub(super) fn lower_user_function_call(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
        dst_vreg: VReg,
    ) -> Result<(), CompileError> {
        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let args = if let Some(sig) = self.decl_signatures.get(&decl_id) {
            self.build_args_from_signature(sig, src_dst, needs_input)?
        } else {
            if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                return Err(CompileError::UnsupportedInstruction(
                    "User-defined functions do not support named arguments or flags yet".into(),
                ));
            }
            let param_vars = self.subfunction_params(decl_id, hir);

            let input_vreg = self.input_vreg_for_call(src_dst);
            let mut args = Vec::new();
            if needs_input {
                args.push(input_vreg);
            }

            let mut positional_idx = 0usize;
            for _ in &param_vars {
                let (arg_vreg, _) = self.positional_args.get(positional_idx).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "User-defined function missing positional arguments".into(),
                    )
                })?;
                args.push(*arg_vreg);
                positional_idx += 1;
            }

            if positional_idx != self.positional_args.len() {
                return Err(CompileError::UnsupportedInstruction(
                    "User-defined function argument count mismatch (too many positional args)"
                        .into(),
                ));
            }
            args
        };

        if args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF subfunctions support at most 5 arguments".into(),
            ));
        }

        let subfn = self.get_or_create_subfunction(decl_id)?;
        self.emit(MirInst::CallSubfn {
            dst: dst_vreg,
            subfn,
            args,
        });

        self.reg_metadata.remove(&src_dst.get());
        Ok(())
    }
}
