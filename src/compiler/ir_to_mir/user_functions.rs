use super::*;
use crate::compiler::subfn_summaries::{
    SubfunctionReturnSummary, infer_subfunction_return_summaries,
};
use nu_protocol::Record;

#[derive(Debug, Clone, Copy)]
pub(super) struct UserFunctionCallArg {
    pub(super) vreg: VReg,
    pub(super) source_reg: Option<RegId>,
}

impl<'a> HirToMirLowering<'a> {
    fn constant_record_key_value(
        reg_constants: &HashMap<RegId, Value>,
        key: RegId,
    ) -> Option<String> {
        reg_constants.get(&key).and_then(|value| match value {
            Value::String { val, .. } | Value::Glob { val, .. } => Some(val.clone()),
            Value::Binary { val, .. } => String::from_utf8(val.clone()).ok(),
            _ => None,
        })
    }

    fn constant_follow_cell_path(value: &Value, path: &CellPath) -> Option<Value> {
        let mut current = value.clone();
        for member in &path.members {
            match member {
                PathMember::String { val, .. } => {
                    let Value::Record { val: record, .. } = &current else {
                        return None;
                    };
                    current = record.get(val)?.clone();
                }
                PathMember::Int { val, .. } => {
                    let Value::List { vals, .. } = &current else {
                        return None;
                    };
                    current = vals.get(*val as usize)?.clone();
                }
            }
        }
        Some(current)
    }

    fn eval_constant_user_function_return(hir: &HirFunction) -> Option<Value> {
        if hir.blocks.len() != 1 {
            return None;
        }
        let block = hir.blocks.first()?;
        let HirTerminator::Return { src } = block.terminator else {
            return None;
        };

        let mut reg_constants = HashMap::<RegId, Value>::new();
        let mut var_constants = HashMap::<VarId, Value>::new();

        for stmt in &block.stmts {
            match stmt {
                HirStmt::LoadLiteral { dst, lit } => {
                    if let Some(value) = lit.to_constant_value() {
                        reg_constants.insert(*dst, value);
                    } else {
                        match lit {
                            HirLiteral::List { .. } => {
                                reg_constants
                                    .insert(*dst, Value::list(Vec::new(), Span::unknown()));
                            }
                            HirLiteral::Record { .. } => {
                                reg_constants
                                    .insert(*dst, Value::record(Record::new(), Span::unknown()));
                            }
                            _ => return None,
                        }
                    }
                }
                HirStmt::LoadValue { dst, val } => {
                    reg_constants.insert(*dst, (**val).clone());
                }
                HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
                    let value = reg_constants.get(src)?.clone();
                    reg_constants.insert(*dst, value);
                }
                HirStmt::LoadVariable { dst, var_id } => {
                    let value = var_constants.get(var_id)?.clone();
                    reg_constants.insert(*dst, value);
                }
                HirStmt::StoreVariable { var_id, src } => {
                    let value = reg_constants.get(src)?.clone();
                    var_constants.insert(*var_id, value);
                }
                HirStmt::DropVariable { var_id } => {
                    var_constants.remove(var_id);
                }
                HirStmt::StringAppend { src_dst, val } => {
                    let Value::String { val: mut dst, .. } = reg_constants.get(src_dst)?.clone()
                    else {
                        return None;
                    };
                    let appended = reg_constants.get(val)?.clone().coerce_into_string().ok()?;
                    dst.push_str(&appended);
                    reg_constants.insert(*src_dst, Value::string(dst, Span::unknown()));
                }
                HirStmt::ListPush { src_dst, item } => {
                    let Value::List { mut vals, .. } = reg_constants.get(src_dst)?.clone() else {
                        return None;
                    };
                    vals.push(reg_constants.get(item)?.clone());
                    reg_constants.insert(*src_dst, Value::list(vals, Span::unknown()));
                }
                HirStmt::RecordInsert { src_dst, key, val } => {
                    let Value::Record { val: record, .. } = reg_constants.get(src_dst)?.clone()
                    else {
                        return None;
                    };
                    let mut record = record.into_owned();
                    let key = Self::constant_record_key_value(&reg_constants, *key)?;
                    let value = reg_constants.get(val)?.clone();
                    record.insert(key, value);
                    reg_constants.insert(*src_dst, Value::record(record, Span::unknown()));
                }
                HirStmt::FollowCellPath { src_dst, path } => {
                    let value = reg_constants.get(src_dst)?.clone();
                    let path_value = reg_constants.get(path)?;
                    let Value::CellPath { val: cell_path, .. } = path_value else {
                        return None;
                    };
                    let projected = Self::constant_follow_cell_path(&value, cell_path)?;
                    reg_constants.insert(*src_dst, projected);
                }
                HirStmt::Collect { .. }
                | HirStmt::Span { .. }
                | HirStmt::Drain { .. }
                | HirStmt::DrainIfEnd { .. }
                | HirStmt::Drop { .. }
                | HirStmt::RedirectOut { .. }
                | HirStmt::RedirectErr { .. }
                | HirStmt::CheckErrRedirected { .. }
                | HirStmt::OnError { .. }
                | HirStmt::OnErrorInto { .. }
                | HirStmt::PopErrorHandler => {}
                _ => return None,
            }
        }

        reg_constants.get(&src).cloned()
    }

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

    pub(super) fn infer_referenced_var_base_var_id(hir: &HirFunction) -> Option<VarId> {
        let mut min_var: Option<usize> = None;

        for block in &hir.blocks {
            for stmt in &block.stmts {
                let var_id = match stmt {
                    HirStmt::LoadVariable { var_id, .. }
                    | HirStmt::StoreVariable { var_id, .. }
                    | HirStmt::DropVariable { var_id } => Some(*var_id),
                    _ => None,
                };
                if let Some(var_id) = var_id
                    && var_id != IN_VARIABLE_ID
                {
                    let id = var_id.get();
                    min_var = Some(min_var.map_or(id, |cur| cur.min(id)));
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
        fn stmt_defined_reg(stmt: &HirStmt) -> Option<RegId> {
            match stmt {
                HirStmt::LoadLiteral { dst, .. }
                | HirStmt::LoadValue { dst, .. }
                | HirStmt::Move { dst, .. }
                | HirStmt::Clone { dst, .. }
                | HirStmt::CloneCellPath { dst, .. }
                | HirStmt::LoadVariable { dst, .. }
                | HirStmt::LoadEnv { dst, .. }
                | HirStmt::LoadEnvOpt { dst, .. }
                | HirStmt::OnErrorInto { dst, .. } => Some(*dst),
                HirStmt::BinaryOp { lhs_dst, .. }
                | HirStmt::Not { src_dst: lhs_dst }
                | HirStmt::FollowCellPath {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::UpsertCellPath {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::RecordInsert {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::RecordSpread {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::StringAppend {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::GlobFrom {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::ListPush {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::ListSpread {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::Call {
                    src_dst: lhs_dst, ..
                }
                | HirStmt::Collect { src_dst: lhs_dst }
                | HirStmt::Span { src_dst: lhs_dst } => Some(*lhs_dst),
                _ => None,
            }
        }

        let mut defined = HashSet::new();
        for block in &hir.blocks {
            for stmt in &block.stmts {
                match stmt {
                    HirStmt::Collect { src_dst }
                    | HirStmt::Drain { src: src_dst }
                    | HirStmt::DrainIfEnd { src: src_dst } => {
                        if !defined.contains(src_dst) {
                            return Some(*src_dst);
                        }
                    }
                    _ => {}
                }
                if let Some(dst) = stmt_defined_reg(stmt) {
                    defined.insert(dst);
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

    fn build_args_from_signature(
        &mut self,
        sig: &UserFunctionSig,
        src_dst: RegId,
        needs_input: bool,
    ) -> Result<Vec<UserFunctionCallArg>, CompileError> {
        let mut args = Vec::new();
        let mut positional_idx = 0usize;
        let mut used_named = HashSet::new();
        let mut used_flags = HashSet::new();

        for param in &sig.params {
            match param.kind {
                UserParamKind::Input => {
                    if needs_input {
                        args.push(UserFunctionCallArg {
                            vreg: self.input_vreg_for_call(src_dst),
                            source_reg: self.input_source_reg_for_call(src_dst),
                        });
                    }
                }
                UserParamKind::Positional => {
                    if let Some((vreg, _)) = self.positional_args.get(positional_idx) {
                        args.push(UserFunctionCallArg {
                            vreg: *vreg,
                            source_reg: self
                                .positional_args
                                .get(positional_idx)
                                .map(|(_, reg)| *reg),
                        });
                        positional_idx += 1;
                    } else if param.optional {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
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
                        used_named.insert(name.clone());
                        args.push(UserFunctionCallArg {
                            vreg: *vreg,
                            source_reg: self.named_args.get(&name).map(|(_, reg)| *reg),
                        });
                    } else if param.optional {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
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
                        used_flags.insert(name.clone());
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(1),
                            source_reg: None,
                        });
                    } else {
                        args.push(UserFunctionCallArg {
                            vreg: self.const_vreg(0),
                            source_reg: None,
                        });
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

    fn input_source_reg_for_call(&self, src_dst: RegId) -> Option<RegId> {
        if self.pipeline_input.is_some() {
            self.pipeline_input_reg
        } else if self.reg_map.contains_key(&src_dst.get()) {
            Some(src_dst)
        } else {
            None
        }
    }

    fn should_inline_user_function_for_abi(hir: &HirFunction) -> bool {
        let has_aggregate_builder = hir.blocks.iter().any(|block| {
            block.stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    HirStmt::RecordInsert { .. }
                        | HirStmt::UpsertCellPath { .. }
                        | HirStmt::StringAppend { .. }
                        | HirStmt::ListPush { .. }
                        | HirStmt::LoadLiteral {
                            lit: HirLiteral::Record { .. } | HirLiteral::List { .. },
                            ..
                        }
                )
            })
        });
        has_aggregate_builder
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
        let call_args = if let Some(sig) = self.decl_signatures.get(&decl_id) {
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
                args.push(UserFunctionCallArg {
                    vreg: input_vreg,
                    source_reg: self.input_source_reg_for_call(src_dst),
                });
            }

            let mut positional_idx = 0usize;
            for _ in &param_vars {
                let (arg_vreg, _) = self.positional_args.get(positional_idx).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "User-defined function missing positional arguments".into(),
                    )
                })?;
                args.push(UserFunctionCallArg {
                    vreg: *arg_vreg,
                    source_reg: self
                        .positional_args
                        .get(positional_idx)
                        .map(|(_, reg)| *reg),
                });
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
        let call_args: Vec<UserFunctionCallArg> = call_args
            .into_iter()
            .map(|arg| {
                let vreg = if let Some(source_reg) = arg.source_reg {
                    self.materialized_metadata_aggregate_vreg(source_reg, arg.vreg)?
                } else {
                    arg.vreg
                };
                Ok(UserFunctionCallArg {
                    vreg,
                    source_reg: arg.source_reg,
                })
            })
            .collect::<Result<_, CompileError>>()?;

        if let Some(value) = Self::eval_constant_user_function_return(hir) {
            self.lower_constant_value(src_dst, &value)?;
            return Ok(());
        }

        // BPF subfunctions cannot safely return pointers to callee-local stack
        // aggregates. Inline simple aggregate-building bodies until we grow an
        // explicit aggregate return ABI.
        if Self::should_inline_user_function_for_abi(hir) {
            self.inline_user_function(decl_id, src_dst, dst_vreg, &call_args)?;
            return Ok(());
        }

        if call_args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF subfunctions support at most 5 arguments".into(),
            ));
        }

        let arg_seeds: Vec<SubfunctionArgSeed> = call_args
            .iter()
            .map(|arg| {
                let metadata = arg
                    .source_reg
                    .and_then(|reg| self.get_metadata(reg).cloned());
                let type_hint = self.vreg_type_hints.get(&arg.vreg).cloned().or_else(|| {
                    metadata.as_ref().and_then(|meta| {
                        meta.field_type
                            .clone()
                            .or_else(|| Self::metadata_record_layout(meta))
                    })
                });
                SubfunctionArgSeed {
                    type_hint,
                    metadata,
                }
            })
            .collect();
        let args: Vec<VReg> = call_args.iter().map(|arg| arg.vreg).collect();

        let subfn = self.get_or_create_subfunction(decl_id, &arg_seeds)?;
        let return_seed = self
            .subfunction_return_seeds
            .get(subfn.0 as usize)
            .cloned()
            .flatten();
        let returned_arg_seed = if let Some(SubfunctionReturnSummary::ReturnsArg(idx)) =
            infer_subfunction_return_summaries(&self.subfunctions)
                .get(&subfn)
                .copied()
        {
            arg_seeds.get(idx).cloned().inspect(|seed| {
                if let Some(arg_ty) = seed.type_hint.clone() {
                    self.vreg_type_hints.insert(dst_vreg, arg_ty);
                }
            })
        } else {
            None
        };
        self.emit(MirInst::CallSubfn {
            dst: dst_vreg,
            subfn,
            args,
        });

        self.reg_metadata.remove(&src_dst.get());
        if let Some(seed) = returned_arg_seed {
            if let Some(meta) = seed.metadata {
                self.reg_metadata.insert(src_dst.get(), meta);
            } else if let Some(arg_ty) = seed.type_hint {
                self.get_or_create_metadata(src_dst).field_type = Some(arg_ty);
            }
        } else if let Some(seed) = return_seed {
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
}
