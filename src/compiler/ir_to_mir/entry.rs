use super::*;

/// Lower HIR to MIR
///
/// This is the main entry point for the HIR → MIR conversion.
///
/// The `decl_names` parameter maps DeclId to command names for the eBPF helper
/// commands (emit, count, histogram, etc.). In plugin context, this is built
/// by querying the engine via `find_decl()`.
#[derive(Debug)]
pub struct MirLoweringResult {
    pub program: MirProgram,
    pub type_hints: MirTypeHints,
    pub generic_map_key_types: HashMap<MapRef, MirType>,
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    pub generic_map_value_semantics: HashMap<MapRef, AnnotatedValueSemantics>,
    pub readonly_globals: Vec<ReadonlyGlobal>,
    pub data_globals: Vec<DataGlobal>,
    pub bss_globals: Vec<BssGlobal>,
}

fn collect_mutated_capture_vars(
    hir: &HirProgram,
    user_functions: &HashMap<DeclId, HirFunction>,
) -> HashSet<VarId> {
    fn scan_function(func: &HirFunction, capture_ids: &HashSet<VarId>, out: &mut HashSet<VarId>) {
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let HirStmt::StoreVariable { var_id, .. } = stmt
                    && capture_ids.contains(var_id)
                {
                    out.insert(*var_id);
                }
            }
        }
    }

    let capture_ids: HashSet<VarId> = hir.captures.iter().map(|(var_id, _)| *var_id).collect();
    let mut mutated = HashSet::new();
    scan_function(&hir.main, &capture_ids, &mut mutated);
    for closure in hir.closures.values() {
        scan_function(closure, &capture_ids, &mut mutated);
    }
    for func in user_functions.values() {
        scan_function(func, &capture_ids, &mut mutated);
    }
    mutated
}

fn constant_string_value(value: &Value) -> Option<String> {
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Some(val.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct NamedGlobalPredeclaration {
    kind: NamedGlobalPredeclarationKind,
}

#[derive(Debug, Clone)]
enum NamedGlobalPredeclarationKind {
    Value { value: Value, initialize: bool },
    TypedValue { type_spec: String, value: Value },
    TypeSpec(String),
}

impl NamedGlobalPredeclarationKind {
    fn priority(&self) -> u8 {
        match self {
            Self::Value {
                initialize: false, ..
            } => 1,
            Self::TypeSpec(_) => 2,
            Self::Value {
                initialize: true, ..
            } => 3,
            Self::TypedValue { .. } => 4,
        }
    }
}

fn collect_named_global_predeclarations_for_function(
    func: &HirFunction,
    decl_names: &HashMap<DeclId, String>,
) -> HashMap<String, NamedGlobalPredeclaration> {
    let mut candidates = HashMap::new();
    let mut reg_constants = HashMap::<RegId, Value>::new();
    let mut var_constants = HashMap::<VarId, Value>::new();
    let mut seen_global_set = HashSet::<String>::new();
    let mut pending_forward_gets = HashSet::<String>::new();

    for block in &func.blocks {
        for stmt in &block.stmts {
            match stmt {
                stmt @ (HirStmt::LoadLiteral { .. }
                | HirStmt::LoadValue { .. }
                | HirStmt::Move { .. }
                | HirStmt::Clone { .. }
                | HirStmt::LoadVariable { .. }
                | HirStmt::StoreVariable { .. }
                | HirStmt::DropVariable { .. }) => {
                    if HirToMirLowering::apply_constant_hir_stmt(
                        stmt,
                        &mut reg_constants,
                        &mut var_constants,
                    )
                    .is_none()
                    {
                        match stmt {
                            HirStmt::LoadLiteral { dst, .. }
                            | HirStmt::LoadValue { dst, .. }
                            | HirStmt::Move { dst, .. }
                            | HirStmt::Clone { dst, .. }
                            | HirStmt::LoadVariable { dst, .. } => {
                                reg_constants.remove(dst);
                            }
                            HirStmt::StoreVariable { var_id, .. }
                            | HirStmt::DropVariable { var_id } => {
                                var_constants.remove(var_id);
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                HirStmt::Call {
                    decl_id,
                    src_dst,
                    args,
                } => {
                    if let Some(cmd_name) = decl_names.get(decl_id) {
                        match cmd_name.as_str() {
                            "global-define" => {
                                let zero_init =
                                    args.flags.iter().any(|flag| flag.as_slice() == b"zero");
                                let type_spec = args.named.iter().find_map(|(name, reg)| {
                                    (name.as_slice() == b"type")
                                        .then(|| {
                                            reg_constants.get(reg).and_then(constant_string_value)
                                        })
                                        .flatten()
                                });
                                if let Some(name_reg) = args.positional.first()
                                    && let Some(name) =
                                        reg_constants.get(name_reg).and_then(constant_string_value)
                                {
                                    let constant_value = reg_constants.get(src_dst).cloned();
                                    let candidate = if let Some(type_spec) = type_spec {
                                        NamedGlobalPredeclaration {
                                            kind: if let Some(value) = constant_value {
                                                NamedGlobalPredeclarationKind::TypedValue {
                                                    type_spec,
                                                    value,
                                                }
                                            } else {
                                                NamedGlobalPredeclarationKind::TypeSpec(type_spec)
                                            },
                                        }
                                    } else if let Some(value) = constant_value {
                                        NamedGlobalPredeclaration {
                                            kind: NamedGlobalPredeclarationKind::Value {
                                                value,
                                                initialize: !zero_init,
                                            },
                                        }
                                    } else {
                                        continue;
                                    };
                                    candidates
                                        .entry(name)
                                        .and_modify(|existing: &mut NamedGlobalPredeclaration| {
                                            if candidate.kind.priority() > existing.kind.priority()
                                            {
                                                *existing = candidate.clone();
                                            }
                                        })
                                        .or_insert(candidate);
                                }
                            }
                            "global-get" => {
                                if let Some(name_reg) = args.positional.first()
                                    && let Some(name) =
                                        reg_constants.get(name_reg).and_then(constant_string_value)
                                    && !seen_global_set.contains(&name)
                                {
                                    pending_forward_gets.insert(name);
                                }
                            }
                            "global-set" => {
                                if let Some(name_reg) = args.positional.first()
                                    && let Some(name) =
                                        reg_constants.get(name_reg).and_then(constant_string_value)
                                {
                                    if pending_forward_gets.contains(&name)
                                        && let Some(value) = reg_constants.get(src_dst).cloned()
                                    {
                                        candidates.entry(name.clone()).or_insert(
                                            NamedGlobalPredeclaration {
                                                kind: NamedGlobalPredeclarationKind::Value {
                                                    value,
                                                    initialize: false,
                                                },
                                            },
                                        );
                                    }
                                    seen_global_set.insert(name);
                                }
                            }
                            _ => {}
                        }
                    }
                    reg_constants.remove(src_dst);
                }
                stmt @ (HirStmt::BinaryOp { .. }
                | HirStmt::Not { .. }
                | HirStmt::FollowCellPath { .. }
                | HirStmt::UpsertCellPath { .. }
                | HirStmt::RecordInsert { .. }
                | HirStmt::RecordSpread { .. }
                | HirStmt::StringAppend { .. }
                | HirStmt::GlobFrom { .. }
                | HirStmt::ListPush { .. }
                | HirStmt::ListSpread { .. }) => {
                    if HirToMirLowering::apply_constant_hir_stmt(
                        stmt,
                        &mut reg_constants,
                        &mut var_constants,
                    )
                    .is_none()
                    {
                        match stmt {
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
                            } => {
                                reg_constants.remove(lhs_dst);
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                HirStmt::Collect { src_dst: lhs_dst } | HirStmt::Span { src_dst: lhs_dst } => {
                    reg_constants.remove(lhs_dst);
                }
                HirStmt::CloneCellPath { dst, .. }
                | HirStmt::LoadEnv { dst, .. }
                | HirStmt::LoadEnvOpt { dst, .. }
                | HirStmt::OnErrorInto { dst, .. } => {
                    reg_constants.remove(dst);
                }
                HirStmt::Drop { .. }
                | HirStmt::Drain { .. }
                | HirStmt::DrainIfEnd { .. }
                | HirStmt::StoreEnv { .. }
                | HirStmt::RedirectOut { .. }
                | HirStmt::RedirectErr { .. }
                | HirStmt::CheckErrRedirected { .. }
                | HirStmt::OpenFile { .. }
                | HirStmt::WriteFile { .. }
                | HirStmt::CloseFile { .. }
                | HirStmt::OnError { .. }
                | HirStmt::PopErrorHandler
                | HirStmt::CheckMatchGuard { .. } => {}
            }
        }
    }

    candidates
}

fn collect_named_global_predeclarations(
    hir: &HirProgram,
    decl_names: &HashMap<DeclId, String>,
    user_functions: &HashMap<DeclId, HirFunction>,
) -> Vec<(String, NamedGlobalPredeclaration)> {
    let mut merged = HashMap::<String, NamedGlobalPredeclaration>::new();

    for (name, value) in collect_named_global_predeclarations_for_function(&hir.main, decl_names) {
        merged
            .entry(name)
            .and_modify(|existing| {
                if value.kind.priority() > existing.kind.priority() {
                    *existing = value.clone();
                }
            })
            .or_insert(value);
    }
    for closure in hir.closures.values() {
        for (name, value) in collect_named_global_predeclarations_for_function(closure, decl_names)
        {
            merged
                .entry(name)
                .and_modify(|existing| {
                    if value.kind.priority() > existing.kind.priority() {
                        *existing = value.clone();
                    }
                })
                .or_insert(value);
        }
    }
    for func in user_functions.values() {
        for (name, value) in collect_named_global_predeclarations_for_function(func, decl_names) {
            merged
                .entry(name)
                .and_modify(|existing| {
                    if value.kind.priority() > existing.kind.priority() {
                        *existing = value.clone();
                    }
                })
                .or_insert(value);
        }
    }

    merged.into_iter().collect()
}

pub fn lower_hir_to_mir_with_hints_maps_and_semantics(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    external_map_value_types: Option<&HashMap<MapRef, MirType>>,
    external_map_value_semantics: Option<&HashMap<MapRef, AnnotatedValueSemantics>>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        hir,
        probe_ctx,
        decl_names,
        type_info,
        None,
        external_map_value_types,
        external_map_value_semantics,
        user_functions,
        decl_signatures,
    )
}

pub fn lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    external_map_key_types: Option<&HashMap<MapRef, MirType>>,
    external_map_value_types: Option<&HashMap<MapRef, MirType>>,
    external_map_value_semantics: Option<&HashMap<MapRef, AnnotatedValueSemantics>>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    let hir_type_hints = type_info.map(mir_hints_from_hir);
    let mutated_capture_vars = collect_mutated_capture_vars(hir, user_functions);
    let forward_named_globals =
        collect_named_global_predeclarations(hir, decl_names, user_functions);
    let mut lowering = HirToMirLowering::new(
        probe_ctx,
        decl_names,
        &hir.closures,
        &hir.captures,
        hir.ctx_param,
        hir_type_hints.as_ref(),
        external_map_key_types,
        external_map_value_types,
        external_map_value_semantics,
        user_functions,
        decl_signatures,
    );
    lowering.init_mutable_capture_globals(&mutated_capture_vars)?;
    lowering.init_annotated_mut_globals(&hir.annotated_mut_globals)?;
    for (name, predecl) in forward_named_globals {
        match predecl.kind {
            NamedGlobalPredeclarationKind::Value { value, initialize } => {
                lowering.predeclare_named_program_global_from_value(&name, &value, initialize)?;
            }
            NamedGlobalPredeclarationKind::TypedValue { type_spec, value } => {
                lowering.define_named_program_global_from_type_spec_and_value(
                    &name, &type_spec, &value,
                )?;
            }
            NamedGlobalPredeclarationKind::TypeSpec(type_spec) => {
                lowering.define_named_program_global_from_type_spec(&name, &type_spec)?;
            }
        }
    }
    lowering.lower_block(&hir.main)?;
    let (
        program,
        type_hints,
        generic_map_key_types,
        generic_map_value_types,
        generic_map_value_semantics,
        readonly_globals,
        data_globals,
        bss_globals,
    ) = lowering.finish_with_hints();
    Ok(MirLoweringResult {
        program,
        type_hints,
        generic_map_key_types,
        generic_map_value_types,
        generic_map_value_semantics,
        readonly_globals,
        data_globals,
        bss_globals,
    })
}

pub fn lower_hir_to_mir_with_hints_and_maps(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    external_map_value_types: Option<&HashMap<MapRef, MirType>>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    lower_hir_to_mir_with_hints_maps_and_semantics(
        hir,
        probe_ctx,
        decl_names,
        type_info,
        external_map_value_types,
        None,
        user_functions,
        decl_signatures,
    )
}

pub fn lower_hir_to_mir_with_hints(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    lower_hir_to_mir_with_hints_and_maps(
        hir,
        probe_ctx,
        decl_names,
        type_info,
        None,
        user_functions,
        decl_signatures,
    )
}

pub fn lower_hir_to_mir(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
) -> Result<MirProgram, CompileError> {
    let empty_user_functions = HashMap::new();
    let empty_signatures = HashMap::new();
    let result = lower_hir_to_mir_with_hints(
        hir,
        probe_ctx,
        decl_names,
        None,
        &empty_user_functions,
        &empty_signatures,
    )?;
    Ok(result.program)
}

/// Lower Nushell IR to MIR
///
/// This preserves the old entry point by converting IR → HIR → MIR.
pub fn lower_ir_to_mir(
    ir_block: &IrBlock,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    closure_irs: &HashMap<nu_protocol::BlockId, IrBlock>,
    captures: &[(VarId, Value)],
    ctx_param: Option<VarId>,
) -> Result<MirProgram, CompileError> {
    let hir_program = lower_ir_to_hir(
        ir_block.clone(),
        closure_irs.clone(),
        captures.to_vec(),
        ctx_param,
    )?;
    lower_hir_to_mir(&hir_program, probe_ctx, decl_names)
}
