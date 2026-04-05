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
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    pub readonly_globals: Vec<ReadonlyGlobal>,
    pub data_globals: Vec<DataGlobal>,
    pub bss_globals: Vec<BssGlobal>,
}

fn collect_mutated_capture_vars(
    hir: &HirProgram,
    user_functions: &HashMap<DeclId, HirFunction>,
) -> HashSet<VarId> {
    fn scan_function(
        func: &HirFunction,
        capture_ids: &HashSet<VarId>,
        out: &mut HashSet<VarId>,
    ) {
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

pub fn lower_hir_to_mir_with_hints_and_maps(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    external_map_value_types: Option<&HashMap<MapRef, MirType>>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    let hir_type_hints = type_info.map(mir_hints_from_hir);
    let mutated_capture_vars = collect_mutated_capture_vars(hir, user_functions);
    let mut lowering = HirToMirLowering::new(
        probe_ctx,
        decl_names,
        &hir.closures,
        &hir.captures,
        hir.ctx_param,
        hir_type_hints.as_ref(),
        external_map_value_types,
        user_functions,
        decl_signatures,
    );
    lowering.init_mutable_capture_globals(&mutated_capture_vars)?;
    lowering.lower_block(&hir.main)?;
    let (
        program,
        type_hints,
        generic_map_value_types,
        readonly_globals,
        data_globals,
        bss_globals,
    ) =
        lowering.finish_with_hints();
    Ok(MirLoweringResult {
        program,
        type_hints,
        generic_map_value_types,
        readonly_globals,
        data_globals,
        bss_globals,
    })
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
