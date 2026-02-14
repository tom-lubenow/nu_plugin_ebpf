use super::*;

/// Lower HIR to MIR
///
/// This is the main entry point for the HIR → MIR conversion.
///
/// The `decl_names` parameter maps DeclId to command names for the eBPF helper
/// commands (emit, count, histogram, etc.). In plugin context, this is built
/// by querying the engine via `find_decl()`.
pub struct MirLoweringResult {
    pub program: MirProgram,
    pub type_hints: MirTypeHints,
}

pub fn lower_hir_to_mir_with_hints(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    let hir_type_hints = type_info.map(mir_hints_from_hir);
    let mut lowering = HirToMirLowering::new(
        probe_ctx,
        decl_names,
        &hir.closures,
        &hir.captures,
        hir.ctx_param,
        hir_type_hints.as_ref(),
        user_functions,
        decl_signatures,
    );
    lowering.lower_block(&hir.main)?;
    let (program, type_hints) = lowering.finish_with_hints();
    Ok(MirLoweringResult {
        program,
        type_hints,
    })
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
    captures: &[(String, i64)],
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
