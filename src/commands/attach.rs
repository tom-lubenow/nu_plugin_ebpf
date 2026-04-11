//! `ebpf attach` command - attach an eBPF probe

use std::collections::{HashMap, HashSet};

use nu_cmd_lang::create_default_context;
use nu_parser::parse;
use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::ast::{Expr, ListItem, RecordItem};
use nu_protocol::casing::Casing;
use nu_protocol::engine::{Closure, StateWorkingSet};
use nu_protocol::eval_const::eval_constant;
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{
    BlockId, Category, DeclId, Example, IntoSpanned, LabeledError, PipelineData, Record, Signature,
    Span, Spanned, SyntaxShape, Type, Value, record,
};

use crate::EbpfPlugin;
use crate::compiler::mir::{MirFunction, MirInst, MirProgram};
use crate::compiler::{
    EbpfObject, MapRef, MirCompileResult, MirType, ProbeContext, ProgramIntrinsic,
    StructOpsObjectSpec, StructOpsValueField, UserFunctionSig, UserParam, UserParamKind,
    compile_mir_to_ebpf_with_hints_and_globals, hir::AnnotatedMutGlobal, hir::HirFunction,
    hir::HirProgram, hir::HirStmt, hir::supports_constant_value, hir_type_infer, infer_ctx_param,
    lower_hir_to_mir_with_hints_maps_and_semantics, lower_ir_to_hir,
    passes::optimize_with_ssa_hints,
};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

mod struct_ops;

use self::struct_ops::{
    StructOpsTopLevelFieldKind, apply_struct_ops_value_field, default_struct_ops_object_name,
    sanitize_struct_ops_component, validate_required_struct_ops_callbacks,
    validate_required_struct_ops_value_fields, validate_sched_ext_callback_kfunc_requirements,
    validate_struct_ops_attach_safety, validate_struct_ops_top_level_field_kind,
};

/// Common Nushell commands used in eBPF closures.
const NU_CLOSURE_COMMANDS: &[&str] = &[
    "where", "each", "skip", "first", "last", "get", "select", "reject", "default", "if", "match",
];

/// Build a mapping from DeclId to command name for known commands
fn build_decl_names(engine: &EngineInterface) -> Result<HashMap<DeclId, String>, LabeledError> {
    let mut decl_names = HashMap::new();

    for cmd_name in ProgramIntrinsic::command_names() {
        if let Some(decl_id) = engine.find_decl(cmd_name).map_err(|e| {
            LabeledError::new("Failed to look up command").with_label(
                format!("Could not find '{}': {}", cmd_name, e),
                Span::unknown(),
            )
        })? {
            decl_names.insert(decl_id, cmd_name.to_string());
        }
    }

    for &cmd_name in NU_CLOSURE_COMMANDS {
        if let Some(decl_id) = engine.find_decl(cmd_name).map_err(|e| {
            LabeledError::new("Failed to look up command").with_label(
                format!("Could not find '{}': {}", cmd_name, e),
                Span::unknown(),
            )
        })? {
            decl_names.insert(decl_id, cmd_name.to_string());
        }
    }

    Ok(decl_names)
}

fn is_known_closure_command(name: &str) -> bool {
    ProgramIntrinsic::from_command_name(name).is_some() || NU_CLOSURE_COMMANDS.contains(&name)
}

fn extract_decl_names_from_formatted_instructions(
    formatted_instructions: &[String],
) -> HashMap<DeclId, String> {
    let mut decl_names = HashMap::new();

    for line in formatted_instructions {
        let Some(decl_pos) = line.find("decl ") else {
            continue;
        };
        let after_decl = &line[(decl_pos + 5)..];
        let digits_len = after_decl
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .count();
        if digits_len == 0 {
            continue;
        }
        let Ok(decl_id) = after_decl[..digits_len].parse::<usize>() else {
            continue;
        };

        let after_digits = &after_decl[digits_len..];
        let Some(name_start) = after_digits.find('"') else {
            continue;
        };
        let after_quote = &after_digits[(name_start + 1)..];
        let Some(name_end) = after_quote.find('"') else {
            continue;
        };
        let name = &after_quote[..name_end];
        decl_names.insert(DeclId::new(decl_id), name.to_string());
    }

    decl_names
}

/// Recursively fetch IR for all closures referenced in an IR block
fn fetch_closure_irs(
    engine: &EngineInterface,
    ir_block: &IrBlock,
    closure_irs: &mut HashMap<BlockId, IrBlock>,
    decl_names: &mut HashMap<DeclId, String>,
    span: Span,
) -> Result<(), LabeledError> {
    use crate::compiler::extract_closure_block_ids;

    let block_ids = extract_closure_block_ids(ir_block);

    for block_id in block_ids {
        if closure_irs.contains_key(&block_id) {
            continue; // Already fetched
        }

        let (nested_ir, nested_decl_names) = fetch_block_ir(engine, block_id, span)?;
        decl_names.extend(nested_decl_names);

        // Recursively fetch any closures referenced by this closure
        fetch_closure_irs(engine, &nested_ir, closure_irs, decl_names, span)?;

        closure_irs.insert(block_id, nested_ir);
    }

    Ok(())
}

fn lower_capture_literals(
    closure: &Spanned<Closure>,
) -> Result<Vec<(nu_protocol::VarId, Value)>, LabeledError> {
    let mut captures = Vec::with_capacity(closure.item.captures.len());
    for (var_id, value) in &closure.item.captures {
        if !supports_constant_value(value) {
            return Err(LabeledError::new("Unsupported captured value in eBPF closure")
                .with_label(
                    format!(
                        "captured variable {} has unsupported type {}; supported captured constants are int, bool, string, binary, glob, filesize, duration, nothing, top-level numeric scalar lists, and recursively constant records",
                        var_id.get(),
                        value.get_type()
                    ),
                    closure.span,
                )
                .with_help(
                    "Bind the value to a supported scalar/string constant before attaching, or inline it directly in the closure",
                ));
        }
        captures.push((*var_id, value.clone()));
    }
    Ok(captures)
}

#[derive(Debug, Clone)]
struct LeadingVariableDeclaration {
    mutable: bool,
    declared_type: Option<Type>,
    initializer: Option<Value>,
}

struct CompiledClosureArtifacts {
    compile_result: MirCompileResult,
    generic_map_value_types: HashMap<MapRef, MirType>,
    generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
    used_kfuncs: HashSet<String>,
}

fn value_to_spanned_closure(value: Value, span: Span) -> Result<Spanned<Closure>, LabeledError> {
    match value {
        Value::Closure {
            val, internal_span, ..
        } => Ok(Spanned {
            item: *val,
            span: internal_span,
        }),
        other => Err(LabeledError::new("Invalid eBPF body")
            .with_label(
                format!(
                    "Expected a closure body for this attach target, got {}",
                    other.get_type()
                ),
                span,
            )
            .with_help("Use a closure like {|ctx| ... } for ordinary program types")),
    }
}

fn collect_used_kfuncs(program: &MirProgram) -> HashSet<String> {
    fn collect_from_inst(inst: &MirInst, out: &mut HashSet<String>) {
        if let MirInst::CallKfunc { kfunc, .. } = inst {
            out.insert(kfunc.clone());
        }
    }

    fn collect_from_function(func: &MirFunction, out: &mut HashSet<String>) {
        for block in &func.blocks {
            for inst in &block.instructions {
                collect_from_inst(inst, out);
            }
            collect_from_inst(&block.terminator, out);
        }
    }

    let mut out = HashSet::new();
    collect_from_function(&program.main, &mut out);
    for subfn in &program.subfunctions {
        collect_from_function(subfn, &mut out);
    }
    out
}

fn fetch_view_source(
    engine: &EngineInterface,
    closure: &Spanned<Closure>,
) -> Result<String, LabeledError> {
    let view_source_decl = engine
        .find_decl("view source")
        .map_err(|e| {
            LabeledError::new("Failed to look up 'view source'")
                .with_label(e.to_string(), closure.span)
        })?
        .ok_or_else(|| {
            LabeledError::new("Required command 'view source' not found").with_label(
                "Annotated mutable globals require view source",
                closure.span,
            )
        })?;

    let mut eval = EvaluatedCall::new(closure.span);
    eval.add_positional(Value::closure(closure.item.clone(), closure.span));
    let data = engine
        .call_decl(view_source_decl, eval, PipelineData::empty(), true, false)
        .map_err(|e| {
            LabeledError::new("Failed to run 'view source'").with_label(e.to_string(), closure.span)
        })?;
    let value = data.into_value(closure.span).map_err(|e| {
        LabeledError::new("Failed to decode 'view source' output")
            .with_label(e.to_string(), closure.span)
    })?;
    match value {
        Value::String { val, .. } => Ok(val),
        _ => Err(LabeledError::new("Unexpected 'view source' output type")
            .with_label("Expected string output from view source", closure.span)),
    }
}

fn eval_supported_constant_value(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
) -> Result<Value, LabeledError> {
    if let Ok(value) = eval_constant(working_set, expr) {
        return Ok(value);
    }

    match &expr.expr {
        Expr::Keyword(kw) => eval_supported_constant_value(working_set, &kw.expr),
        Expr::Subexpression(block_id) | Expr::Block(block_id) => {
            let block = working_set.get_block(*block_id);
            let expr = block
                .pipelines
                .first()
                .and_then(|pipeline| pipeline.elements.first())
                .map(|element| &element.expr)
                .ok_or_else(|| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label("constant subexpression is empty", expr.span)
                })?;
            eval_supported_constant_value(working_set, expr)
        }
        Expr::Record(items) => {
            let mut record = Record::new();
            for item in items {
                match item {
                    RecordItem::Pair(key_expr, value_expr) => {
                        let key = constant_record_key(working_set, key_expr)?;
                        let value = eval_supported_constant_value(working_set, value_expr)?;
                        record.push(key, value);
                    }
                    RecordItem::Spread(_, _) => {
                        return Err(
                            LabeledError::new("Unsupported annotated mutable global initializer")
                                .with_label(
                                    "record spreads are not supported in compile-time global initializers",
                                    expr.span,
                                ),
                        )
                    }
                }
            }
            Ok(Value::record(record, expr.span))
        }
        Expr::List(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    ListItem::Item(item_expr) => {
                        values.push(eval_supported_constant_value(working_set, item_expr)?);
                    }
                    ListItem::Spread(_, _) => {
                        return Err(
                            LabeledError::new("Unsupported annotated mutable global initializer")
                                .with_label(
                                    "list spreads are not supported in compile-time global initializers",
                                    expr.span,
                                ),
                        )
                    }
                }
            }
            Ok(Value::list(values, expr.span))
        }
        _ => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label("Not a constant.", expr.span)
            .with_help(
                "Leading annotated `mut` declarations in eBPF closures require a compile-time constant initializer",
            )),
    }
}

fn constant_record_key(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
) -> Result<String, LabeledError> {
    if let Ok(value) = eval_constant(working_set, expr) {
        return value.coerce_into_string().map_err(|e| {
            LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(e.to_string(), expr.span)
        });
    }

    if let Some(string) = expr.as_string() {
        return Ok(string);
    }
    if let Some((path, _quoted)) = expr.as_filepath() {
        return Ok(path);
    }

    match &expr.expr {
        Expr::Var(_) => {
            Ok(String::from_utf8_lossy(working_set.get_span_contents(expr.span)).into())
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label("record key is not a constant string", expr.span),
        ),
    }
}

fn parse_leading_variable_declarations(
    source: &str,
    span: Span,
) -> Result<Vec<LeadingVariableDeclaration>, LabeledError> {
    let engine_state = create_default_context();
    let mut working_set = StateWorkingSet::new(&engine_state);
    let top_block = parse(&mut working_set, None, source.as_bytes(), false);

    let closure_block_id = top_block
        .pipelines
        .iter()
        .flat_map(|pipeline| pipeline.elements.iter())
        .find_map(|element| match &element.expr.expr {
            Expr::Closure(block_id) | Expr::Block(block_id) => Some(*block_id),
            _ => None,
        })
        .ok_or_else(|| {
            LabeledError::new("Failed to recover closure source structure")
                .with_label("Expected closure source from view source", span)
        })?;

    let closure_block = working_set.get_block(closure_block_id);
    let mut declarations = Vec::new();
    let mut seen_non_declaration = false;

    for pipeline in &closure_block.pipelines {
        let Some(first) = pipeline.elements.first() else {
            continue;
        };
        let Expr::Call(call) = &first.expr.expr else {
            seen_non_declaration = true;
            continue;
        };
        let cmd_name = working_set.get_decl(call.decl_id).name();
        let is_var_decl = cmd_name == "mut" || cmd_name == "let";
        if !is_var_decl {
            seen_non_declaration = true;
            continue;
        }

        let var_expr = call.positional_nth(0).ok_or_else(|| {
            LabeledError::new("Failed to parse leading variable declaration")
                .with_label("Missing declaration target", first.expr.span)
        })?;
        let declared_type = (var_expr.ty != Type::Any).then(|| var_expr.ty.clone());
        let mutable = cmd_name == "mut";

        if seen_non_declaration && mutable && declared_type.is_some() {
            return Err(
                LabeledError::new("Annotated mutable globals must be declared first")
                    .with_label(
                        "typed `mut` declarations only become compiler-managed globals when they are contiguous at the start of the attached closure",
                        first.expr.span,
                    )
                    .with_help(
                        "Move this annotated `mut` declaration above function definitions and other statements, or drop the type annotation if you only want an ordinary local variable",
                    ),
            );
        }

        let initializer = if mutable && declared_type.is_some() {
            let init_expr = call
                .positional_nth(1)
                .map(|expr| expr.as_keyword().unwrap_or(expr))
                .ok_or_else(|| {
                    LabeledError::new("Failed to parse annotated mutable declaration")
                        .with_label("Missing initializer", first.expr.span)
                })?;
            Some(eval_supported_constant_value(&working_set, init_expr)?)
        } else {
            None
        };

        declarations.push(LeadingVariableDeclaration {
            mutable,
            declared_type,
            initializer,
        });

        if seen_non_declaration {
            continue;
        }
    }

    Ok(declarations)
}

fn collect_variable_declaration_store_var_ids(ir_block: &IrBlock) -> Vec<nu_protocol::VarId> {
    ir_block
        .instructions
        .iter()
        .zip(ir_block.comments.iter())
        .filter_map(|(inst, comment)| match (inst, comment.as_ref()) {
            (Instruction::StoreVariable { var_id, .. }, "let") => Some(*var_id),
            _ => None,
        })
        .collect()
}

fn map_leading_annotated_mut_globals(
    source: &str,
    ir_block: &IrBlock,
    span: Span,
) -> Result<Vec<AnnotatedMutGlobal>, LabeledError> {
    let declarations = parse_leading_variable_declarations(source, span)?;
    if declarations.is_empty() {
        return Ok(Vec::new());
    }

    let declaration_var_ids = collect_variable_declaration_store_var_ids(ir_block);
    if declaration_var_ids.len() < declarations.len() {
        return Err(LabeledError::new(
            "Failed to map annotated mutable globals onto closure variables",
        )
        .with_label(
            "The recovered source declarations did not match the closure IR declaration order",
            span,
        )
        .with_help(
            "Keep compiler-managed annotated `mut` declarations at the top of the attached closure",
        ));
    }

    Ok(declarations
        .into_iter()
        .zip(declaration_var_ids)
        .filter_map(|(decl, var_id)| {
            (decl.mutable && decl.declared_type.is_some())
                .then(|| {
                    decl.initializer.zip(decl.declared_type).map(
                        |(initial_value, declared_type)| AnnotatedMutGlobal {
                            var_id,
                            declared_type,
                            initial_value,
                        },
                    )
                })
                .flatten()
        })
        .collect())
}

fn strip_leading_annotated_mut_initializer_stmts(
    hir: &mut HirProgram,
    span: Span,
) -> Result<(), LabeledError> {
    if hir.annotated_mut_globals.is_empty() {
        return Ok(());
    }

    let entry = hir.main.entry.0;
    let stmts = &mut hir.main.blocks[entry].stmts;
    let mut cursor = 0usize;

    for annotated in &hir.annotated_mut_globals {
        let Some(rel_end) = stmts[cursor..].iter().position(
            |stmt| matches!(stmt, HirStmt::StoreVariable { var_id, .. } if *var_id == annotated.var_id),
        ) else {
            return Err(
                LabeledError::new("Failed to strip leading annotated mutable initializers")
                    .with_label(
                        format!(
                            "Could not locate the initializer store for annotated mutable variable {} in the entry block",
                            annotated.var_id.get()
                        ),
                        span,
                    )
                    .with_help(
                        "Keep compiler-managed annotated `mut` declarations contiguous at the start of the attached closure",
                    ),
            );
        };
        let store_idx = cursor + rel_end;
        let cleanup_src = match &stmts[store_idx] {
            HirStmt::StoreVariable { src, .. } => Some(*src),
            _ => None,
        };
        cursor = store_idx + 1;

        if let Some(cleanup_src) = cleanup_src {
            while let Some(stmt) = stmts.get(cursor) {
                match stmt {
                    HirStmt::Drain { src } | HirStmt::Drop { src } if *src == cleanup_src => {
                        cursor += 1;
                    }
                    HirStmt::DrainIfEnd { src } if *src == cleanup_src => {
                        cursor += 1;
                    }
                    _ => break,
                }
            }
        }
    }

    if cursor > 0 {
        stmts.drain(0..cursor);
    }

    Ok(())
}

fn parse_view_ir_json(
    json: &str,
    span: Span,
) -> Result<(IrBlock, HashMap<DeclId, String>), LabeledError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        LabeledError::new("Failed to parse 'view ir --json' output").with_label(e.to_string(), span)
    })?;
    let ir_value = value.get("ir_block").ok_or_else(|| {
        LabeledError::new("Missing ir_block in 'view ir --json' output")
            .with_label("Expected ir_block field", span)
    })?;
    let ir_block: IrBlock = serde_json::from_value(ir_value.clone()).map_err(|e| {
        LabeledError::new("Failed to decode 'view ir --json' block").with_label(e.to_string(), span)
    })?;
    let formatted_instructions = value
        .get("formatted_instructions")
        .and_then(|formatted| formatted.as_array())
        .map(|lines| {
            lines
                .iter()
                .filter_map(|line| line.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok((
        ir_block,
        extract_decl_names_from_formatted_instructions(&formatted_instructions),
    ))
}

fn fetch_view_ir_json(
    engine: &EngineInterface,
    eval: EvaluatedCall,
    span: Span,
) -> Result<(IrBlock, HashMap<DeclId, String>), LabeledError> {
    let view_ir_decl = engine
        .find_decl("view ir")
        .map_err(|e| {
            LabeledError::new("Failed to look up 'view ir'").with_label(e.to_string(), span)
        })?
        .ok_or_else(|| {
            LabeledError::new("Required command 'view ir' not found")
                .with_label("User-defined functions require view ir", span)
        })?;

    let data = engine
        .call_decl(view_ir_decl, eval, PipelineData::empty(), true, false)
        .map_err(|e| {
            LabeledError::new("Failed to run 'view ir'").with_label(e.to_string(), span)
        })?;
    let value = data.into_value(span).map_err(|e| {
        LabeledError::new("Failed to decode 'view ir' output").with_label(e.to_string(), span)
    })?;
    let json = match value {
        Value::String { val, .. } => val,
        _ => {
            return Err(LabeledError::new("Unexpected 'view ir' output type")
                .with_label("Expected string output from view ir --json", span));
        }
    };

    parse_view_ir_json(&json, span)
}

fn fetch_block_ir(
    engine: &EngineInterface,
    block_id: BlockId,
    span: Span,
) -> Result<(IrBlock, HashMap<DeclId, String>), LabeledError> {
    let mut eval = EvaluatedCall::new(span);
    eval.add_flag("json".into_spanned(span));
    eval.add_positional(Value::int(block_id.get() as i64, span));
    fetch_view_ir_json(engine, eval, span)
}

fn fetch_decl_ir(
    engine: &EngineInterface,
    decl_id: DeclId,
    span: Span,
) -> Result<(IrBlock, HashMap<DeclId, String>), LabeledError> {
    let mut eval = EvaluatedCall::new(span);
    eval.add_flag("json".into_spanned(span));
    eval.add_flag("decl-id".into_spanned(span));
    eval.add_positional(Value::int(decl_id.get() as i64, span));
    fetch_view_ir_json(engine, eval, span)
}

fn collect_user_function_irs(
    engine: &EngineInterface,
    ir_block: &IrBlock,
    closure_irs: &mut HashMap<BlockId, IrBlock>,
    decl_names: &mut HashMap<DeclId, String>,
    span: Span,
) -> Result<HashMap<DeclId, IrBlock>, LabeledError> {
    use crate::compiler::extract_call_decl_ids;

    fn scan_block(
        block: &IrBlock,
        decl_names: &HashMap<DeclId, String>,
        seen: &mut HashSet<DeclId>,
        pending: &mut Vec<DeclId>,
    ) {
        for decl_id in extract_call_decl_ids(block) {
            if decl_names
                .get(&decl_id)
                .is_some_and(|name| is_known_closure_command(name))
            {
                continue;
            }
            if seen.insert(decl_id) {
                pending.push(decl_id);
            }
        }
    }

    let mut pending = Vec::new();
    let mut seen = HashSet::new();

    scan_block(ir_block, decl_names, &mut seen, &mut pending);
    for ir in closure_irs.values() {
        scan_block(ir, decl_names, &mut seen, &mut pending);
    }

    let mut user_irs = HashMap::new();
    let mut scanned_closures: HashSet<BlockId> = closure_irs.keys().copied().collect();

    while let Some(decl_id) = pending.pop() {
        let (ir, fetched_decl_names) = fetch_decl_ir(engine, decl_id, span)?;
        decl_names.extend(fetched_decl_names);
        scan_block(&ir, decl_names, &mut seen, &mut pending);

        fetch_closure_irs(engine, &ir, closure_irs, decl_names, span)?;
        for (block_id, closure_ir) in closure_irs.iter() {
            if scanned_closures.insert(*block_id) {
                scan_block(closure_ir, decl_names, &mut seen, &mut pending);
            }
        }

        user_irs.insert(decl_id, ir);
    }

    Ok(user_irs)
}

fn signature_from_record(record: &Record) -> Option<UserFunctionSig> {
    let sig_val = record.cased(Casing::Sensitive).get("signatures")?;
    let sig_record = match sig_val {
        Value::Record { val, .. } => val,
        _ => return None,
    };
    let any_val = sig_record.cased(Casing::Sensitive).get("any")?;
    let params = match any_val {
        Value::List { vals, .. } => vals,
        _ => return None,
    };
    let mut out = Vec::new();
    for param in params {
        let record = match param {
            Value::Record { val, .. } => val,
            _ => continue,
        };
        let param_type = record
            .cased(Casing::Sensitive)
            .get("parameter_type")
            .and_then(|v| match v {
                Value::String { val, .. } => Some(val.as_str()),
                _ => None,
            })?;
        let name = record
            .cased(Casing::Sensitive)
            .get("parameter_name")
            .and_then(|v| match v {
                Value::String { val, .. } => Some(val.clone()),
                Value::Nothing { .. } => None,
                _ => None,
            });
        let optional = record
            .cased(Casing::Sensitive)
            .get("is_optional")
            .and_then(|v| match v {
                Value::Bool { val, .. } => Some(*val),
                _ => None,
            })
            .unwrap_or(false);
        let kind = match param_type {
            "input" => UserParamKind::Input,
            "positional" => UserParamKind::Positional,
            "named" => UserParamKind::Named,
            "switch" => UserParamKind::Switch,
            "rest" => UserParamKind::Rest,
            "output" => continue,
            _ => continue,
        };
        out.push(UserParam {
            name,
            kind,
            optional,
        });
    }
    Some(UserFunctionSig { params: out })
}

fn user_signature_from_ast_signature(sig: &Signature) -> UserFunctionSig {
    let mut params = Vec::new();
    params.push(UserParam {
        name: None,
        kind: UserParamKind::Input,
        optional: false,
    });

    params.extend(sig.required_positional.iter().map(|param| UserParam {
        name: Some(param.name.clone()),
        kind: UserParamKind::Positional,
        optional: false,
    }));
    params.extend(sig.optional_positional.iter().map(|param| UserParam {
        name: Some(param.name.clone()),
        kind: UserParamKind::Positional,
        optional: true,
    }));
    if let Some(rest) = &sig.rest_positional {
        params.push(UserParam {
            name: Some(rest.name.clone()),
            kind: UserParamKind::Rest,
            optional: true,
        });
    }
    params.extend(sig.named.iter().map(|flag| UserParam {
        name: Some(flag.long.clone()),
        kind: if flag.arg.is_some() {
            UserParamKind::Named
        } else {
            UserParamKind::Switch
        },
        optional: !flag.required,
    }));

    UserFunctionSig { params }
}

fn parse_inline_user_function_signatures(
    source: &str,
    decl_ids: &HashSet<DeclId>,
    decl_names: &HashMap<DeclId, String>,
    span: Span,
) -> Result<HashMap<DeclId, UserFunctionSig>, LabeledError> {
    if decl_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut name_to_decl_id = HashMap::new();
    let mut ambiguous_names = HashSet::new();
    for decl_id in decl_ids {
        let Some(name) = decl_names.get(decl_id).cloned() else {
            continue;
        };
        if name_to_decl_id.insert(name.clone(), *decl_id).is_some() {
            ambiguous_names.insert(name);
        }
    }
    for name in &ambiguous_names {
        name_to_decl_id.remove(name);
    }

    if name_to_decl_id.is_empty() {
        return Ok(HashMap::new());
    }

    let engine_state = create_default_context();
    let mut working_set = StateWorkingSet::new(&engine_state);
    let top_block = parse(&mut working_set, None, source.as_bytes(), false);

    let closure_block_id = top_block
        .pipelines
        .iter()
        .flat_map(|pipeline| pipeline.elements.iter())
        .find_map(|element| match &element.expr.expr {
            Expr::Closure(block_id) | Expr::Block(block_id) => Some(*block_id),
            _ => None,
        })
        .ok_or_else(|| {
            LabeledError::new("Failed to recover closure source structure")
                .with_label("Expected closure source from view source", span)
        })?;

    let closure_block = working_set.get_block(closure_block_id);
    let mut out = HashMap::new();

    for pipeline in &closure_block.pipelines {
        let Some(first) = pipeline.elements.first() else {
            continue;
        };
        let Expr::Call(call) = &first.expr.expr else {
            continue;
        };
        let cmd_name = working_set.get_decl(call.decl_id).name();
        if cmd_name != "def" {
            continue;
        }
        let Some(def_name) = call.positional_nth(0).and_then(|expr| expr.as_string()) else {
            continue;
        };
        let Some(&decl_id) = name_to_decl_id.get(&def_name) else {
            continue;
        };
        let Some(sig) = call.positional_nth(1).and_then(|expr| expr.as_signature()) else {
            continue;
        };
        out.insert(decl_id, user_signature_from_ast_signature(&sig));
    }

    Ok(out)
}

fn fetch_user_function_signatures(
    engine: &EngineInterface,
    decl_ids: &HashSet<DeclId>,
    span: Span,
) -> Result<HashMap<DeclId, UserFunctionSig>, LabeledError> {
    if decl_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let scope_decl = engine
        .find_decl("scope commands")
        .map_err(|e| {
            LabeledError::new("Failed to look up 'scope commands'").with_label(e.to_string(), span)
        })?
        .ok_or_else(|| {
            LabeledError::new("Required command 'scope commands' not found")
                .with_label("User-defined functions require scope commands", span)
        })?;

    let call = EvaluatedCall::new(span);
    let data = engine
        .call_decl(scope_decl, call, PipelineData::empty(), true, false)
        .map_err(|e| {
            LabeledError::new("Failed to run 'scope commands'").with_label(e.to_string(), span)
        })?;
    let value = data.into_value(span).map_err(|e| {
        LabeledError::new("Failed to decode 'scope commands' output")
            .with_label(e.to_string(), span)
    })?;

    let list = match value {
        Value::List { vals, .. } => vals,
        _ => {
            return Err(LabeledError::new("Unexpected 'scope commands' output type")
                .with_label("Expected list output from scope commands", span));
        }
    };

    let mut sigs = HashMap::new();
    for item in list {
        let record = match item {
            Value::Record { val, .. } => val,
            _ => continue,
        };
        let decl_id = record
            .cased(Casing::Sensitive)
            .get("decl_id")
            .and_then(|v| match v {
                Value::Int { val, .. } => Some(DeclId::new(*val as usize)),
                _ => None,
            });
        let decl_id = match decl_id {
            Some(id) => id,
            None => continue,
        };
        if !decl_ids.contains(&decl_id) {
            continue;
        }
        if let Some(sig) = signature_from_record(&record) {
            sigs.insert(decl_id, sig);
        }
    }

    Ok(sigs)
}

fn compile_closure_with_context(
    engine: &EngineInterface,
    closure: &Spanned<Closure>,
    probe_context: &ProbeContext,
    pin_group: Option<&str>,
    call_head: Span,
) -> Result<CompiledClosureArtifacts, LabeledError> {
    use crate::loader::{LoadError, get_state};

    let (ir_block, mut ir_decl_names) =
        fetch_block_ir(engine, closure.item.block_id, closure.span)?;
    let closure_source = fetch_view_source(engine, closure)?;
    let annotated_mut_globals =
        map_leading_annotated_mut_globals(&closure_source, &ir_block, closure.span)?;

    let mut decl_names = build_decl_names(engine)?;
    decl_names.extend(ir_decl_names.drain());

    let mut closure_irs = HashMap::new();
    fetch_closure_irs(
        engine,
        &ir_block,
        &mut closure_irs,
        &mut decl_names,
        call_head,
    )?;

    let user_ir_blocks = collect_user_function_irs(
        engine,
        &ir_block,
        &mut closure_irs,
        &mut decl_names,
        call_head,
    )?;

    let captures = lower_capture_literals(closure)?;
    let ctx_param = infer_ctx_param(&ir_block);

    let mut hir_program =
        lower_ir_to_hir(ir_block, closure_irs, captures, ctx_param).map_err(|e| {
            LabeledError::new("eBPF compilation failed")
                .with_label(e.to_string(), call_head)
                .with_help("The closure may use unsupported operations")
        })?;
    hir_program.annotated_mut_globals = annotated_mut_globals;
    strip_leading_annotated_mut_initializer_stmts(&mut hir_program, closure.span)?;

    let mut user_functions = HashMap::new();
    for (decl_id, ir) in user_ir_blocks.iter() {
        let func = HirFunction::from_ir_block(ir.clone()).map_err(|e| {
            LabeledError::new("eBPF compilation failed")
                .with_label(e.to_string(), call_head)
                .with_help("User-defined function uses unsupported operations")
        })?;
        user_functions.insert(*decl_id, func);
    }

    let user_decl_ids: HashSet<DeclId> = user_functions.keys().copied().collect();
    let mut user_signatures = fetch_user_function_signatures(engine, &user_decl_ids, call_head)?;
    let inline_signatures = parse_inline_user_function_signatures(
        &closure_source,
        &user_decl_ids,
        &decl_names,
        closure.span,
    )?;
    for (decl_id, sig) in inline_signatures {
        user_signatures.entry(decl_id).or_insert(sig);
    }
    let state = get_state();
    let external_map_value_types = pin_group
        .map(|group| {
            state
                .pinned_generic_map_value_types(group)
                .map_err(|e| match e {
                    LoadError::LockPoisoned => LabeledError::new("Failed to attach eBPF probe")
                        .with_label("loader state lock poisoned", call_head),
                    other => LabeledError::new("Failed to attach eBPF probe")
                        .with_label(other.to_string(), call_head),
                })
        })
        .transpose()?;
    let external_map_value_semantics = pin_group
        .map(|group| {
            state
                .pinned_generic_map_value_semantics(group)
                .map_err(|e| match e {
                    LoadError::LockPoisoned => LabeledError::new("Failed to attach eBPF probe")
                        .with_label("loader state lock poisoned", call_head),
                    other => LabeledError::new("Failed to attach eBPF probe")
                        .with_label(other.to_string(), call_head),
                })
        })
        .transpose()?;

    let hir_types = match hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    ) {
        Ok(types) => types,
        Err(errors) => {
            if let Some(err) = errors.into_iter().next() {
                return Err(LabeledError::new("eBPF compilation failed")
                    .with_label(err.to_string(), call_head)
                    .with_help("The closure may use unsupported operations"));
            }
            unreachable!("infer_hir_types returned empty error list");
        }
    };

    let lower_result = lower_hir_to_mir_with_hints_maps_and_semantics(
        &hir_program,
        Some(probe_context),
        &decl_names,
        Some(&hir_types),
        external_map_value_types.as_ref(),
        external_map_value_semantics.as_ref(),
        &user_functions,
        &user_signatures,
    )
    .map_err(|e| {
        LabeledError::new("eBPF compilation failed")
            .with_label(e.to_string(), call_head)
            .with_help("The closure may use unsupported operations")
    })?;
    let crate::compiler::MirLoweringResult {
        program: mut mir_program,
        mut type_hints,
        generic_map_value_types,
        generic_map_value_semantics,
        readonly_globals,
        data_globals,
        bss_globals,
    } = lower_result;

    optimize_with_ssa_hints(
        &mut mir_program.main,
        Some(probe_context),
        &mut type_hints.main,
        &type_hints.main_stack_slots,
        &type_hints.generic_map_value_types,
    );
    if type_hints.subfunctions.len() < mir_program.subfunctions.len() {
        type_hints
            .subfunctions
            .resize_with(mir_program.subfunctions.len(), HashMap::new);
    }
    if type_hints.subfunction_stack_slots.len() < mir_program.subfunctions.len() {
        type_hints
            .subfunction_stack_slots
            .resize_with(mir_program.subfunctions.len(), HashMap::new);
    }
    for (subfn, subfn_hints, subfn_stack_slots) in mir_program
        .subfunctions
        .iter_mut()
        .zip(type_hints.subfunctions.iter_mut())
        .zip(type_hints.subfunction_stack_slots.iter())
        .map(|((subfn, subfn_hints), subfn_stack_slots)| (subfn, subfn_hints, subfn_stack_slots))
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            subfn_hints,
            subfn_stack_slots,
            &type_hints.generic_map_value_types,
        );
    }

    let used_kfuncs = collect_used_kfuncs(&mir_program);

    let compile_result = compile_mir_to_ebpf_with_hints_and_globals(
        &mir_program,
        Some(probe_context),
        Some(&type_hints),
        readonly_globals,
        data_globals,
        bss_globals,
    )
    .map_err(|e| {
        LabeledError::new("eBPF compilation failed")
            .with_label(e.to_string(), call_head)
            .with_help("Check that the closure uses supported BPF operations")
    })?;

    Ok(CompiledClosureArtifacts {
        compile_result,
        generic_map_value_types,
        generic_map_value_semantics,
        used_kfuncs,
    })
}

fn compile_struct_ops_object(
    engine: &EngineInterface,
    value_type_name: &str,
    body: &Record,
    call_head: Span,
) -> Result<EbpfObject, LabeledError> {
    let object_name = default_struct_ops_object_name(value_type_name);
    validate_required_struct_ops_value_fields(value_type_name, body, call_head)?;
    let mut spec = StructOpsObjectSpec::zeroed_from_kernel_btf(&object_name, value_type_name)
        .map_err(|e| {
            LabeledError::new("Failed to initialize struct_ops object")
                .with_label(e.to_string(), call_head)
        })?;
    let mut callbacks = Vec::new();
    let mut callback_fields = HashSet::new();
    let mut callback_kfuncs = HashMap::new();

    for (field_name, value) in body.iter() {
        match value {
            Value::Closure {
                val, internal_span, ..
            } => {
                validate_struct_ops_top_level_field_kind(
                    value_type_name,
                    field_name,
                    StructOpsTopLevelFieldKind::Callback,
                    value.span(),
                )?;
                let closure = Spanned {
                    item: (**val).clone(),
                    span: *internal_span,
                };
                let probe_context =
                    ProbeContext::new_struct_ops_callback(value_type_name, field_name.as_str());
                let compiled = compile_closure_with_context(
                    engine,
                    &closure,
                    &probe_context,
                    None,
                    call_head,
                )?;
                let callback_name = format!(
                    "{}_{}",
                    object_name,
                    sanitize_struct_ops_component(field_name)
                );
                callback_fields.insert(field_name.to_string());
                callback_kfuncs.insert(field_name.to_string(), compiled.used_kfuncs.clone());
                callbacks.push(compiled.compile_result.into_struct_ops_callback(
                    field_name.as_str(),
                    callback_name,
                    compiled.generic_map_value_types,
                    compiled.generic_map_value_semantics,
                ));
            }
            _ => {
                validate_struct_ops_top_level_field_kind(
                    value_type_name,
                    field_name,
                    StructOpsTopLevelFieldKind::Value,
                    value.span(),
                )?;
                let mut field_path = vec![TrampolineFieldSelector::Field(field_name.to_string())];
                spec = apply_struct_ops_value_field(spec, &mut field_path, value)?;
            }
        }
    }

    if value_type_name == "sched_ext_ops" {
        validate_sched_ext_callback_kfunc_requirements(body, &callback_kfuncs, call_head)?;
    }

    validate_required_struct_ops_callbacks(value_type_name, &callback_fields, call_head)?;

    spec.to_object_with_compiled_callbacks(callbacks)
        .map_err(|e| {
            LabeledError::new("Failed to build struct_ops object")
                .with_label(e.to_string(), call_head)
        })
}

#[derive(Clone)]
pub struct EbpfAttach;

impl PluginCommand for EbpfAttach {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf attach"
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel hook such as a probe, tracepoint, userspace function, or packet hook."
    }

    fn extra_description(&self) -> &str {
        r#"This command compiles a Nushell closure to eBPF bytecode and attaches
it to the specified probe point. The closure runs in the kernel whenever
the probe point is hit.

Supported attach types:
  - kprobe, kretprobe
  - fentry, fexit, tp_btf
  - tracepoint, raw_tracepoint
  - uprobe, uretprobe
  - lsm
  - perf_event
  - socket_filter
  - xdp, tc
  - cgroup_skb
  - cgroup_device
  - cgroup_sock
  - sock_ops
  - sk_msg
  - sk_skb
  - sk_skb_parser
  - cgroup_sysctl
  - cgroup_sockopt
  - cgroup_sock_addr
  - sk_lookup
  - lirc_mode2
  - struct_ops

Body forms:
  - Ordinary program types use a closure body: {|ctx| ... }
  - struct_ops uses a record body whose callback fields are closures and whose
    simple top-level value fields are compile-time constants:
      { select_cpu: {|ctx| 0 }, name: "demo" }
    Top-level value fields currently accept int, bool, string, binary, and
    constant int-list values for fixed integer arrays.
    Nested record values are also supported for by-value substruct members.
    Nested list values are also supported for by-value array members, including
    arrays of records.
    Pointer-hop field initialization is still rejected.

Context parameter syntax (recommended):
  The closure can take a context parameter to access program context information:

  Universal tracing fields (all tracing attach types):
    {|ctx| $ctx.pid }     - Get process ID (thread ID)
    {|ctx| $ctx.tgid }    - Get thread group ID (process ID)
    {|ctx| $ctx.uid }     - Get user ID
    {|ctx| $ctx.gid }     - Get group ID
    {|ctx| $ctx.comm }    - Get process command name (first 16 bytes)
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.cgroup_id } - Get the current task cgroup ID

  Packet-context fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.cgroup_id } - Get the current task cgroup ID
    {|ctx| $ctx.packet_len } - Get packet length from xdp_md or __sk_buff
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type on skb-backed packet programs
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping on skb-backed packet programs
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order on skb-backed packet programs
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present on skb-backed packet programs
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI on skb-backed packet programs
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order on skb-backed packet programs
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array on skb-backed packet programs
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid on skb-backed packet programs
    {|ctx| $ctx.napi_id } - Get the skb napi_id on skb-backed packet programs
    {|ctx| $ctx.wire_len } - Get the skb wire_len on skb-backed packet programs
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs on skb-backed packet programs
    {|ctx| $ctx.gso_size } - Get the skb gso_size on skb-backed packet programs
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp on skb-backed packet programs
    {|ctx| $ctx.data }    - Get packet data pointer
    {|ctx| $ctx.data_end } - Get packet end pointer
    {|ctx| $ctx.ingress_ifindex } - Get ingress interface index
    {|ctx| $ctx.ifindex } - Get the XDP ingress ifindex or skb ifindex, depending on program type
    {|ctx| $ctx.tc_index } - Get the skb tc_index on skb-backed packet programs
    {|ctx| $ctx.hash }    - Get the skb hash on skb-backed packet programs
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie on supported socket-backed contexts
    {|ctx| $ctx.socket_uid } - Get the socket owner UID on socket_filter, tc, cgroup_skb, and sk_skb
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie on supported socket-backed contexts
    {|ctx| $ctx.mark }    - Get the skb mark on skb-backed packet programs
    {|ctx| $ctx.priority } - Get the skb priority on skb-backed packet programs
    {|ctx| ($ctx.data | get 0) } - Read the first packet byte with an auto-generated data_end guard
    {|ctx| $ctx.data.u16be.6 } - Read a big-endian 16-bit packet scalar (here: bytes 12..13)
    {|ctx| $ctx.data.eth.ethertype } - Read the Ethernet ethertype through a typed packet header view
    {|ctx| $ctx.data.eth.payload.ipv4.protocol } - Step past Ethernet or a single VLAN tag, then parse IPv4
    {|ctx| $ctx.data.eth.payload.ipv4.payload.tcp.payload.0 } - Step through variable IPv4/TCP headers and read the first TCP payload byte
    XDP-only extras:
    {|ctx| $ctx.rx_queue_index } - Get RX queue index
    {|ctx| $ctx.egress_ifindex } - Get egress interface index
    Note: XDP closures can return action aliases like `pass`, `drop`,
    `tx`, and `redirect`, and TC closures can return aliases like `ok`,
    `shot`, `pipe`, and `redirect`. cgroup_skb closures can return
    `allow` or `deny`. socket_filter closures can return `drop` / `deny`
    for `0`, or `pass` / `keep` / `allow` to snapshot the full packet by
    returning `ctx.packet_len`. `helper-call "bpf_redirect" IFINDEX FLAGS`
    is also type-checked on XDP/TC paths; XDP requires `FLAGS = 0`.
    `helper-call "bpf_redirect_peer" IFINDEX FLAGS` is modeled on
    `tc:...:ingress` and also requires `FLAGS = 0`.
    `helper-call "bpf_redirect_neigh" IFINDEX 0 0 0` is modeled on tc
    paths for the default neighbor-resolution form. Raw numeric return
    codes still work. Packet reads currently support scalar byte access
    through `get`/indexing, direct `u16be`/`u32be` cell-path scalar loads,
    and typed header views `eth`, `ipv4`, `udp`, and `tcp`. Those views also
    support `payload` stepping: `eth.payload` skips Ethernet and a single
    VLAN tag when present, `ipv4.payload` uses the runtime IHL, and
    `tcp.payload` uses the runtime data offset. IPv4/TCP options are skipped
    correctly by those payload steps, but deeper option parsing and stacked
    VLAN tags are still not modeled.

  perf_event targets:
    {|ctx| $ctx.cpu }    - Get current CPU ID for the sampled event
    {|ctx| $ctx.ktime }  - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.pid }    - Get current thread ID at sample time
    {|ctx| $ctx.comm }   - Get current command name at sample time
    Note: initial perf_event support covers software `cpu-clock`,
    `task-clock`, `context-switches`, `cpu-migrations`, `page-faults`,
    `minor-faults`, and `major-faults`, plus hardware `cpu-cycles`,
    `instructions`, `cache-references`, `cache-misses`,
    `branch-instructions`, `branch-misses`, `bus-cycles`,
    `stalled-cycles-frontend`, `stalled-cycles-backend`, and
    `ref-cpu-cycles` through specs like `perf_event:software:cpu-clock`
    or `perf_event:hardware:cpu-cycles`, with optional selectors `cpu=N`,
    `pid=N`, `period=N`, or `freq=N`. Omitting the sample policy defaults
    to `period=1000000`, and omitting `cpu=` attaches on all online CPUs.

  socket_filter targets:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get packet length from `skb->len`
    {|ctx| $ctx.data }    - Get packet data pointer
    {|ctx| $ctx.data_end } - Get packet end pointer
    {|ctx| $ctx.ingress_ifindex } - Get the skb ifindex
    Note: the initial socket_filter surface uses targets like
    `socket_filter:udp4:127.0.0.1:31337`, `socket_filter:udp6:[::1]:31337`,
    `socket_filter:tcp4:127.0.0.1:31337`, or `socket_filter:tcp6:[::1]:31337`,
    which create and hold open a bound socket while the program is attached.
    Return values are snapshot lengths: `0` drops the packet,
    positive values keep it, and aliases like `pass` / `keep` expand to
    `ctx.packet_len`.

  lirc_mode2 fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sample }  - Get the raw LIRC mode2 sample word
    {|ctx| $ctx.raw }     - Alias for the raw LIRC mode2 sample word
    {|ctx| $ctx.value }   - Get the low 24-bit LIRC payload value
    {|ctx| $ctx.mode }    - Get the high-byte LIRC event kind mask
    Note: lirc_mode2 targets use device paths such as `/dev/lirc0`. The
    initial surface is read-only and exposes the raw mode2 sample layout,
    where `ctx.mode` corresponds to constants like `LIRC_MODE2_PULSE` and
    `ctx.value` is the low 24-bit duration/frequency payload.

  lsm targets:
    {|ctx| $ctx.pid }    - Get current thread ID at hook time
    {|ctx| $ctx.comm }   - Get current command name at hook time
    {|ctx| $ctx.arg0 }   - Get the first BTF-typed LSM hook argument
    {|ctx| $ctx.arg0.f_flags } - Project through BTF-backed LSM hook arguments
    Note: initial LSM support uses `lsm:<hook_name>` targets such as
    `lsm:file_open`. Live loading requires a kernel with BPF LSM enabled;
    `--dry-run` is the safest way to validate object construction and BTF
    argument access on a development machine.

  cgroup_sysctl fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.write }   - Get whether the sysctl knob is being written (`1`) or read (`0`)
    {|ctx| $ctx.file_pos } - Get the current sysctl file position
    Note: cgroup_sysctl closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes.

  cgroup_sock fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include family, type, protocol, mark, priority, src_port, dst_port, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.sock_type } - Get socket type
    {|ctx| $ctx.protocol } - Get socket protocol
    {|ctx| $ctx.bound_dev_if } - Get the bound device ifindex
    {|ctx| $ctx.mark }    - Get the socket mark
    {|ctx| $ctx.priority } - Get the socket priority
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current socket context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    Note: cgroup_sock closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. Initial support covers `sock_create`,
    `sock_release`, `post_bind4`, and `post_bind6` with the scalar fields
    above. On `cgroup_sock`, socket-address projection fields through
    `ctx.sk` such as `ctx.sk.src_port` and `ctx.sk.dst_port` are only
    available on `post_bind4` and `post_bind6`.

  cgroup_device fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.access_type } - Get the encoded device access type
    {|ctx| $ctx.major }   - Get the requested device major number
    {|ctx| $ctx.minor }   - Get the requested device minor number
    Note: cgroup_device closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. `ctx.access_type` is the raw kernel encoding
    `(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*`.

  sock_ops fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.op }      - Get the sock_ops callback opcode
    {|ctx| $ctx.args }    - Get the four sock_ops callback argument words as a fixed array
    {|ctx| mut ctx = $ctx; $ctx.reply = 1; 1 } - Write the raw sock_ops reply word through ordinary assignment
    {|ctx| mut ctx = $ctx; $ctx.replylong.0 = 7; 1 } - Write a raw replylong u32 word through ordinary assignment
    {|ctx| $ctx.packet_len } - Get the packet length when packet metadata is available
    {|ctx| $ctx.data }    - Get the packet data pointer when packet metadata is available
    {|ctx| $ctx.data_end } - Get the packet end pointer when packet metadata is available
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current sock_ops context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current sock_ops context
    {|ctx| $ctx.is_fullsock } - Get whether the context has a full socket
    {|ctx| $ctx.snd_cwnd } - Get the current sending congestion window
    {|ctx| $ctx.srtt_us }  - Get the smoothed RTT in microseconds shifted by 3
    {|ctx| $ctx.cb_flags } - Get requested sock_ops callback flags
    {|ctx| $ctx.state }   - Get the current TCP state
    {|ctx| $ctx.rtt_min } - Get the minimum observed RTT in microseconds
    {|ctx| $ctx.snd_ssthresh } - Get the current slow-start threshold
    {|ctx| $ctx.rcv_nxt } - Get the next expected receive sequence number
    {|ctx| $ctx.snd_nxt } - Get the next send sequence number
    {|ctx| $ctx.snd_una } - Get the oldest unacknowledged send sequence number
    {|ctx| $ctx.mss_cache } - Get the current cached MSS
    {|ctx| $ctx.ecn_flags } - Get the current ECN/TCP option flags
    {|ctx| $ctx.rate_delivered } - Get the recent delivered-packet rate sample numerator
    {|ctx| $ctx.rate_interval_us } - Get the delivery-rate sampling interval in microseconds
    {|ctx| $ctx.packets_out } - Get the number of outstanding packets
    {|ctx| $ctx.retrans_out } - Get the number of retransmitted outstanding packets
    {|ctx| $ctx.total_retrans } - Get the total retransmission count
    {|ctx| $ctx.segs_in } - Get the total inbound segment count
    {|ctx| $ctx.data_segs_in } - Get the total inbound data-segment count
    {|ctx| $ctx.segs_out } - Get the total outbound segment count
    {|ctx| $ctx.data_segs_out } - Get the total outbound data-segment count
    {|ctx| $ctx.lost_out } - Get the current lost-out packet estimate
    {|ctx| $ctx.sacked_out } - Get the current SACKed-out packet estimate
    {|ctx| $ctx.sk_txhash } - Get the socket transmit hash
    {|ctx| $ctx.bytes_received } - Get the total received byte count
    {|ctx| $ctx.bytes_acked } - Get the total acknowledged byte count
    {|ctx| $ctx.skb_len } - Get the total packet length when packet metadata is available
    {|ctx| $ctx.skb_tcp_flags } - Get packet TCP flags when packet metadata is available
    {|ctx| $ctx.skb_hwtstamp } - Get packet hardware timestamp when packet metadata is available
    Note: sock_ops uses raw integer return codes. Observation-only examples
    should return `1`. `ctx.reply` and `ctx.replylong.<0-3>` are writable raw
    `u32` words after shadowing the immutable closure parameter as mutable, for
    example `mut ctx = $ctx; $ctx.reply = 1`. IPv6 addresses are
    exposed as fixed arrays of four host-order u32 words, for example
    `($ctx.remote_ip6 | get 3)`. `ctx.args` uses the same fixed-array model,
    for example `($ctx.args | get 0)`. `ctx.data` / `ctx.data_end` use the
    same guarded packet access model as XDP and tc when packet metadata is
    available, so forms like `($ctx.data | get 0)` are valid on packet-aware
    sock_ops callbacks.

  sk_msg fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total message size in bytes
    {|ctx| $ctx.data }    - Get the packet/message data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet/message access
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include family, type, protocol, mark, priority, src_port, dst_port, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current sk_msg context
    Note: sk_msg programs attach to a pinned sockmap or sockhash path such as
    `/sys/fs/bpf/demo_sockmap`. Initial sk_msg support is read-only and uses
    raw integer verdict codes; observation-only examples should return `pass`
    or `1`. `ctx.data` / `ctx.data_end` use the same guarded packet access
    model as XDP and tc, so forms like `($ctx.data | get 0)` are valid. IPv6
    addresses are exposed as fixed arrays of four host-order u32 words, for
    example `($ctx.remote_ip6 | get 3)`. Modeled socket-message helpers are
    also available through the ordinary helper surface, for example
    `helper-call "bpf_msg_apply_bytes" $ctx 8` or
    `helper-call "bpf_msg_cork_bytes" $ctx 8`, plus range/data reshaping
    helpers such as `helper-call "bpf_msg_pull_data" $ctx 0 8 0` and
    `helper-call "bpf_msg_push_data" $ctx 0 8 0` or
    `helper-call "bpf_msg_pop_data" $ctx 0 8 0`. Socket-pointer helpers are
    also available on `ctx.sk` after a null check, for example
    `if $ctx.sk != 0 { helper-call "bpf_sk_cgroup_id" $ctx.sk }`.

  sk_skb fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total packet length in bytes
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid
    {|ctx| $ctx.napi_id } - Get the skb napi_id
    {|ctx| $ctx.wire_len } - Get the skb wire_len
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs
    {|ctx| $ctx.gso_size } - Get the skb gso_size
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp
    {|ctx| $ctx.data }    - Get the packet data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet access
    {|ctx| $ctx.ingress_ifindex } - Get the ingress interface index
    {|ctx| $ctx.ifindex } - Get the skb ifindex
    {|ctx| $ctx.tc_index } - Get the skb tc_index
    {|ctx| $ctx.hash }    - Get the skb hash
    {|ctx| $ctx.mark }    - Get the skb mark
    {|ctx| $ctx.priority } - Get the skb priority
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    Note: initial sk_skb support targets pinned sockmap or sockhash paths such
    as `/sys/fs/bpf/demo_sockmap` and emits `sk_skb/stream_verdict` programs.
    It uses raw verdict codes but supports `pass` / `drop` aliases, and
    `ctx.data` / `ctx.data_end` use the same guarded packet access model as
    tc and cgroup_skb. IPv4 addresses and the remote port are normalized to
    host byte order, and IPv6 addresses are exposed as four host-order u32
    words for ordinary Nushell indexing.

  sk_skb_parser fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get total packet length in bytes
    {|ctx| $ctx.pkt_type } - Get the skb pkt_type
    {|ctx| $ctx.queue_mapping } - Get the skb queue_mapping
    {|ctx| $ctx.eth_protocol } - Get the skb protocol / ethertype in host byte order
    {|ctx| $ctx.vlan_present } - Get whether skb VLAN metadata is present
    {|ctx| $ctx.vlan_tci } - Get the skb VLAN TCI
    {|ctx| $ctx.vlan_proto } - Get the skb VLAN ethertype in host byte order
    {|ctx| $ctx.cb } - Get the skb cb words as a fixed array
    {|ctx| $ctx.tc_classid } - Get the skb tc_classid
    {|ctx| $ctx.napi_id } - Get the skb napi_id
    {|ctx| $ctx.wire_len } - Get the skb wire_len
    {|ctx| $ctx.gso_segs } - Get the skb gso_segs
    {|ctx| $ctx.gso_size } - Get the skb gso_size
    {|ctx| $ctx.hwtstamp } - Get the skb hardware timestamp
    {|ctx| $ctx.data }    - Get the packet data pointer
    {|ctx| $ctx.data_end } - Get the end pointer for packet access
    {|ctx| $ctx.ingress_ifindex } - Get the ingress interface index
    {|ctx| $ctx.ifindex } - Get the skb ifindex
    {|ctx| $ctx.tc_index } - Get the skb tc_index
    {|ctx| $ctx.hash }    - Get the skb hash
    {|ctx| $ctx.mark }    - Get the skb mark
    {|ctx| $ctx.priority } - Get the skb priority
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    Note: initial sk_skb_parser support targets pinned sockmap or sockhash
    paths such as `/sys/fs/bpf/demo_sockmap` and emits `sk_skb/stream_parser`
    programs. It uses raw integer parser returns rather than verdict aliases,
    so ordinary examples should return an integer such as `0` or `$ctx.packet_len`.
    IPv4 addresses and the remote port are normalized to host byte order, and
    IPv6 addresses are exposed as four host-order u32 words for ordinary
    Nushell indexing.

  cgroup_sockopt fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.family } - Project the current socket through a typed bpf_sock pointer (fields include family, type, protocol, mark, priority, src_port, dst_port, state, and rx_queue_mapping)
    {|ctx| $ctx.level }   - Get the socket-option level
    {|ctx| $ctx.optname } - Get the socket-option name
    {|ctx| $ctx.optlen }  - Get the socket-option length
    {|ctx| $ctx.optval }  - Get the kernel pointer to the sockopt buffer
    {|ctx| $ctx.optval_end } - Get the end pointer for the sockopt buffer
    {|ctx| $ctx.sockopt_retval } - Get the getsockopt return value on `cgroup_sockopt:get`
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    Note: cgroup_sockopt closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. `optval` / `optval_end` are surfaced as kernel
    pointers, so existing pointer reads like `($ctx.optval | get 0)` or
    `read-kernel-str` can inspect buffer contents. `ctx.sk` uses the same
    typed `bpf_sock` projection model as `cgroup_sock`, `sk_lookup`, and
    `sk_msg`. On `cgroup_sockopt:get`, writable return overrides use ordinary
    assignment through a mutable local alias such as `mut ctx = $ctx;
    $ctx.sockopt_retval = 0`.

  cgroup_sock_addr fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.socket_cookie } - Get the stable socket cookie for the current socket context
    {|ctx| $ctx.netns_cookie } - Get the stable network-namespace cookie for the current socket context
    {|ctx| $ctx.user_family } - Get userspace-requested socket family
    {|ctx| $ctx.user_ip4 } - Get the IPv4 destination/source address in host byte order on *4 hooks
    {|ctx| $ctx.user_ip6 } - Get the IPv6 destination/source address as four host-order u32 words on *6 hooks
    {|ctx| $ctx.user_port } - Get the requested port in host byte order
    {|ctx| $ctx.family }  - Get kernel socket family
    {|ctx| $ctx.sock_type } - Get socket type
    {|ctx| $ctx.protocol } - Get socket protocol
    {|ctx| $ctx.msg_src_ip4 } - Get the IPv4 source address in host byte order on sendmsg4/recvmsg4
    {|ctx| $ctx.msg_src_ip6 } - Get the IPv6 source address as four host-order u32 words on sendmsg6/recvmsg6
    Note: cgroup_sock_addr closures can return `allow` or `deny` instead of
    raw `1`/`0` result codes. This initial slice still exposes IPv6
    addresses as fixed arrays of four u32 words rather than a higher-level
    address type.

  sk_lookup fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.sk.bound_dev_if } - Project the selected socket through a typed bpf_sock pointer (fields include family, type, protocol, mark, priority, src_port, dst_port, state, and rx_queue_mapping)
    {|ctx| $ctx.family }  - Get socket family
    {|ctx| $ctx.protocol } - Get IP protocol
    {|ctx| $ctx.cookie }  - Get the socket lookup cookie
    {|ctx| $ctx.remote_ip4 } - Get the remote IPv4 address in host byte order
    {|ctx| $ctx.remote_ip6 } - Get the remote IPv6 address as four host-order u32 words
    {|ctx| $ctx.remote_port } - Get the remote port in host byte order
    {|ctx| $ctx.local_ip4 } - Get the local IPv4 address in host byte order
    {|ctx| $ctx.local_ip6 } - Get the local IPv6 address as four host-order u32 words
    {|ctx| $ctx.local_port } - Get the local port in host byte order
    {|ctx| $ctx.ingress_ifindex } - Get the arriving ingress interface index
    Note: sk_lookup closures can return `pass` or `drop` instead of raw
    `1`/`0` result codes. `allow` / `deny` aliases also work. IPv6
    addresses are exposed as fixed arrays of four host-order u32 words, so
    normal Nushell indexing works, for example `($ctx.remote_ip6 | get 3)`.

  Function fields:
    {|ctx| $ctx.arg0 }    - Get function argument 0
    {|ctx| $ctx.arg1 }    - Get function argument 1
    {|ctx| $ctx.retval }  - Get return value (kretprobe/uretprobe/fexit)

    Note: kprobe/uprobe expose pt_regs-style ctx.arg0-5. fentry/fexit/tp_btf use
    kernel BTF. Scalar/pointer trampoline args and returns work directly.
    By-value trampoline args and pointer-backed trampoline args/returns
    support scalar/pointer field projection like ctx.arg0.some_field.
    Pointer-backed projections use null-guarded bpf_probe_read_{kernel,user}
    and can cross intermediate and repeated pointer hops like ctx.arg0.foo.bar
    or ctx.arg0.fdt.fd.f_inode.i_ino. Fixed-size arrays can be indexed with
    numeric path segments like ctx.arg0.comm.0, and pointer-backed sequences
    can now also be indexed with constant numeric segments such as
    `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd;
    $fd.0.f_inode.i_ino`. Numeric `get` now supports the same typed
    kernel/user pointer traversal through a register value, and also supports
    stack-backed fixed arrays such as `let idx = ($ctx.pid mod 2);
    ($ctx.arg0.comm | get $idx)`. Pointer-valued examples include
    `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
    Bounded ascending `for` loops over static integer ranges now lower to
    verifier-safe loops, so `for i in 0..0 { ... get $i ... }` works.
    Bounded arithmetic on those indices, such as
    `let j = (($i + 1) mod 2)`, is preserved too. The same range tracking
    now works for typed unsigned runtime fields such as
    `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing
    also works for both bound and repeated direct paths, for example
    `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1);
    ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx =
    ($ctx.arg0.fdt.max_fds - 1); ... }`. Descending ranges are still
    rejected. Typed BTF bitfields are also projected through those same
    paths, including after numeric `get`, for example `let idx =
    ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx);
    $clamp.value`.
    Terminal array leaves and unsupported aggregate leaves are exposed as
    stack-backed byte buffers. Representable terminal struct leaves keep their
    field layouts, including BTF bitfield members, for count/counter decoding,
    and single-value emit can now stream those struct leaves as records.
    Nested array/record fields inside emitted values also decode recursively
    when the compiler can preserve their layouts. emit still preserves
    unsupported aggregate layouts as binary payloads, and count can use them
    as byte-buffer keys. ebpf counters decodes those keys using any schema the
    compiler still has: arrays and typed structs can surface as strings,
    lists, or records; opaque aggregate layouts still display as binary. Plain
    trampoline ctx.argN and ctx.retval loads also preserve their typed pointer
    or aggregate layouts
    across bindings, for example `let files = $ctx.arg0;
    $files.fdt.fd.f_inode.i_ino` or `let inode = $ctx.arg0.f_inode;
    $inode.i_sb.s_flags`. Kernel-BTF-backed contexts also expose named
    parameter names through `ctx.arg.<name>`, for example
    `ctx.arg.prev_cpu`, `ctx.arg.p.pid`, or `ctx.arg.file.f_flags`.
    16-byte byte-array/string keys such as ctx.arg0.comm continue to display
    as strings.
    Aggregate fexit returns still depend on kernel trampoline support;
    some kernels reject struct returns entirely.

  Tracepoint fields:
    Access fields specific to each tracepoint. Fields are read from tracefs.
    Example for syscalls/sys_enter_openat:
      {|ctx| $ctx.dfd }      - Directory file descriptor
      {|ctx| $ctx.filename } - Pointer to filename string
      {|ctx| $ctx.flags }    - Open flags

Output commands:
  emit              - Send value to userspace via ring buffer
  read-str          - Read string from userspace memory pointer
  read-kernel-str   - Read string from kernel memory (rare)
  global-define     - Declare a named compiler-managed program global
  global-get        - Load a named compiler-managed program global
  global-set        - Store the pipeline input into a named compiler-managed program global

Globals:
  Prefer leading annotated `mut` bindings for small private program state:
    {|ctx| mut state: int = 0; $state = ($state + 1); $state | count }
  The initializer must currently be a compile-time constant.

Aggregation commands:
  count             - Count occurrences by key
  histogram         - Add value to log2 histogram

Timing commands:
  start-timer       - Record timestamp (use with --pin for cross-probe timing)
  stop-timer        - Calculate elapsed nanoseconds since start-timer

Advanced commands:
  helper-call       - Call a modeled BPF helper by name
  kfunc-call        - Call a typed kernel kfunc by name (optional --btf-id)
  map-push          - Push into a named queue or stack map (--kind queue|stack)

Flags:
  --stream (-s)     Stream events in real-time. The command blocks and yields
                    events as they occur. Use Ctrl-C to stop, or pipe to
                    `first N` to capture a fixed number of events.

  --dry-run (-n)    Generate eBPF bytecode without loading into kernel.
                    Returns the compiled ELF binary. Useful for:
                    - Debugging compilation issues
                    - Inspecting generated bytecode (pipe to `save prog.o`)
                    - Validating closures before deployment

  --unsafe-struct-ops
                    Allow live loading of high-risk struct_ops families such as
                    `sched_ext_ops`. Prefer `--dry-run` on the host and use a VM
                    or disposable environment before enabling this.

  --pin (-p) GROUP  Pin maps to /sys/fs/bpf/nushell/GROUP/ for sharing between
                    probes. Essential for timing measurements where kprobe and
                    kretprobe need to share the timestamp map:

                    let entry = ebpf attach --pin timing 'kprobe:vfs_read' {
                        start-timer
                    }
                    let exit = ebpf attach --pin timing 'kretprobe:vfs_read' {
                        stop-timer | histogram
                    }

                    Maps are automatically unpinned when all probes detach.

Limits:
  - eBPF stack: 512 bytes (complex closures may overflow)
  - String reads: 128 bytes max (longer strings truncated)
  - Map entries: 10,240 max per map (count, histogram, timers)
  - Ring buffer: 256 KB (high event rates may drop events)
  - Stack traces: 127 frames max

Discovering tracepoints:
  ls /sys/kernel/tracing/events/              # List categories
  ls /sys/kernel/tracing/events/syscalls/     # List syscall tracepoints
  cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format  # View fields

Requirements:
  - Linux kernel 4.18+ for the basic tracing paths
  - Linux kernel 5.5+ with /sys/kernel/btf/vmlinux for fentry/fexit
  - CAP_BPF + CAP_PERFMON capabilities, or root access
  - Run `ebpf setup` to configure capabilities"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf attach")
            .input_output_types(vec![
                (Type::Nothing, Type::Int),     // Returns probe ID (default)
                (Type::Nothing, Type::Binary),  // Returns ELF with --dry-run
                (Type::Nothing, Type::table()), // Streams events with --stream
            ])
            .required(
                "probe",
                SyntaxShape::String,
                "The probe point (e.g., 'kprobe:sys_clone', 'xdp:lo', 'socket_filter:udp4:127.0.0.1:31337', 'socket_filter:udp6:[::1]:31337', 'socket_filter:tcp4:127.0.0.1:31337', 'socket_filter:tcp6:[::1]:31337', 'cgroup_skb:/sys/fs/cgroup:egress', 'cgroup_device:/sys/fs/cgroup', 'cgroup_sock:/sys/fs/cgroup:sock_create', 'sock_ops:/sys/fs/cgroup', 'sk_msg:/sys/fs/bpf/demo_sockmap', 'sk_skb:/sys/fs/bpf/demo_sockmap', 'sk_skb_parser:/sys/fs/bpf/demo_sockmap', 'cgroup_sysctl:/sys/fs/cgroup', 'cgroup_sockopt:/sys/fs/cgroup:get', 'cgroup_sock_addr:/sys/fs/cgroup:connect4', 'sk_lookup:/proc/self/ns/net', or 'lirc_mode2:/dev/lirc0').",
            )
            .required(
                "body",
                SyntaxShape::Any,
                "Closure body for ordinary attach types, or a record of constant fields and optional callback closures for struct_ops.",
            )
            .switch(
                "stream",
                "Stream events directly (Ctrl-C to stop)",
                Some('s'),
            )
            .switch(
                "dry-run",
                "Generate bytecode but don't load into kernel",
                Some('n'),
            )
            .switch(
                "unsafe-struct-ops",
                "Allow live loading of high-risk struct_ops families such as sched_ext_ops",
                None,
            )
            .named(
                "pin",
                SyntaxShape::String,
                "Pin maps to share between probes (e.g., --pin mygroup)",
                Some('p'),
            )
            .category(Category::Experimental)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec![
            "bpf",
            "kernel",
            "trace",
            "probe",
            "kprobe",
            "fentry",
            "fexit",
            "tp_btf",
            "tracepoint",
            "uprobe",
            "uretprobe",
            "userspace",
            "perf_event",
            "socket_filter",
            "xdp",
            "tc",
            "cgroup_skb",
            "cgroup_device",
            "cgroup_sock",
            "sock_ops",
            "sk_msg",
            "sk_skb",
            "sk_skb_parser",
            "cgroup_sysctl",
            "cgroup_sockopt",
            "cgroup_sock_addr",
            "sk_lookup",
            "lirc_mode2",
            "struct_ops",
        ]
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }",
                description: "Stream events from sys_clone (Ctrl-C to stop)",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10",
                description: "Capture first 10 sys_read events",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.filename | emit }",
                description: "Stream filenames from openat syscalls using tracepoint",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fentry:do_sys_openat2' {|ctx| if $ctx.arg1 != 0 { $ctx.arg1 | read-str --max-len 64 | emit } } | first 5",
                description: "Capture the first 5 fentry filenames using BTF-backed trampoline args",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fexit:ksys_read' {|ctx| $ctx.retval | emit } | first 5",
                description: "Capture the first 5 fexit return values using BTF-backed trampolines",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'tp_btf:sys_enter' {|ctx| $ctx.arg1.orig_ax | count; 0 }",
                description: "Dry-run a BTF-enabled raw tracepoint using typed trampoline args",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'lsm:file_open' {|ctx| $ctx.arg0.f_flags | count; 0 }",
                description: "Dry-run an LSM file_open hook using BTF-backed hook arguments",
                result: None,
            },
            Example {
                example: "ebpf attach 'perf_event:software:cpu-clock:period=100000' {|ctx| $ctx.cpu | count; 0 }",
                description: "Count software cpu-clock samples by CPU",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:udp4:127.0.0.1:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback UDP packet lengths on a bound socket_filter receive socket",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:udp6:[::1]:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback UDPv6 packet lengths on a bound socket_filter receive socket",
                result: None,
            },
            Example {
                example: "ebpf attach 'socket_filter:tcp4:127.0.0.1:31337' {|ctx| $ctx.packet_len | count; 'pass' }",
                description: "Count loopback TCP packet lengths on a bound socket_filter listener",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_skb:/sys/fs/cgroup:egress' {|ctx| $ctx.packet_len | count; 'allow' }",
                description: "Count packet lengths on cgroup egress traffic",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_device:/sys/fs/cgroup' {|ctx| $ctx.major | count; 'allow' }",
                description: "Count device major numbers requested by processes in a cgroup",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock:/sys/fs/cgroup:sock_create' {|ctx| $ctx.family | count; 'allow' }",
                description: "Count socket families at cgroup socket-create time",
                result: None,
            },
            Example {
                example: "ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx.op | count; 1 }",
                description: "Count sock_ops callback opcodes on TCP socket events in a cgroup",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_msg:/sys/fs/bpf/demo_sockmap' {|ctx| ($ctx.data | get 0) | count; 'pass' }",
                description: "Count first-byte observations on a pinned sockmap or sockhash sk_msg verdict hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_skb:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 'pass' }",
                description: "Count packet lengths on a pinned sockmap or sockhash sk_skb stream-verdict hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_skb_parser:/sys/fs/bpf/demo_sockmap' {|ctx| $ctx.local_port | count; 0 }",
                description: "Count packet lengths on a pinned sockmap or sockhash sk_skb stream-parser hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sysctl:/sys/fs/cgroup' {|ctx| $ctx.write | count; 'allow' }",
                description: "Count sysctl reads versus writes on a cgroup sysctl hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sockopt:/sys/fs/cgroup:get' {|ctx| $ctx.optname | count; 'allow' }",
                description: "Count getsockopt option names on a cgroup socket-option hook",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect4' {|ctx| $ctx.user_port | count; 'allow' }",
                description: "Count requested ports on cgroup connect4 hooks",
                result: None,
            },
            Example {
                example: "ebpf attach 'cgroup_sock_addr:/sys/fs/cgroup:connect6' {|ctx| ($ctx.user_ip6 | get 3) | count; 'allow' }",
                description: "Count the last host-order IPv6 address word on cgroup connect6 hooks",
                result: None,
            },
            Example {
                example: "ebpf attach 'sk_lookup:/proc/self/ns/net' {|ctx| $ctx.local_port | count; 'pass' }",
                description: "Count local ports seen by socket lookup in the current network namespace",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'lirc_mode2:/dev/lirc0' {|ctx| $ctx.value | count; 0 }",
                description: "Dry-run a lirc_mode2 decoder using the raw mode2 sample context",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'struct_ops:sched_ext_ops' { name: 'nu_demo' }",
                description: "Build a struct_ops object from constant value fields and optional callback closures without loading it",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'struct_ops:sched_ext_ops' { name: 'nu_demo', select_cpu: {|ctx| let p = $ctx.arg.p; let prev = $ctx.arg.prev_cpu; let wake = $ctx.arg.wake_flags; let mask = (kfunc-call \"scx_bpf_get_online_cpumask\"); if $mask != 0 { let cpu = (kfunc-call \"scx_bpf_select_cpu_and\" $p $prev $wake $mask 0); kfunc-call \"scx_bpf_put_cpumask\" $mask; $cpu } else { $prev } } }",
                description: "Dry-run a sched_ext select_cpu callback with the safe cpumask acquire/use/release pattern",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'kprobe:ksys_read' {|| helper-call 'bpf_get_current_pid_tgid' | count }",
                description: "Dry-run a closure that calls a modeled BPF helper by name",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_attach(engine, call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_attach(
    engine: &EngineInterface,
    call: &EvaluatedCall,
) -> Result<PipelineData, LabeledError> {
    use crate::loader::{LoadError, ProgramSpec, get_state, parse_program_spec};

    let probe_spec: String = call.req(0)?;
    let body: Value = call.req(1)?;
    let dry_run = call.has_flag("dry-run")?;
    let stream = call.has_flag("stream")?;
    let allow_unsafe_struct_ops = call.has_flag("unsafe-struct-ops")?;
    let pin_group: Option<String> = call.get_flag("pin")?;

    // Parse the probe specification (includes validation)
    let program_spec = parse_program_spec(&probe_spec).map_err(|e| match &e {
        crate::loader::LoadError::FunctionNotFound { name, suggestions } => {
            let help = if suggestions.is_empty() {
                format!("Check the function name. Use 'sudo cat /sys/kernel/tracing/available_filter_functions | grep {name}' to find available functions.")
            } else {
                format!("Did you mean: {}?", suggestions.join(", "))
            };
            LabeledError::new(format!("Kernel function '{}' not found", name))
                .with_label("This function is not available for probing", call.head)
                .with_help(help)
        }
        crate::loader::LoadError::TracepointNotFound { category, name } => {
            LabeledError::new(format!("Tracepoint '{}/{}' not found", category, name))
                .with_label("This tracepoint does not exist", call.head)
                .with_help(format!(
                    "Use 'sudo ls /sys/kernel/tracing/events/{}' to see available tracepoints",
                    category
                ))
        }
        crate::loader::LoadError::UnsupportedTrampolineTarget {
            probe_type,
            target,
            reason,
        } => {
            let mut err =
                LabeledError::new(format!("Unsupported {} target '{}'", probe_type, target))
                    .with_label(reason.clone(), call.head);
            if let Some(help) = match probe_type.as_str() {
                "fentry" | "fexit" => Some(
                    "fentry/fexit require kernel BTF and a trampoline-compatible target signature. Try a scalar/pointer-return target or use kprobe/kretprobe for broader coverage",
                ),
                _ => None,
            } {
                err = err.with_help(help);
            }
            err
        }
        crate::loader::LoadError::NeedsSudo => {
            LabeledError::new("Elevated privileges required")
                .with_label("eBPF operations require root or CAP_BPF capability", call.head)
                .with_help("Run nushell with sudo: sudo nu")
        }
        _ => LabeledError::new("Invalid probe specification")
            .with_label(e.to_string(), call.head)
            .with_help("Use format like 'kprobe:sys_clone' or 'tracepoint:syscalls/sys_enter_read'"),
    })?;

    let object = match &program_spec {
        ProgramSpec::StructOps { value_type_name } => {
            if stream {
                return Err(LabeledError::new("Streaming is not supported for struct_ops objects")
                    .with_label(
                        "struct_ops objects currently register callbacks but cannot stream events",
                        call.head,
                    ));
            }
            if pin_group.is_some() {
                return Err(LabeledError::new(
                    "Pinned map sharing is not supported for struct_ops",
                )
                .with_label("struct_ops objects currently cannot use --pin", call.head));
            }
            validate_struct_ops_attach_safety(
                value_type_name,
                dry_run,
                allow_unsafe_struct_ops,
                call.head,
            )?;
            let record = body.into_record().map_err(|e| {
                LabeledError::new("Invalid struct_ops body")
                    .with_label(e.to_string(), call.head)
                    .with_help(
                        "Use a record whose callback fields are closures, for example { select_cpu: {|ctx| 0 } }",
                    )
            })?;
            compile_struct_ops_object(engine, value_type_name, &record, call.head)?
        }
        _ => {
            let closure = value_to_spanned_closure(body, call.head)?;
            let prog_type = program_spec.program_type();
            let target = program_spec.target_string();
            let probe_context = ProbeContext::new(prog_type, &target);
            let compiled = compile_closure_with_context(
                engine,
                &closure,
                &probe_context,
                pin_group.as_deref(),
                call.head,
            )?;
            let mut program = compiled.compile_result.into_program(
                prog_type,
                &target,
                "nushell_ebpf",
                compiled.generic_map_value_types,
                compiled.generic_map_value_semantics,
            );
            if pin_group.is_some() {
                program = program.with_pinning();
            }
            EbpfObject::single_program(program)
        }
    };

    let state = get_state();

    if dry_run {
        let elf = object.to_elf().map_err(|e| {
            LabeledError::new("Failed to generate ELF").with_label(e.to_string(), call.head)
        })?;
        return Ok(PipelineData::Value(Value::binary(elf, call.head), None));
    }

    // Load and attach
    let probe_id = state
        .attach_with_pin(&object, pin_group.as_deref())
        .map_err(|e| {
            let help = match &e {
                LoadError::PermissionDenied => {
                    Some("Try running with sudo or grant CAP_BPF capability")
                }
                _ => None,
            };
            let mut err = LabeledError::new("Failed to attach eBPF probe")
                .with_label(e.to_string(), call.head);
            if let Some(h) = help {
                err = err.with_help(h);
            }
            err
        })?;

    if stream {
        // For streaming, we return values one at a time
        // In a plugin, we can use PipelineData with an iterator
        let span = call.head;
        let iter = EventStreamIterator::new(probe_id, span);
        Ok(PipelineData::ListStream(
            nu_protocol::ListStream::new(iter, span, engine.signals().clone()),
            None,
        ))
    } else {
        Ok(PipelineData::Value(
            Value::int(probe_id as i64, call.head),
            None,
        ))
    }
}

/// Iterator that streams events from an attached eBPF probe
#[cfg(target_os = "linux")]
struct EventStreamIterator {
    probe_id: u32,
    span: Span,
    pending_events: std::collections::VecDeque<Value>,
}

#[cfg(target_os = "linux")]
impl EventStreamIterator {
    fn new(probe_id: u32, span: Span) -> Self {
        Self {
            probe_id,
            span,
            pending_events: std::collections::VecDeque::new(),
        }
    }

    fn poll_batch(&mut self) {
        use crate::loader::{BpfEventData, get_state};
        use std::time::Duration;

        let state = get_state();
        if let Ok(events) = state.poll_events(self.probe_id, Duration::from_millis(100)) {
            for e in events {
                let value = match e.data {
                    BpfEventData::Record(fields) => {
                        let mut rec = Record::new();
                        for (name, value) in fields {
                            let val = Self::field_value_to_nu_value(value, self.span);
                            rec.push(name, val);
                        }
                        rec.push("cpu", Value::int(e.cpu as i64, self.span));
                        Value::record(rec, self.span)
                    }
                    _ => {
                        let value = match e.data {
                            BpfEventData::Int(v) => Value::int(v, self.span),
                            BpfEventData::String(s) => Value::string(s, self.span),
                            BpfEventData::Bytes(b) => Value::binary(b, self.span),
                            BpfEventData::Record(_) => unreachable!(),
                        };
                        Value::record(
                            record! {
                                "value" => value,
                                "cpu" => Value::int(e.cpu as i64, self.span),
                            },
                            self.span,
                        )
                    }
                };
                self.pending_events.push_back(value);
            }
        }
    }

    fn field_value_to_nu_value(value: crate::loader::BpfFieldValue, span: Span) -> Value {
        match value {
            crate::loader::BpfFieldValue::Int(v) => Value::int(v, span),
            crate::loader::BpfFieldValue::String(s) => Value::string(s, span),
            crate::loader::BpfFieldValue::Bytes(b) => Value::binary(b, span),
            crate::loader::BpfFieldValue::Array(values) => Value::list(
                values
                    .into_iter()
                    .map(|value| Self::field_value_to_nu_value(value, span))
                    .collect(),
                span,
            ),
            crate::loader::BpfFieldValue::Record(fields) => {
                let mut rec = Record::new();
                for (name, value) in fields {
                    rec.push(name, Self::field_value_to_nu_value(value, span));
                }
                Value::record(rec, span)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Iterator for EventStreamIterator {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Return any pending events first
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }

        // Keep polling until we get an event
        // This is a blocking iterator - it will keep trying until events arrive
        loop {
            self.poll_batch();
            if let Some(event) = self.pending_events.pop_front() {
                return Some(event);
            }
            // Small sleep to avoid busy-waiting
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for EventStreamIterator {
    fn drop(&mut self) {
        use crate::loader::get_state;
        let _ = get_state().detach(self.probe_id);
    }
}

#[cfg(test)]
mod tests;
