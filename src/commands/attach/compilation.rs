use std::collections::{HashMap, HashSet};

use nu_cmd_lang::create_default_context;
use nu_parser::parse;
use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::ast::{CellPath, Expr, ExternalArgument, ListItem, RecordItem};
use nu_protocol::casing::Casing;
use nu_protocol::engine::{Closure, StateWorkingSet};
use nu_protocol::eval_const::{eval_constant, eval_constant_with_input};
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{
    BlockId, DeclId, FromValue, IntoSpanned, LabeledError, PipelineData, Record, Signature, Span,
    Spanned, Type, Value,
};

use super::struct_ops::{
    StructOpsTopLevelFieldKind, apply_struct_ops_value_field, default_struct_ops_object_name,
    sanitize_struct_ops_component, validate_required_struct_ops_callbacks,
    validate_required_struct_ops_value_fields, validate_struct_ops_callback_kfunc_requirements,
    validate_struct_ops_top_level_field_kind,
};
use crate::compiler::mir::{MirFunction, MirInst, MirProgram};
use crate::compiler::{
    EbpfObject, MapRef, MirCompileResult, MirType, ProbeContext, ProgramIntrinsic,
    StructOpsObjectSpec, UserFunctionSig, UserParam, UserParamKind,
    compile_mir_to_ebpf_with_hints_and_globals, hir::AnnotatedMutGlobal, hir::HirFunction,
    hir::HirProgram, hir::HirStmt, hir::supports_constant_value, hir_type_infer, infer_ctx_param,
    lower_hir_to_mir_with_hints_maps_and_semantics, lower_ir_to_hir,
    passes::optimize_with_ssa_hints,
};
use crate::kernel_btf::TrampolineFieldSelector;

/// Common Nushell commands used in eBPF closures.
const NU_CLOSURE_COMMANDS: &[&str] = &[
    "where", "each", "skip", "first", "last", "get", "select", "reject", "default", "if", "match",
];

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

pub(super) fn extract_decl_names_from_formatted_instructions(
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
            continue;
        }

        let (nested_ir, nested_decl_names) = fetch_block_ir(engine, block_id, span)?;
        decl_names.extend(nested_decl_names);

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

pub(super) struct CompiledClosureArtifacts {
    pub(super) compile_result: MirCompileResult,
    pub(super) generic_map_value_types: HashMap<MapRef, MirType>,
    pub(super) generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
    pub(super) used_kfuncs: HashSet<String>,
}

pub(super) fn value_to_spanned_closure(
    value: Value,
    span: Span,
) -> Result<Spanned<Closure>, LabeledError> {
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
    eval_supported_constant_value_with_input(working_set, expr, None)
}

fn eval_supported_constant_value_with_input(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    input: Option<Value>,
) -> Result<Value, LabeledError> {
    if let Expr::GlobPattern(token, _) = &expr.expr {
        return Ok(eval_supported_constant_bare_token(token, expr.span));
    }

    let pipeline_input = input.clone().map_or_else(PipelineData::empty, |value| {
        PipelineData::value(value, None)
    });
    if let Ok(data) = eval_constant_with_input(working_set, expr, pipeline_input) {
        return data.into_value(expr.span).map_err(|e| {
            LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(e.to_string(), expr.span)
        });
    }

    match &expr.expr {
        Expr::Keyword(kw) => eval_supported_constant_value_with_input(working_set, &kw.expr, input),
        Expr::Subexpression(block_id) | Expr::Block(block_id) => {
            let block = working_set.get_block(*block_id);
            eval_supported_constant_block(working_set, block, input, expr.span)
        }
        Expr::FullCellPath(full_cell_path) => {
            let value =
                eval_supported_constant_value_with_input(working_set, &full_cell_path.head, input)?;
            value
                .follow_cell_path(&full_cell_path.tail)
                .map(|projected| projected.into_owned())
                .map_err(|e| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(e.to_string(), expr.span)
                })
        }
        Expr::Record(items) => {
            let mut record = Record::new();
            for item in items {
                match item {
                    RecordItem::Pair(key_expr, value_expr) => {
                        let key = constant_record_key(working_set, key_expr)?;
                        let value =
                            eval_supported_constant_value_with_input(working_set, value_expr, None)?;
                        record.push(key, value);
                    }
                    RecordItem::Spread(_, spread_expr) => {
                        let value =
                            eval_supported_constant_value_with_input(working_set, spread_expr, None)?;
                        let Value::Record {
                            val: spread_record, ..
                        } = value
                        else {
                            return Err(
                                LabeledError::new(
                                    "Unsupported annotated mutable global initializer",
                                )
                                .with_label(
                                    "record spreads in compile-time global initializers must evaluate to records",
                                    spread_expr.span,
                                ),
                            );
                        };
                        for (key, value) in spread_record.iter() {
                            record.insert(key, value.clone());
                        }
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
                        values.push(eval_supported_constant_value_with_input(
                            working_set,
                            item_expr,
                            None,
                        )?);
                    }
                    ListItem::Spread(_, spread_expr) => {
                        let value = eval_supported_constant_value_with_input(
                            working_set,
                            spread_expr,
                            None,
                        )?;
                        let Value::List {
                            vals: spread_values, ..
                        } = value
                        else {
                            return Err(
                                LabeledError::new(
                                    "Unsupported annotated mutable global initializer",
                                )
                                .with_label(
                                    "list spreads in compile-time global initializers must evaluate to lists",
                                    spread_expr.span,
                                ),
                            );
                        };
                        values.extend(spread_values);
                    }
                }
            }
            Ok(Value::list(values, expr.span))
        }
        Expr::Call(call) => eval_supported_constant_call(working_set, call, input, expr.span),
        Expr::ExternalCall(head, args) => {
            eval_supported_constant_external_call(working_set, head, args, input, expr.span)
        }
        _ => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label("Not a constant.", expr.span)
            .with_help(
                "Leading annotated `mut` declarations in eBPF closures require a compile-time constant initializer",
            )),
    }
}

fn eval_supported_constant_bare_token(token: &str, span: Span) -> Value {
    if let Ok(int) = token.parse::<i64>() {
        return Value::int(int, span);
    }
    match token {
        "true" => Value::bool(true, span),
        "false" => Value::bool(false, span),
        "null" | "nothing" => Value::nothing(span),
        _ => Value::glob(token, false, span),
    }
}

fn eval_supported_constant_block(
    working_set: &StateWorkingSet,
    block: &nu_protocol::ast::Block,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut current = input;

    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            if element.redirection.is_some() {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "compile-time global initializer pipelines cannot redirect output",
                            element.expr.span,
                        ),
                );
            }

            current = Some(eval_supported_constant_value_with_input(
                working_set,
                &element.expr,
                current,
            )?);
        }
    }

    current.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label("constant subexpression is empty", span)
    })
}

fn eval_supported_constant_cell_path(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
) -> Result<CellPath, LabeledError> {
    match &expr.expr {
        Expr::String(path)
        | Expr::RawString(path)
        | Expr::Filepath(path, _)
        | Expr::Directory(path, _) => {
            return CellPath::from_value(Value::string(path, expr.span)).map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), expr.span)
            });
        }
        Expr::GlobPattern(path, _) => {
            let value = path
                .parse::<i64>()
                .ok()
                .filter(|index| *index >= 0)
                .map(|index| Value::int(index, expr.span))
                .unwrap_or_else(|| Value::string(path, expr.span));
            return CellPath::from_value(value).map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), expr.span)
            });
        }
        Expr::Var(_) => {
            let path =
                String::from_utf8_lossy(working_set.get_span_contents(expr.span)).into_owned();
            let value = path
                .parse::<i64>()
                .ok()
                .filter(|index| *index >= 0)
                .map(|index| Value::int(index, expr.span))
                .unwrap_or_else(|| Value::string(path, expr.span));
            return CellPath::from_value(value).map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), expr.span)
            });
        }
        _ => {}
    }

    let value = eval_supported_constant_value(working_set, expr)?;
    CellPath::from_value(value).map_err(|e| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(e.to_string(), expr.span)
    })
}

fn eval_supported_constant_call(
    working_set: &StateWorkingSet,
    call: &nu_protocol::ast::Call,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let cmd_name = working_set.get_decl(call.decl_id).name();

    match cmd_name {
        "append" | "prepend" => eval_supported_constant_list_mutation_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            span,
        ),
        "insert" | "update" | "upsert" => eval_supported_constant_path_mutation_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            call.positional_nth(1),
            span,
        ),
        _ => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                format!(
                    "command `{cmd_name}` is not supported in compile-time global initializers"
                ),
                span,
            )
            .with_help(
                "Use a compile-time constant expression, record/list literal, spread, or supported pipeline primitive like `upsert`",
            )),
    }
}

fn eval_supported_constant_external_call(
    working_set: &StateWorkingSet,
    head: &nu_protocol::ast::Expression,
    args: &[ExternalArgument],
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let cmd_name = match &head.expr {
        Expr::String(name)
        | Expr::RawString(name)
        | Expr::GlobPattern(name, _)
        | Expr::Filepath(name, _)
        | Expr::Directory(name, _) => name.as_str(),
        _ => {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "compile-time global initializer external command name must be a constant string",
                    head.span,
                ));
        }
    };

    match cmd_name {
        "append" | "prepend" => {
            let [item_arg] = args else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(format!("`{cmd_name}` requires exactly one argument"), span));
            };

            let ExternalArgument::Regular(item_expr) = item_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` item cannot use spread syntax in compile-time global initializers"
                        ),
                        item_arg.expr().span,
                    ));
            };

            eval_supported_constant_list_mutation_call(
                working_set,
                cmd_name,
                input,
                Some(item_expr),
                span,
            )
        }
        "insert" | "update" | "upsert" => {
            let [path_arg, new_value_arg] = args else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(format!("`{cmd_name}` requires exactly two arguments"), span));
            };

            let ExternalArgument::Regular(path_expr) = path_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` cell path cannot use spread syntax in compile-time global initializers"
                        ),
                        path_arg.expr().span,
                    ));
            };
            let ExternalArgument::Regular(new_value_expr) = new_value_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` replacement value cannot use spread syntax in compile-time global initializers"
                        ),
                        new_value_arg.expr().span,
                    ));
            };

            eval_supported_constant_path_mutation_call(
                working_set,
                cmd_name,
                input,
                Some(path_expr),
                Some(new_value_expr),
                span,
            )
        }
        _ => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                format!(
                    "external command `{cmd_name}` is not supported in compile-time global initializers"
                ),
                span,
            )
            .with_help(
                "Use a compile-time constant expression, record/list literal, spread, or supported pipeline primitive like `upsert`",
            )),
    }
}

fn eval_supported_constant_list_mutation_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    item_expr: Option<&nu_protocol::ast::Expression>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{cmd_name}` in a compile-time global initializer must receive pipeline input"),
            span,
        )
    })?;
    let item_expr = item_expr.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(format!("`{cmd_name}` requires an item argument"), span)
    })?;
    let item = eval_supported_constant_value(working_set, item_expr)?;

    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires list input"),
                span,
            ));
    };

    let updated = match cmd_name {
        "append" => vals.into_iter().chain(std::iter::once(item)).collect(),
        "prepend" => std::iter::once(item).chain(vals).collect(),
        _ => {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "compile-time global initializer list mutation `{cmd_name}` is not supported"
                    ),
                    span,
                ));
        }
    };

    Ok(Value::list(updated, value_span))
}

fn eval_supported_constant_path_mutation_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    path_expr: Option<&nu_protocol::ast::Expression>,
    new_value_expr: Option<&nu_protocol::ast::Expression>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;

    let path_expr = path_expr.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(format!("`{cmd_name}` requires a cell path argument"), span)
    })?;
    let new_value_expr = new_value_expr.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(format!("`{cmd_name}` requires a replacement value"), span)
    })?;
    let path = eval_supported_constant_cell_path(working_set, path_expr)?;
    let new_value = eval_supported_constant_value(working_set, new_value_expr)?;

    match cmd_name {
        "insert" => value
            .insert_data_at_cell_path(&path.members, new_value, span)
            .map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), span)
            })?,
        "update" => value
            .update_data_at_cell_path(&path.members, new_value)
            .map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), span)
            })?,
        "upsert" => value
            .upsert_data_at_cell_path(&path.members, new_value)
            .map_err(|e| {
                LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(e.to_string(), span)
            })?,
        _ => {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "compile-time global initializer path mutation `{cmd_name}` is not supported"
                    ),
                    span,
                ));
        }
    }

    Ok(value)
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

pub(super) fn map_leading_annotated_mut_globals(
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

pub(super) fn strip_leading_annotated_mut_initializer_stmts(
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

pub(super) fn parse_inline_user_function_signatures(
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

pub(super) fn compile_closure_with_context(
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

pub(super) fn compile_struct_ops_object(
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

    validate_struct_ops_callback_kfunc_requirements(
        value_type_name,
        body,
        &callback_kfuncs,
        call_head,
    )?;

    validate_required_struct_ops_callbacks(value_type_name, &callback_fields, call_head)?;

    spec.to_object_with_compiled_callbacks(callbacks)
        .map_err(|e| {
            LabeledError::new("Failed to build struct_ops object")
                .with_label(e.to_string(), call_head)
        })
}
