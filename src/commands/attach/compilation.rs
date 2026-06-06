use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;

use fancy_regex::{NoExpand, Regex as FancyRegex};
use heck::{
    ToKebabCase, ToLowerCamelCase, ToShoutySnakeCase, ToSnakeCase, ToTitleCase, ToUpperCamelCase,
};
use nu_cmd_lang::create_default_context;
use nu_parser::parse;
use nu_plugin::{EngineInterface, EvaluatedCall};
use nu_protocol::ast::{
    Boolean, CellPath, Comparison, Expr, ExternalArgument, ListItem, Math, Operator,
    RangeInclusion, RecordItem,
};
use nu_protocol::casing::Casing;
use nu_protocol::engine::{Closure, StateWorkingSet};
use nu_protocol::eval_const::{eval_constant, eval_constant_with_input};
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{
    BlockId, Config, DeclId, FromValue, IntoSpanned, LabeledError, ParseError, PipelineData, Range,
    Record, Signature, Span, Spanned, Type, Value, levenshtein_distance,
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::closure_params::recover_closure_param_sources;
use super::struct_ops::{
    StructOpsTopLevelFieldKind, apply_struct_ops_value_field, default_struct_ops_object_name,
    sanitize_struct_ops_component, validate_required_struct_ops_callbacks,
    validate_required_struct_ops_value_fields, validate_struct_ops_callback_kfunc_requirements,
    validate_struct_ops_top_level_field_kind,
};
use crate::compiler::{
    EbpfObject, MapRef, MirCompileResult, MirType, ProbeContext, ProgramIntrinsic,
    StructOpsObjectSpec, UserFunctionSig, UserParam, UserParamKind,
    compile_mir_to_ebpf_with_hints_and_globals, hir::AnnotatedMutGlobal, hir::HirFunction,
    hir::HirProgram, hir::HirStmt, hir::infer_ctx_param_excluding, hir::supports_constant_value,
    hir_type_infer, ir_to_mir::MAX_STRING_SIZE,
    lower_hir_to_mir_with_hints_key_value_maps_and_semantics, lower_ir_to_hir,
    passes::optimize_with_ssa_hints,
};
use crate::kernel_btf::TrampolineFieldSelector;

/// Common Nushell commands used in eBPF closures.
const NU_CLOSURE_COMMANDS: &[&str] = &[
    "where",
    "each",
    "all",
    "any",
    "take",
    "skip",
    "drop",
    "reverse",
    "uniq",
    "sort",
    "compact",
    "find",
    "append",
    "prepend",
    "char",
    "seq",
    "seq char",
    "seq date",
    "fill",
    "is-empty",
    "is-not-empty",
    "describe",
    "bytes length",
    "bytes starts-with",
    "bytes ends-with",
    "bytes index-of",
    "bytes reverse",
    "bytes build",
    "bytes at",
    "bytes add",
    "bytes remove",
    "bytes replace",
    "bytes collect",
    "bytes split",
    "str length",
    "str starts-with",
    "str ends-with",
    "str contains",
    "str distance",
    "str join",
    "split chars",
    "split list",
    "split row",
    "split words",
    "str stats",
    "str expand",
    "str index-of",
    "str substring",
    "str replace",
    "str trim",
    "str downcase",
    "str upcase",
    "str reverse",
    "str capitalize",
    "str camel-case",
    "str kebab-case",
    "str pascal-case",
    "str screaming-snake-case",
    "str snake-case",
    "str title-case",
    "length",
    "bits and",
    "bits not",
    "bits or",
    "bits rol",
    "bits ror",
    "bits shl",
    "bits shr",
    "bits xor",
    "math avg",
    "math exp",
    "math max",
    "math median",
    "math min",
    "math mode",
    "math product",
    "math arccos",
    "math arccosh",
    "math arcsin",
    "math arcsinh",
    "math arctan",
    "math arctanh",
    "math ceil",
    "math cos",
    "math cosh",
    "math floor",
    "math ln",
    "math log",
    "math round",
    "math sin",
    "math sinh",
    "math sqrt",
    "math stddev",
    "math sum",
    "math tan",
    "math tanh",
    "math variance",
    "math abs",
    "first",
    "last",
    "get",
    "select",
    "reject",
    "rename",
    "merge",
    "columns",
    "transpose",
    "values",
    "insert",
    "update",
    "upsert",
    "default",
    "if",
    "match",
    "random int",
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

pub(super) fn is_known_closure_command(name: &str) -> bool {
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
    closure_spans: &mut HashMap<BlockId, Span>,
    decl_names: &mut HashMap<DeclId, String>,
    span: Span,
) -> Result<(), LabeledError> {
    use crate::compiler::extract_closure_block_ids;

    let block_ids = extract_closure_block_ids(ir_block);

    for block_id in block_ids {
        if closure_irs.contains_key(&block_id) {
            continue;
        }

        let FetchedIrBlock {
            ir_block: nested_ir,
            decl_names: nested_decl_names,
            block_span,
        } = fetch_block_ir(engine, block_id, span)?;
        decl_names.extend(nested_decl_names);
        if let Some(block_span) = block_span {
            closure_spans.insert(block_id, block_span);
        }

        fetch_closure_irs(
            engine,
            &nested_ir,
            closure_irs,
            closure_spans,
            decl_names,
            span,
        )?;

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
                        "captured variable {} has unsupported type {}; supported captured constants are int, bool, string, binary, glob, filesize, duration, nothing, numeric scalar lists, homogeneous fixed arrays of scalar/string/binary/record constants with fixed-layout fields, and recursively constant records",
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

fn spans_overlap(left: Span, right: Span) -> bool {
    if left.is_empty() || right.is_empty() {
        left.start == right.start
    } else {
        left.start < right.end && right.start < left.end
    }
}

fn parse_error_in_span(parse_errors: &[ParseError], span: Span) -> Option<&ParseError> {
    parse_errors
        .iter()
        .find(|error| spans_overlap(error.span(), span))
}

fn annotated_mut_parse_error(error: &ParseError) -> LabeledError {
    LabeledError::new("Failed to parse annotated mutable declaration")
        .with_label(error.to_string(), error.span())
        .with_help(
            "Nushell rejected this typed `mut` declaration before the eBPF compiler could hoist it; use a type-compatible constant initializer such as `{}` for scalar record zero-init, or use `global-define --type` when no plain Nushell value can express the desired fixed layout",
        )
}

pub(super) struct CompiledClosureArtifacts {
    pub(super) compile_result: MirCompileResult,
    pub(super) generic_map_value_types: HashMap<MapRef, MirType>,
    pub(super) generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
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

fn eval_supported_constant_value_with_env(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Value, LabeledError> {
    eval_supported_constant_value_with_input(working_set, expr, None, env)
}

fn eval_supported_constant_value_with_input(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    input: Option<Value>,
    env: &HashMap<nu_protocol::VarId, Value>,
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
        Expr::Keyword(kw) => {
            eval_supported_constant_value_with_input(working_set, &kw.expr, input, env)
        }
        Expr::Subexpression(block_id) | Expr::Block(block_id) => {
            let block = working_set.get_block(*block_id);
            eval_supported_constant_block(working_set, block, input, env, expr.span)
        }
        Expr::Var(var_id) => env.get(var_id).cloned().ok_or_else(|| {
            LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label("Not a compile-time constant binding.", expr.span)
                .with_help(
                    "Only earlier leading `let` declarations with supported constant initializers can be referenced by annotated `mut` global initializers",
                )
        }),
        Expr::UnaryNot(inner) => eval_supported_constant_unary_not(working_set, inner, env),
        Expr::BinaryOp(lhs, op_expr, rhs) => {
            eval_supported_constant_binary_op(working_set, lhs, op_expr, rhs, env, expr.span)
        }
        Expr::FullCellPath(full_cell_path) => {
            let value = eval_supported_constant_value_with_input(
                working_set,
                &full_cell_path.head,
                input,
                env,
            )?;
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
                        let key = constant_record_key(working_set, key_expr, env)?;
                        let value = eval_supported_constant_value_with_input(
                            working_set, value_expr, None, env,
                        )?;
                        record.push(key, value);
                    }
                    RecordItem::Spread(_, spread_expr) => {
                        let value = eval_supported_constant_value_with_input(
                            working_set, spread_expr, None, env,
                        )?;
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
                            env,
                        )?);
                    }
                    ListItem::Spread(_, spread_expr) => {
                        let value = eval_supported_constant_value_with_input(
                            working_set,
                            spread_expr,
                            None,
                            env,
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
        Expr::Call(call) => eval_supported_constant_call(working_set, call, input, env, expr.span),
        Expr::ExternalCall(head, args) => {
            eval_supported_constant_external_call(working_set, head, args, input, env, expr.span)
        }
        _ => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label("Not a constant.", expr.span)
            .with_help(
                "Leading annotated `mut` declarations in eBPF closures require a compile-time constant initializer",
            )),
    }
}

fn eval_supported_constant_unary_not(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    let Value::Bool { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`not` requires a compile-time boolean in global initializers; got {}",
                    value.get_type()
                ),
                expr.span,
            ),
        );
    };
    Ok(Value::bool(!val, expr.span))
}

fn eval_supported_constant_binary_op(
    working_set: &StateWorkingSet,
    lhs: &nu_protocol::ast::Expression,
    op_expr: &nu_protocol::ast::Expression,
    rhs: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let Expr::Operator(op) = &op_expr.expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "constant binary expressions require an operator in global initializers",
                op_expr.span,
            ),
        );
    };
    let op = *op;

    match op {
        Operator::Boolean(boolean) => {
            eval_supported_constant_boolean_op(working_set, lhs, boolean, rhs, env, span)
        }
        Operator::Comparison(comparison) => {
            let lhs_value = eval_supported_constant_value_with_env(working_set, lhs, env)?;
            let rhs_value = eval_supported_constant_value_with_env(working_set, rhs, env)?;
            eval_supported_constant_comparison_op(comparison, lhs_value, rhs_value, span)
        }
        Operator::Math(math) => {
            let lhs_value = eval_supported_constant_value_with_env(working_set, lhs, env)?;
            let rhs_value = eval_supported_constant_value_with_env(working_set, rhs, env)?;
            eval_supported_constant_math_binary_op(math, lhs_value, rhs_value, span)
        }
        Operator::Bits(_) | Operator::Assignment(_) => Err(LabeledError::new(
            "Unsupported annotated mutable global initializer",
        )
        .with_label(
            format!(
                "operator `{}` is not supported in compile-time global initializers",
                op.as_str()
            ),
            span,
        )),
    }
}

fn eval_supported_constant_boolean_op(
    working_set: &StateWorkingSet,
    lhs: &nu_protocol::ast::Expression,
    op: Boolean,
    rhs: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let lhs_value = eval_supported_constant_value_with_env(working_set, lhs, env)?;
    let Value::Bool { val: lhs_bool, .. } = lhs_value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{op}` requires compile-time boolean operands in global initializers; left operand has type {}",
                    lhs_value.get_type()
                ),
                lhs.span,
            ),
        );
    };

    if op == Boolean::And && !lhs_bool {
        return Ok(Value::bool(false, span));
    }
    if op == Boolean::Or && lhs_bool {
        return Ok(Value::bool(true, span));
    }

    let rhs_value = eval_supported_constant_value_with_env(working_set, rhs, env)?;
    let Value::Bool { val: rhs_bool, .. } = rhs_value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{op}` requires compile-time boolean operands in global initializers; right operand has type {}",
                    rhs_value.get_type()
                ),
                rhs.span,
            ),
        );
    };

    let output = match op {
        Boolean::And => lhs_bool && rhs_bool,
        Boolean::Or => lhs_bool || rhs_bool,
        Boolean::Xor => lhs_bool ^ rhs_bool,
    };
    Ok(Value::bool(output, span))
}

fn eval_supported_constant_comparison_op(
    op: Comparison,
    lhs: Value,
    rhs: Value,
    span: Span,
) -> Result<Value, LabeledError> {
    if matches!(
        op,
        Comparison::In | Comparison::NotIn | Comparison::Has | Comparison::NotHas
    ) {
        return eval_supported_constant_membership_comparison_op(op, &lhs, &rhs, span);
    }

    let result = match op {
        Comparison::Equal => eval_supported_constant_values_equal(&lhs, &rhs),
        Comparison::NotEqual => {
            eval_supported_constant_values_equal(&lhs, &rhs).map(|value| !value)
        }
        Comparison::LessThan
        | Comparison::GreaterThan
        | Comparison::LessThanOrEqual
        | Comparison::GreaterThanOrEqual => eval_supported_constant_values_compare(op, &lhs, &rhs),
        Comparison::StartsWith | Comparison::NotStartsWith => {
            eval_supported_constant_values_affix(op, &lhs, &rhs).map(|value| {
                if op == Comparison::NotStartsWith {
                    !value
                } else {
                    value
                }
            })
        }
        Comparison::EndsWith | Comparison::NotEndsWith => {
            eval_supported_constant_values_affix(op, &lhs, &rhs).map(|value| {
                if op == Comparison::NotEndsWith {
                    !value
                } else {
                    value
                }
            })
        }
        _ => None,
    };

    result.map(|value| Value::bool(value, span)).ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{op}` is not supported for compile-time operands {} and {} in global initializers",
                lhs.get_type(),
                rhs.get_type()
            ),
            span,
        )
    })
}

fn eval_supported_constant_membership_comparison_op(
    op: Comparison,
    lhs: &Value,
    rhs: &Value,
    span: Span,
) -> Result<Value, LabeledError> {
    let result = match op {
        Comparison::In => lhs.r#in(span, rhs, span),
        Comparison::NotIn => lhs.not_in(span, rhs, span),
        Comparison::Has => lhs.has(span, rhs, span),
        Comparison::NotHas => lhs.not_has(span, rhs, span),
        _ => unreachable!("membership comparison op prefiltered"),
    };

    result.map_err(|err| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(err.to_string(), span)
    })
}

fn eval_supported_constant_values_equal(lhs: &Value, rhs: &Value) -> Option<bool> {
    match (lhs, rhs) {
        (Value::Bool { val: lhs, .. }, Value::Bool { val: rhs, .. }) => Some(lhs == rhs),
        (Value::Int { val: lhs, .. }, Value::Int { val: rhs, .. }) => Some(lhs == rhs),
        (Value::Filesize { val: lhs, .. }, Value::Filesize { val: rhs, .. }) => Some(lhs == rhs),
        (Value::Duration { val: lhs, .. }, Value::Duration { val: rhs, .. }) => Some(lhs == rhs),
        (Value::String { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::String { val: lhs, .. }, Value::Glob { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::Glob { val: rhs, .. }) => Some(lhs == rhs),
        (Value::Binary { val: lhs, .. }, Value::Binary { val: rhs, .. }) => Some(lhs == rhs),
        (Value::Nothing { .. }, Value::Nothing { .. }) => Some(true),
        _ => None,
    }
}

fn eval_supported_constant_values_compare(
    op: Comparison,
    lhs: &Value,
    rhs: &Value,
) -> Option<bool> {
    match (lhs, rhs) {
        (Value::Int { val: lhs, .. }, Value::Int { val: rhs, .. }) => {
            eval_supported_constant_ord_compare(op, lhs.cmp(rhs))
        }
        (Value::Filesize { val: lhs, .. }, Value::Filesize { val: rhs, .. }) => {
            eval_supported_constant_ord_compare(op, lhs.cmp(rhs))
        }
        (Value::Duration { val: lhs, .. }, Value::Duration { val: rhs, .. }) => {
            eval_supported_constant_ord_compare(op, lhs.cmp(rhs))
        }
        (Value::String { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::String { val: lhs, .. }, Value::Glob { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::Glob { val: rhs, .. }) => {
            eval_supported_constant_ord_compare(op, lhs.cmp(rhs))
        }
        _ => None,
    }
}

fn eval_supported_constant_ord_compare(
    op: Comparison,
    ordering: std::cmp::Ordering,
) -> Option<bool> {
    match op {
        Comparison::LessThan => Some(ordering.is_lt()),
        Comparison::GreaterThan => Some(ordering.is_gt()),
        Comparison::LessThanOrEqual => Some(!ordering.is_gt()),
        Comparison::GreaterThanOrEqual => Some(!ordering.is_lt()),
        _ => None,
    }
}

fn eval_supported_constant_values_affix(op: Comparison, lhs: &Value, rhs: &Value) -> Option<bool> {
    let check_start = matches!(op, Comparison::StartsWith | Comparison::NotStartsWith);
    match (lhs, rhs) {
        (Value::String { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::String { val: lhs, .. }, Value::Glob { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::String { val: rhs, .. })
        | (Value::Glob { val: lhs, .. }, Value::Glob { val: rhs, .. }) => Some(if check_start {
            lhs.starts_with(rhs)
        } else {
            lhs.ends_with(rhs)
        }),
        _ => None,
    }
}

fn eval_supported_constant_math_binary_op(
    op: Math,
    lhs: Value,
    rhs: Value,
    span: Span,
) -> Result<Value, LabeledError> {
    match op {
        Math::Add | Math::Subtract | Math::Multiply => {
            eval_supported_constant_int_math_binary_op(op, lhs, rhs, span)
        }
        Math::Concatenate => eval_supported_constant_concatenate_binary_op(lhs, rhs, span),
        Math::Divide | Math::FloorDivide | Math::Modulo | Math::Pow => Err(LabeledError::new(
            "Unsupported annotated mutable global initializer",
        )
        .with_label(
            format!(
                "operator `{}` is not supported in compile-time global initializers",
                op.as_str()
            ),
            span,
        )),
    }
}

fn eval_supported_constant_int_math_binary_op(
    op: Math,
    lhs: Value,
    rhs: Value,
    span: Span,
) -> Result<Value, LabeledError> {
    let (Value::Int { val: lhs, .. }, Value::Int { val: rhs, .. }) = (&lhs, &rhs) else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "operator `{}` requires compile-time integer operands in global initializers; got {} and {}",
                    op.as_str(),
                    lhs.get_type(),
                    rhs.get_type()
                ),
                span,
            ),
        );
    };

    let output = match op {
        Math::Add => lhs.checked_add(*rhs),
        Math::Subtract => lhs.checked_sub(*rhs),
        Math::Multiply => lhs.checked_mul(*rhs),
        _ => unreachable!("integer math op prefiltered"),
    }
    .ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "operator `{}` overflows i64 in compile-time global initializers",
                op.as_str()
            ),
            span,
        )
    })?;

    Ok(Value::int(output, span))
}

fn eval_supported_constant_concatenate_binary_op(
    lhs: Value,
    rhs: Value,
    span: Span,
) -> Result<Value, LabeledError> {
    match (lhs, rhs) {
        (Value::String { mut val, .. }, Value::String { val: rhs, .. })
        | (Value::String { mut val, .. }, Value::Glob { val: rhs, .. })
        | (Value::Glob { mut val, .. }, Value::String { val: rhs, .. })
        | (Value::Glob { mut val, .. }, Value::Glob { val: rhs, .. }) => {
            val.push_str(&rhs);
            Ok(Value::string(val, span))
        }
        (Value::Binary { mut val, .. }, Value::Binary { val: rhs, .. }) => {
            val.extend(rhs);
            Ok(Value::binary(val, span))
        }
        (Value::List { mut vals, .. }, Value::List { vals: rhs, .. }) => {
            vals.extend(rhs);
            Ok(Value::list(vals, span))
        }
        (lhs, rhs) => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "operator `++` requires string, binary, or list operands in compile-time global initializers; got {} and {}",
                    lhs.get_type(),
                    rhs.get_type()
                ),
                span,
            ),
        ),
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
    env: &HashMap<nu_protocol::VarId, Value>,
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
                env,
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
    env: &HashMap<nu_protocol::VarId, Value>,
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
        Expr::Var(var_id) => {
            if let Some(value) = env.get(var_id) {
                return CellPath::from_value(value.clone()).map_err(|e| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(e.to_string(), expr.span)
                });
            }

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

    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    CellPath::from_value(value).map_err(|e| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(e.to_string(), expr.span)
    })
}

fn eval_supported_constant_call(
    working_set: &StateWorkingSet,
    call: &nu_protocol::ast::Call,
    input: Option<Value>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let cmd_name = working_set.get_decl(call.decl_id).name();

    match cmd_name {
        "first" | "last" => eval_supported_constant_list_first_or_last_call(
            working_set,
            cmd_name,
            input,
            &call.arguments,
            env,
            span,
        ),
        "take" | "skip" | "drop" => eval_supported_constant_list_take_skip_or_drop_call(
            working_set,
            cmd_name,
            input,
            &call.arguments,
            env,
            span,
        ),
        "reverse" | "uniq" => {
            if !call.arguments.is_empty() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept arguments in compile-time global initializers"
                        ),
                        span,
                    ));
            }
            eval_supported_constant_list_reverse_or_uniq(cmd_name, input, span)
        }
        "compact" => eval_supported_constant_list_compact_call(
            working_set,
            input,
            &call.arguments,
            env,
            span,
        ),
        "sort" => eval_supported_constant_list_sort_call(input, &call.arguments, span),
        "find" => eval_supported_constant_list_find_call(
            working_set,
            input,
            &call.arguments,
            env,
            span,
        ),
        "length" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_length(input, span)
        }
        "is-empty" | "is-not-empty" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_empty_predicate(cmd_name, input, span)
        }
        "bytes length" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_bytes_length(input, span)
        }
        "bytes at" => {
            let range =
                eval_supported_constant_bytes_at_call_range(working_set, &call.arguments, env, span)?;
            eval_supported_constant_bytes_at(input, range, span)
        }
        "bytes add" => {
            let args =
                eval_supported_constant_bytes_add_call_args(working_set, &call.arguments, env, span)?;
            eval_supported_constant_bytes_add(input, args, span)
        }
        "bytes build" => {
            let bytes =
                eval_supported_constant_bytes_build_call_args(working_set, &call.arguments, env)?;
            eval_supported_constant_bytes_build(input, bytes, span)
        }
        "bytes collect" => {
            let separator =
                eval_supported_constant_bytes_collect_call_separator(working_set, &call.arguments, env)?;
            eval_supported_constant_bytes_collect(input, separator, span)
        }
        "bytes reverse" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_bytes_reverse(input, span)
        }
        "bytes starts-with" | "bytes ends-with" => {
            let pattern = eval_supported_constant_bytes_predicate_call_pattern(
                working_set,
                cmd_name,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bytes_predicate(cmd_name, input, pattern, span)
        }
        "bytes index-of" => {
            let args = eval_supported_constant_bytes_index_of_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bytes_index_of(input, args, span)
        }
        "bytes remove" => {
            let args = eval_supported_constant_bytes_remove_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bytes_remove(input, args, span)
        }
        "bytes replace" => {
            let args = eval_supported_constant_bytes_replace_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bytes_replace(input, args, span)
        }
        "bytes split" => {
            let separator = eval_supported_constant_bytes_split_call_separator(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bytes_split(input, separator, span)
        }
        "bits and" | "bits or" | "bits xor" => {
            let args = eval_supported_constant_bits_binary_call_args(
                working_set,
                cmd_name,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bits_binary(cmd_name, input, args, span)
        }
        "bits not" => {
            let mode =
                eval_supported_constant_bits_not_call_mode(working_set, &call.arguments, env, span)?;
            eval_supported_constant_bits_not(cmd_name, input, mode, span)
        }
        "bits shl" | "bits shr" | "bits rol" | "bits ror" => {
            let args = eval_supported_constant_bits_shift_rotate_call_args(
                working_set,
                cmd_name,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_bits_shift_rotate(cmd_name, input, args, span)
        }
        "math abs" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_abs(input, span)
        }
        "math avg" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_avg(input, span)
        }
        "math max" | "math min" | "math product" | "math sum" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_int_reduce(cmd_name, input, span)
        }
        "math median" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_median(input, span)
        }
        "math mode" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_mode(input, span)
        }
        "math ceil" | "math floor" | "math round" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_math_rounding(cmd_name, input, span)
        }
        "char" => {
            let output =
                eval_supported_constant_char_call_args(working_set, &call.arguments, env, span)?;
            eval_supported_constant_char(input, output, span)
        }
        "fill" => {
            let args = eval_supported_constant_fill_call_args(
                working_set,
                &call.arguments,
                env,
            )?;
            eval_supported_constant_fill(input, args, span)
        }
        "str length" => {
            let mode = eval_supported_constant_str_length_mode_call(&call.arguments)?;
            eval_supported_constant_str_length(input, mode, span)
        }
        "str starts-with" | "str ends-with" | "str contains" => {
            let args = eval_supported_constant_str_predicate_call_args(
                working_set,
                cmd_name,
                &call.arguments,
                env,
            )?;
            eval_supported_constant_str_predicate(cmd_name, input, args, span)
        }
        "str index-of" => {
            let args = eval_supported_constant_str_index_of_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_str_index_of(input, args, span)
        }
        "str distance" => {
            let compare = eval_supported_constant_str_distance_call_arg(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_str_distance(input, compare, span)
        }
        "str join" => {
            let separator =
                eval_supported_constant_str_join_call_separator(working_set, &call.arguments, env)?;
            eval_supported_constant_str_join(input, separator, span)
        }
        "str stats" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_str_stats(input, span)
        }
        "str expand" => {
            let use_path = eval_supported_constant_str_expand_args(&call.arguments)?;
            eval_supported_constant_str_expand(input, use_path, span)
        }
        "str trim" => {
            let args = eval_supported_constant_str_trim_args(working_set, &call.arguments, env)?;
            eval_supported_constant_str_trim(input, args, span)
        }
        "str substring" => {
            let args = eval_supported_constant_str_substring_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_str_substring(input, args, span)
        }
        "str replace" => {
            let args = eval_supported_constant_str_replace_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_str_replace(input, args, span)
        }
        "str downcase"
        | "str upcase"
        | "str reverse"
        | "str capitalize"
        | "str camel-case"
        | "str kebab-case"
        | "str pascal-case"
        | "str screaming-snake-case"
        | "str snake-case"
        | "str title-case" => {
            eval_supported_constant_no_argument_call(cmd_name, &call.arguments)?;
            eval_supported_constant_str_transform(cmd_name, input, span)
        }
        "split chars" => {
            let use_grapheme_clusters =
                eval_supported_constant_split_chars_mode_call(&call.arguments)?;
            eval_supported_constant_split_chars(input, use_grapheme_clusters, span)
        }
        "split list" => {
            let args =
                eval_supported_constant_split_list_call_args(working_set, &call.arguments, env)?;
            eval_supported_constant_split_list(input, args, span)
        }
        "split row" => {
            let args =
                eval_supported_constant_split_row_call_args(working_set, &call.arguments, env)?;
            eval_supported_constant_split_row(input, args, span)
        }
        "split words" => {
            let args =
                eval_supported_constant_split_words_call_args(working_set, &call.arguments, env)?;
            eval_supported_constant_split_words(input, args, span)
        }
        "get" => eval_supported_constant_get_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            env,
            span,
        ),
        "append" | "prepend" => eval_supported_constant_list_mutation_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            env,
            span,
        ),
        "merge" => eval_supported_constant_record_merge_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            env,
            span,
        ),
        "select" | "reject" => eval_supported_constant_record_select_or_reject_call(
            working_set,
            cmd_name,
            input,
            &call.arguments,
            env,
            span,
        ),
        "rename" => eval_supported_constant_record_rename_call(working_set, input, call, env, span),
        "columns" | "values" => {
            if !call.arguments.is_empty() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept arguments in compile-time global initializers"
                        ),
                        span,
                    ));
            }
            eval_supported_constant_record_columns_or_values(cmd_name, input, span)
        }
        "transpose" => {
            let args = eval_supported_constant_record_transpose_call_args(
                working_set,
                &call.arguments,
                env,
                span,
            )?;
            eval_supported_constant_record_transpose(input, args, span)
        }
        "default" => eval_supported_constant_default_call(
            working_set,
            input,
            &call.arguments,
            env,
            span,
        ),
        "insert" | "update" | "upsert" => eval_supported_constant_path_mutation_call(
            working_set,
            cmd_name,
            input,
            call.positional_nth(0),
            call.positional_nth(1),
            env,
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
    env: &HashMap<nu_protocol::VarId, Value>,
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
        "first" | "last" => {
            for arg in args {
                if let ExternalArgument::Spread(expr) = arg {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` count argument cannot use spread syntax in compile-time global initializers"
                            ),
                            expr.span,
                        ));
                }
            }
            let count_expr = match args {
                [] => None,
                [ExternalArgument::Regular(expr)] => Some(expr),
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts at most one count argument in compile-time global initializers"
                            ),
                            span,
                        ));
                }
            };
            eval_supported_constant_list_first_or_last(
                working_set, cmd_name, input, count_expr, env, span,
            )
        }
        "take" | "skip" | "drop" => {
            for arg in args {
                if let ExternalArgument::Spread(expr) = arg {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` count argument cannot use spread syntax in compile-time global initializers"
                            ),
                            expr.span,
                        ));
                }
            }
            let count_expr = match args {
                [] => None,
                [ExternalArgument::Regular(expr)] => Some(expr),
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts at most one count argument in compile-time global initializers"
                            ),
                            span,
                        ));
                }
            };
            eval_supported_constant_list_take_skip_or_drop(
                working_set, cmd_name, input, count_expr, env, span,
            )
        }
        "reverse" | "uniq" => {
            if !args.is_empty() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept arguments in compile-time global initializers"
                        ),
                        span,
                    ));
            }
            eval_supported_constant_list_reverse_or_uniq(cmd_name, input, span)
        }
        "compact" => {
            let mut arg_exprs = Vec::new();
            for arg in args {
                let ExternalArgument::Regular(expr) = arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`compact` arguments cannot use spread syntax in compile-time global initializers",
                            arg.expr().span,
                        ));
                };
                arg_exprs.push(expr);
            }
            eval_supported_constant_list_compact_external_call(
                working_set, input, arg_exprs, env, span,
            )
        }
        "sort" => {
            let mut reverse = false;
            if let Some(first_arg) = args.first() {
                let ExternalArgument::Regular(first_expr) = first_arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`sort` arguments cannot use spread syntax in compile-time global initializers",
                            first_arg.expr().span,
                        ));
                };
                let first_value =
                    eval_supported_constant_value_with_env(working_set, first_expr, env)?;
                if matches!(
                    first_value,
                    Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--reverse"
                ) {
                    reverse = true;
                    if args.len() > 1 {
                        return Err(
                            LabeledError::new("Unsupported annotated mutable global initializer")
                                .with_label(
                                    "`sort` does not accept arguments in compile-time global initializers",
                                    span,
                                ),
                        );
                    }
                } else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`sort` does not accept arguments in compile-time global initializers",
                            span,
                        ));
                }
            }
            eval_supported_constant_list_sort(input, reverse, span)
        }
        "find" => {
            let [needle_arg] = args else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`find` requires exactly one search argument in compile-time global initializers",
                        span,
                    ));
            };
            let ExternalArgument::Regular(needle_expr) = needle_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`find` search argument cannot use spread syntax in compile-time global initializers",
                        needle_arg.expr().span,
                    ));
            };
            eval_supported_constant_list_find(
                working_set,
                input,
                needle_expr,
                env,
                span,
            )
        }
        "length" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_length(input, span)
        }
        "is-empty" | "is-not-empty" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_empty_predicate(cmd_name, input, span)
        }
        "bytes" => {
            eval_supported_constant_bytes_external_call(working_set, input, args, env, span)
        }
        "bytes length" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_bytes_length(input, span)
        }
        "bytes at" => {
            let range = eval_supported_constant_bytes_at_external_range(working_set, args, env, span)?;
            eval_supported_constant_bytes_at(input, range, span)
        }
        "bytes add" => {
            let args = eval_supported_constant_bytes_add_external_args(working_set, args, env, span)?;
            eval_supported_constant_bytes_add(input, args, span)
        }
        "bytes build" => {
            let bytes = eval_supported_constant_bytes_build_external_args(working_set, args, env)?;
            eval_supported_constant_bytes_build(input, bytes, span)
        }
        "bytes collect" => {
            let separator =
                eval_supported_constant_bytes_collect_external_separator(working_set, args, env, span)?;
            eval_supported_constant_bytes_collect(input, separator, span)
        }
        "bytes reverse" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_bytes_reverse(input, span)
        }
        "bytes starts-with" | "bytes ends-with" => {
            let pattern = eval_supported_constant_bytes_predicate_external_pattern(
                working_set,
                cmd_name,
                args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_predicate(cmd_name, input, pattern, span)
        }
        "bytes index-of" => {
            let args =
                eval_supported_constant_bytes_index_of_external_args(working_set, args, env, span)?;
            eval_supported_constant_bytes_index_of(input, args, span)
        }
        "bytes remove" => {
            let args =
                eval_supported_constant_bytes_remove_external_args(working_set, args, env, span)?;
            eval_supported_constant_bytes_remove(input, args, span)
        }
        "bytes replace" => {
            let args =
                eval_supported_constant_bytes_replace_external_args(working_set, args, env, span)?;
            eval_supported_constant_bytes_replace(input, args, span)
        }
        "bytes split" => {
            let separator =
                eval_supported_constant_bytes_split_external_separator(working_set, args, env, span)?;
            eval_supported_constant_bytes_split(input, separator, span)
        }
        "bits" => eval_supported_constant_bits_external_call(working_set, input, args, env, span),
        "bits and" | "bits or" | "bits xor" => {
            let args =
                eval_supported_constant_bits_binary_external_args(working_set, cmd_name, args, env, span)?;
            eval_supported_constant_bits_binary(cmd_name, input, args, span)
        }
        "bits not" => {
            let mode =
                eval_supported_constant_bits_not_external_mode(working_set, args, env, span)?;
            eval_supported_constant_bits_not(cmd_name, input, mode, span)
        }
        "bits shl" | "bits shr" | "bits rol" | "bits ror" => {
            let args = eval_supported_constant_bits_shift_rotate_external_args(
                working_set,
                cmd_name,
                args,
                env,
                span,
            )?;
            eval_supported_constant_bits_shift_rotate(cmd_name, input, args, span)
        }
        "math" => eval_supported_constant_math_external_call(working_set, input, args, env, span),
        "math abs" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_abs(input, span)
        }
        "math avg" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_avg(input, span)
        }
        "math max" | "math min" | "math product" | "math sum" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_int_reduce(cmd_name, input, span)
        }
        "math median" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_median(input, span)
        }
        "math mode" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_mode(input, span)
        }
        "math ceil" | "math floor" | "math round" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_math_rounding(cmd_name, input, span)
        }
        "char" => {
            let output = eval_supported_constant_char_external_args(working_set, args, env, span)?;
            eval_supported_constant_char(input, output, span)
        }
        "fill" => {
            let args = eval_supported_constant_fill_external_args(working_set, args, env)?;
            eval_supported_constant_fill(input, args, span)
        }
        "str" => eval_supported_constant_str_external_call(working_set, input, args, env, span),
        "str length" => {
            let mode = eval_supported_constant_str_length_mode_external_args(
                working_set,
                "str length",
                args,
                env,
                span,
            )?;
            eval_supported_constant_str_length(input, mode, span)
        }
        "str starts-with" | "str ends-with" | "str contains" => {
            let args = eval_supported_constant_str_predicate_external_args(
                working_set,
                cmd_name,
                args,
                env,
                span,
            )?;
            eval_supported_constant_str_predicate(cmd_name, input, args, span)
        }
        "str index-of" => {
            let args =
                eval_supported_constant_str_index_of_external_args(working_set, args, env, span)?;
            eval_supported_constant_str_index_of(input, args, span)
        }
        "str distance" => {
            let compare =
                eval_supported_constant_str_distance_external_arg(working_set, args, env, span)?;
            eval_supported_constant_str_distance(input, compare, span)
        }
        "str join" => {
            let separator =
                eval_supported_constant_str_join_external_separator(working_set, args, env, span)?;
            eval_supported_constant_str_join(input, separator, span)
        }
        "str stats" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_str_stats(input, span)
        }
        "str expand" => {
            let use_path =
                eval_supported_constant_str_expand_external_args(working_set, args, env, span)?;
            eval_supported_constant_str_expand(input, use_path, span)
        }
        "str trim" => {
            let args = eval_supported_constant_str_trim_external_args(working_set, args, env, span)?;
            eval_supported_constant_str_trim(input, args, span)
        }
        "str substring" => {
            let args =
                eval_supported_constant_str_substring_external_args(working_set, args, env, span)?;
            eval_supported_constant_str_substring(input, args, span)
        }
        "str replace" => {
            let args =
                eval_supported_constant_str_replace_external_args(working_set, args, env, span)?;
            eval_supported_constant_str_replace(input, args, span)
        }
        "str downcase"
        | "str upcase"
        | "str reverse"
        | "str capitalize"
        | "str camel-case"
        | "str kebab-case"
        | "str pascal-case"
        | "str screaming-snake-case"
        | "str snake-case"
        | "str title-case" => {
            eval_supported_constant_no_external_args(cmd_name, args, span)?;
            eval_supported_constant_str_transform(cmd_name, input, span)
        }
        "split" => eval_supported_constant_split_external_call(working_set, input, args, env, span),
        "split chars" => {
            let use_grapheme_clusters =
                eval_supported_constant_split_chars_mode_external_args(working_set, args, env, span)?;
            eval_supported_constant_split_chars(input, use_grapheme_clusters, span)
        }
        "split list" => {
            let args = eval_supported_constant_split_list_external_args(working_set, args, env, span)?;
            eval_supported_constant_split_list(input, args, span)
        }
        "split row" => {
            let args = eval_supported_constant_split_row_external_args(working_set, args, env, span)?;
            eval_supported_constant_split_row(input, args, span)
        }
        "split words" => {
            let args =
                eval_supported_constant_split_words_external_args(working_set, args, env, span)?;
            eval_supported_constant_split_words(input, args, span)
        }
        "get" => {
            let [path_arg] = args else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label("`get` requires exactly one argument", span));
            };

            let ExternalArgument::Regular(path_expr) = path_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`get` path cannot use spread syntax in compile-time global initializers",
                        path_arg.expr().span,
                    ));
            };

            eval_supported_constant_get_call(
                working_set,
                cmd_name,
                input,
                Some(path_expr),
                env,
                span,
            )
        }
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
                env,
                span,
            )
        }
        "merge" => {
            let [record_arg] = args else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(format!("`{cmd_name}` requires exactly one argument"), span));
            };

            let ExternalArgument::Regular(record_expr) = record_arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` record argument cannot use spread syntax in compile-time global initializers"
                        ),
                        record_arg.expr().span,
                    ));
            };

            eval_supported_constant_record_merge_call(
                working_set,
                cmd_name,
                input,
                Some(record_expr),
                env,
                span,
            )
        }
        "select" | "reject" => {
            let fields = args
                .iter()
                .map(|arg| {
                    let ExternalArgument::Regular(field_expr) = arg else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name}` field arguments cannot use spread syntax in compile-time global initializers"
                            ),
                            arg.expr().span,
                        ));
                    };
                    eval_supported_constant_record_field_name(working_set, field_expr, env)
                })
                .collect::<Result<Vec<_>, _>>()?;

            eval_supported_constant_record_select_or_reject(
                cmd_name,
                input,
                fields,
                span,
            )
        }
        "rename" => {
            if let Some(first_arg) = args.first() {
                let ExternalArgument::Regular(first_expr) = first_arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`rename` field arguments cannot use spread syntax in compile-time global initializers",
                            first_arg.expr().span,
                        ));
                };
                let first_value =
                    eval_supported_constant_value_with_env(working_set, first_expr, env)?;
                if matches!(
                    first_value,
                    Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--block" || val == "-b"
                ) {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`rename --block` is not supported in compile-time global initializers",
                            span,
                        ));
                }
                if matches!(
                    first_value,
                    Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--column" || val == "-c"
                ) {
                    let [_, column_arg] = args else {
                        return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                "`rename --column` requires exactly one record mapping in compile-time global initializers",
                                span,
                            ));
                    };
                    let ExternalArgument::Regular(column_expr) = column_arg else {
                        return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                "`rename --column` record mapping cannot use spread syntax in compile-time global initializers",
                                column_arg.expr().span,
                            ));
                    };
                    let pairs = eval_supported_constant_record_rename_column_pairs(
                        working_set,
                        column_expr,
                        env,
                    )?;
                    return eval_supported_constant_record_rename_column(input, pairs, span);
                }
            }

            let fields = args
                .iter()
                .map(|arg| {
                    let ExternalArgument::Regular(field_expr) = arg else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`rename` field arguments cannot use spread syntax in compile-time global initializers",
                            arg.expr().span,
                        ));
                    };
                    eval_supported_constant_record_field_name(working_set, field_expr, env)
                })
                .collect::<Result<Vec<_>, _>>()?;

            eval_supported_constant_record_rename_positional(input, fields, span)
        }
        "columns" | "values" => {
            if !args.is_empty() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept arguments in compile-time global initializers"
                        ),
                        span,
                    ));
            }
            eval_supported_constant_record_columns_or_values(cmd_name, input, span)
        }
        "transpose" => {
            let args = eval_supported_constant_record_transpose_external_args(
                working_set,
                args,
                env,
                span,
            )?;
            eval_supported_constant_record_transpose(input, args, span)
        }
        "default" => eval_supported_constant_default_external_call(
            working_set,
            input,
            args,
            env,
            span,
        ),
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
                env,
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

fn eval_supported_constant_get_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    path_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
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
    let path = eval_supported_constant_cell_path(working_set, path_expr, env)?;

    value
        .follow_cell_path(&path.members)
        .map(|projected| projected.into_owned())
        .map_err(|e| {
            LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(e.to_string(), span)
        })
}

fn eval_supported_constant_list_first_or_last_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut count_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if count_expr.replace(expr).is_some() {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`{cmd_name}` accepts at most one count argument in compile-time global initializers"
                                ),
                                arg.span(),
                            ),
                    );
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` count argument cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_list_first_or_last(working_set, cmd_name, input, count_expr, env, span)
}

fn eval_supported_constant_list_first_or_last(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    count_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires list input"),
                span,
            ),
        );
    };

    let Some(count_expr) = count_expr else {
        if vals.is_empty() {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires a non-empty compile-time list in global initializers"
                    ),
                    span,
                ),
            );
        }
        return if cmd_name == "first" {
            Ok(vals.into_iter().next().expect("non-empty list checked"))
        } else {
            Ok(vals.into_iter().last().expect("non-empty list checked"))
        };
    };

    let count_value = eval_supported_constant_value_with_env(working_set, count_expr, env)?;
    let Value::Int { val: raw_count, .. } = count_value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` count must be a compile-time integer in global initializers"),
                count_expr.span,
            ),
        );
    };
    if raw_count < 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` count must be non-negative in global initializers"),
                count_expr.span,
            ),
        );
    }
    let count = usize::try_from(raw_count).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{cmd_name}` count is too large for compile-time global initializers"),
            count_expr.span,
        )
    })?;

    let selected = if cmd_name == "first" {
        vals.into_iter().take(count).collect()
    } else {
        let start = vals.len().saturating_sub(count);
        vals.into_iter().skip(start).collect()
    };

    Ok(Value::list(selected, value_span))
}

fn eval_supported_constant_list_reverse_or_uniq(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires list input"),
                span,
            ),
        );
    };

    let transformed = if cmd_name == "reverse" {
        vals.into_iter().rev().collect()
    } else {
        let mut unique = Vec::new();
        for value in vals {
            if !unique.contains(&value) {
                unique.push(value);
            }
        }
        unique
    };

    Ok(Value::list(transformed, value_span))
}

fn eval_supported_constant_list_compact_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut remove_empty = false;
    let mut columns = Vec::new();
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                columns.push(eval_supported_constant_record_field_name(
                    working_set,
                    expr,
                    env,
                )?);
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.0.item != "empty" || named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`compact` accepts only the --empty flag in compile-time global initializers",
                            arg.span(),
                        ));
                }
                remove_empty = true;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`compact` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_list_compact(input, remove_empty, columns, span)
}

fn eval_supported_constant_list_compact_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    mut arg_exprs: Vec<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut remove_empty = false;
    if let Some(first) = arg_exprs.first() {
        let first_value = eval_supported_constant_value_with_env(working_set, first, env)?;
        if matches!(
            first_value,
            Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--empty"
        ) {
            remove_empty = true;
            arg_exprs.remove(0);
        }
    }

    let columns = arg_exprs
        .into_iter()
        .map(|expr| eval_supported_constant_record_field_name(working_set, expr, env))
        .collect::<Result<Vec<_>, _>>()?;
    eval_supported_constant_list_compact(input, remove_empty, columns, span)
}

fn eval_supported_constant_list_compact(
    input: Option<Value>,
    remove_empty: bool,
    columns: Vec<String>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`compact` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`compact` in a compile-time global initializer requires list input",
                span,
            ),
        );
    };
    if !columns.is_empty()
        && !vals
            .iter()
            .all(|value| matches!(value, Value::Record { .. }))
    {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`compact` does not accept column arguments for non-record lists in compile-time global initializers",
                span,
            ),
        );
    }

    let vals = vals
        .into_iter()
        .filter(|value| {
            eval_supported_constant_compact_keeps_value_for_columns(value, remove_empty, &columns)
        })
        .collect::<Vec<_>>();
    Ok(Value::list(vals, value_span))
}

fn eval_supported_constant_compact_keeps_value_for_columns(
    value: &Value,
    remove_empty: bool,
    columns: &[String],
) -> bool {
    if columns.is_empty() {
        return eval_supported_constant_compact_keeps_value(value, remove_empty);
    }

    let Value::Record { val, .. } = value else {
        return true;
    };

    columns.iter().all(|column| {
        val.get(column)
            .is_some_and(|value| eval_supported_constant_compact_keeps_value(value, remove_empty))
    })
}

fn eval_supported_constant_compact_keeps_value(value: &Value, remove_empty: bool) -> bool {
    match value {
        Value::Nothing { .. } => false,
        Value::String { val, .. } => !remove_empty || !val.is_empty(),
        Value::Binary { val, .. } => !remove_empty || !val.is_empty(),
        Value::List { vals, .. } => !remove_empty || !vals.is_empty(),
        Value::Record { val, .. } => !remove_empty || !val.is_empty(),
        _ => true,
    }
}

fn eval_supported_constant_no_argument_call(
    cmd_name: &str,
    args: &[nu_protocol::ast::Argument],
) -> Result<(), LabeledError> {
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` does not accept arguments in compile-time global initializers"
                            ),
                            arg.span(),
                        ),
                );
            }
        }
    }

    Ok(())
}

fn eval_supported_constant_no_external_args(
    cmd_name: &str,
    args: &[ExternalArgument],
    span: Span,
) -> Result<(), LabeledError> {
    if let Some(arg) = args.first() {
        if let ExternalArgument::Spread(expr) = arg {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                    ),
                    expr.span,
                ));
        }

        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` does not accept arguments in compile-time global initializers"
                ),
                span,
            ),
        );
    }

    Ok(())
}

fn eval_supported_constant_required_pipeline_input(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })
}

fn eval_supported_constant_length(input: Option<Value>, span: Span) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("length", input, span)?;
    let len = match value {
        Value::Nothing { .. } => 0,
        Value::List { ref vals, .. } => vals.len(),
        Value::Binary { ref val, .. } => val.len(),
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`length` in a compile-time global initializer requires list, binary, or null input",
                    span,
                ),
            );
        }
    };

    Ok(Value::int(len as i64, span))
}

fn eval_supported_constant_empty_predicate(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let empty = match value {
        Value::Nothing { .. } => true,
        Value::String { ref val, .. } => val.is_empty(),
        Value::Binary { ref val, .. } => val.is_empty(),
        Value::List { ref vals, .. } => vals.is_empty(),
        Value::Record { ref val, .. } => val.is_empty(),
        Value::Bool { .. }
        | Value::Int { .. }
        | Value::Float { .. }
        | Value::Filesize { .. }
        | Value::Duration { .. } => false,
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` in a compile-time global initializer requires list, record, string, binary, scalar, or null input"
                    ),
                    span,
                ),
            );
        }
    };
    let result = if cmd_name == "is-not-empty" {
        !empty
    } else {
        empty
    };

    Ok(Value::bool(result, span))
}

fn eval_supported_constant_bytes_length(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes length", input, span)?;
    let value_span = value.span();
    match value {
        Value::Binary { val, .. } => Ok(Value::int(val.len() as i64, span)),
        Value::List { vals, .. } => {
            let lengths = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`bytes length` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    Ok(Value::int(val.len() as i64, value_span))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(lengths, value_span))
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes length` in a compile-time global initializer requires binary or list<binary> input",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bytes_at_call_range(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantMaybeOpenRange, LabeledError> {
    let mut range_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if range_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes at` accepts exactly one range argument in compile-time global initializers; cell-path rest arguments are not supported",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`bytes at` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes at` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(range_expr) = range_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes at` requires exactly one range argument in compile-time global initializers",
                span,
            ),
        );
    };
    eval_supported_constant_range_argument(working_set, range_expr, env, "bytes at")
}

fn eval_supported_constant_bytes_at_external_range(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantMaybeOpenRange, LabeledError> {
    let mut range = None;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes at` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        if let Expr::GlobPattern(token, _) = &expr.expr
            && let Some(parsed_range) =
                eval_supported_constant_range_token(token, expr.span, "bytes at")?
        {
            if range.replace(parsed_range).is_some() {
                return Err(LabeledError::new(
                    "Unsupported annotated mutable global initializer",
                )
                .with_label(
                    "`bytes at` accepts exactly one range argument in compile-time global initializers; cell-path rest arguments are not supported",
                    expr.span,
                ));
            }
            continue;
        }
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let parsed_range = eval_supported_constant_range_value(value, expr.span, "bytes at")?;
        if range.replace(parsed_range).is_some() {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes at` accepts exactly one range argument in compile-time global initializers; cell-path rest arguments are not supported",
                    expr.span,
                ));
        }
    }

    range.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`bytes at` requires exactly one range argument in compile-time global initializers",
            span,
        )
    })
}

fn eval_supported_constant_bytes_at(
    input: Option<Value>,
    range: ConstantMaybeOpenRange,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes at", input, span)?;
    let value_span = value.span();
    match value {
        Value::Binary { val, .. } => Ok(Value::binary(
            eval_supported_constant_bytes_slice(val, range),
            value_span,
        )),
        Value::List { vals, .. } => {
            let sliced = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`bytes at` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    Ok(Value::binary(
                        eval_supported_constant_bytes_slice(val, range),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(sliced, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes at` in a compile-time global initializer requires binary or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bytes_slice(input: Vec<u8>, range: ConstantMaybeOpenRange) -> Vec<u8> {
    let (start, end) = eval_supported_constant_string_range_bounds(range, input.len());
    input[start..end].to_vec()
}

#[derive(Clone)]
struct ConstantBytesAddArgs {
    data: Vec<u8>,
    index: i64,
    from_end: bool,
}

fn eval_supported_constant_bytes_add_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesAddArgs, LabeledError> {
    let mut data_expr = None;
    let mut index = None;
    let mut from_end = false;

    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if data_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes add` accepts exactly one binary data argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "end" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes add --end` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    if from_end {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes add` accepts --end at most once in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    from_end = true;
                }
                "index" => {
                    let Some(index_expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes add --index` requires a compile-time integer value in global initializers",
                            arg.span(),
                        ));
                    };
                    if index
                        .replace(eval_supported_constant_bytes_add_index_arg(
                            working_set,
                            index_expr,
                            env,
                            false,
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes add` accepts --index at most once in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes add` supports only --end and --index in compile-time global initializers",
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes add` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(data_expr) = data_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes add` requires exactly one binary data argument in compile-time global initializers",
                span,
            ),
        );
    };
    let data = eval_supported_constant_binary_argument(working_set, data_expr, env, "bytes add")?;
    let index = index.unwrap_or(0);
    eval_supported_constant_bytes_add_validate_index(index, span)?;

    Ok(ConstantBytesAddArgs {
        data,
        index,
        from_end,
    })
}

fn eval_supported_constant_bytes_add_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesAddArgs, LabeledError> {
    let mut data_expr = None;
    let mut index = None;
    let mut from_end = false;
    let mut arg_index = 0usize;

    while arg_index < args.len() {
        let arg = &args[arg_index];
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes add` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };

        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } if val == "--end" => {
                if from_end {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bytes add` accepts --end at most once in compile-time global initializers",
                        expr.span,
                    ));
                }
                from_end = true;
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val == "--index" => {
                let Some(next_arg) = args.get(arg_index + 1) else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bytes add --index` requires a compile-time integer value in global initializers",
                        expr.span,
                    ));
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bytes add --index` cannot use spread syntax in compile-time global initializers",
                        next_arg.expr().span,
                    ));
                };
                if index
                    .replace(eval_supported_constant_bytes_add_index_arg(
                        working_set,
                        next_expr,
                        env,
                        true,
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bytes add` accepts --index at most once in compile-time global initializers",
                        expr.span,
                    ));
                }
                arg_index += 1;
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--index=") => {
                let raw = val
                    .split_once('=')
                    .map(|(_, value)| value)
                    .expect("starts_with --index= prechecked");
                let parsed = raw.parse::<i64>().map_err(|_| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes add --index` requires a compile-time integer value in global initializers",
                            expr.span,
                        )
                })?;
                if index.replace(parsed).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bytes add` accepts --index at most once in compile-time global initializers",
                        expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--") => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes add` supports only --end and --index in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => {
                if data_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes add` accepts exactly one binary data argument in compile-time global initializers",
                            expr.span,
                        ));
                }
            }
        }

        arg_index += 1;
    }

    let Some(data_expr) = data_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes add` requires exactly one binary data argument in compile-time global initializers",
                span,
            ),
        );
    };
    let data = eval_supported_constant_binary_argument(working_set, data_expr, env, "bytes add")?;
    let index = index.unwrap_or(0);
    eval_supported_constant_bytes_add_validate_index(index, span)?;

    Ok(ConstantBytesAddArgs {
        data,
        index,
        from_end,
    })
}

fn eval_supported_constant_bytes_add_index_arg(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    parse_string: bool,
) -> Result<i64, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Int { val, .. } => Ok(val),
        Value::String { val, .. } | Value::Glob { val, .. } if parse_string => {
            val.parse::<i64>().map_err(|_| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`bytes add --index` requires a compile-time integer value in global initializers",
                    expr.span,
                )
            })
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes add --index` requires a compile-time integer value in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bytes_add_validate_index(
    index: i64,
    span: Span,
) -> Result<(), LabeledError> {
    if index < 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes add --index` requires a non-negative integer in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(())
}

fn eval_supported_constant_bytes_add(
    input: Option<Value>,
    args: ConstantBytesAddArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    eval_supported_constant_bytes_transform_items("bytes add", input, span, |bytes| {
        eval_supported_constant_add_bytes(bytes, &args)
    })
}

fn eval_supported_constant_add_bytes(input: Vec<u8>, args: &ConstantBytesAddArgs) -> Vec<u8> {
    let index = usize::try_from(args.index)
        .expect("bytes add index is validated as non-negative before use");
    let insert_at = if args.from_end {
        input.len().saturating_sub(index)
    } else {
        index.min(input.len())
    };

    let mut output = Vec::with_capacity(input.len().saturating_add(args.data.len()));
    output.extend_from_slice(&input[..insert_at]);
    output.extend_from_slice(&args.data);
    output.extend_from_slice(&input[insert_at..]);
    output
}

fn eval_supported_constant_bytes_build_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Vec<u8>, LabeledError> {
    let mut bytes = Vec::new();
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                eval_supported_constant_bytes_build_extend_arg(working_set, expr, env, &mut bytes)?;
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`bytes build` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes build` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }
    Ok(bytes)
}

fn eval_supported_constant_bytes_build_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Vec<u8>, LabeledError> {
    let mut bytes = Vec::new();
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes build` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        eval_supported_constant_bytes_build_extend_arg(working_set, expr, env, &mut bytes)?;
    }
    Ok(bytes)
}

fn eval_supported_constant_bytes_build_extend_arg(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    bytes: &mut Vec<u8>,
) -> Result<(), LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Binary { val, .. } => bytes.extend(val),
        Value::String { val, .. } | Value::Glob { val, .. }
            if eval_supported_constant_binary_token(&val).is_some() =>
        {
            bytes.extend(
                eval_supported_constant_binary_token(&val)
                    .expect("binary token parser prechecked")
                    .map_err(|err| {
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!("`bytes build` requires a valid binary literal: {err}"),
                                expr.span,
                            )
                    })?,
            );
        }
        Value::Int { val, .. } => {
            let byte = u8::try_from(val).map_err(|_| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`bytes build` byte integer {val} is out of range 0..255"),
                    expr.span,
                )
            })?;
            bytes.push(byte);
        }
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bytes build` arguments must be compile-time binary values or byte integers in global initializers; got {}",
                        other.get_type()
                    ),
                    expr.span,
                ),
            );
        }
    }
    Ok(())
}

fn eval_supported_constant_bytes_build(
    input: Option<Value>,
    bytes: Vec<u8>,
    span: Span,
) -> Result<Value, LabeledError> {
    if input.is_some() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes build` does not accept pipeline input in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(Value::binary(bytes, span))
}

fn eval_supported_constant_bytes_collect_call_separator(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Option<Vec<u8>>, LabeledError> {
    let mut separator_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if separator_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes collect` accepts at most one binary separator argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`bytes collect` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes collect` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    separator_expr
        .map(|expr| {
            eval_supported_constant_binary_argument(working_set, expr, env, "bytes collect")
        })
        .transpose()
}

fn eval_supported_constant_bytes_collect_external_separator(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Option<Vec<u8>>, LabeledError> {
    let separator_expr = match args {
        [] => return Ok(None),
        [arg] => {
            let ExternalArgument::Regular(expr) = arg else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes collect` separator cannot use spread syntax in compile-time global initializers",
                        arg.expr().span,
                    ));
            };
            expr
        }
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`bytes collect` accepts at most one binary separator argument in compile-time global initializers",
                    span,
                ),
            );
        }
    };
    eval_supported_constant_binary_argument(working_set, separator_expr, env, "bytes collect")
        .map(Some)
}

fn eval_supported_constant_bytes_collect(
    input: Option<Value>,
    separator: Option<Vec<u8>>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes collect", input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes collect` in a compile-time global initializer requires list<binary> input; got {}",
                    value.get_type()
                ),
                span,
            ),
        );
    };

    let mut output = Vec::new();
    for (index, value) in vals.into_iter().enumerate() {
        let Value::Binary { val, .. } = value else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bytes collect` requires binary list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        if index > 0 {
            if let Some(separator) = &separator {
                output.extend(separator);
            }
        }
        output.extend(val);
    }
    Ok(Value::binary(output, value_span))
}

fn eval_supported_constant_bytes_reverse(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes reverse", input, span)?;
    let value_span = value.span();
    match value {
        Value::Binary { mut val, .. } => {
            val.reverse();
            Ok(Value::binary(val, value_span))
        }
        Value::List { vals, .. } => {
            let reversed = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { mut val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`bytes reverse` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    val.reverse();
                    Ok(Value::binary(val, value_span))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(reversed, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes reverse` in a compile-time global initializer requires binary or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_binary_argument(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    cmd_name: &str,
) -> Result<Vec<u8>, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Binary { val, .. } => Ok(val),
        Value::String { val, .. } | Value::Glob { val, .. }
            if eval_supported_constant_binary_token(&val).is_some() =>
        {
            eval_supported_constant_binary_token(&val)
                .expect("binary token parser prechecked")
                .map_err(|err| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!("`{cmd_name}` requires a valid binary literal: {err}"),
                            expr.span,
                        )
                })
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` argument must be a compile-time binary value in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_binary_token(token: &str) -> Option<Result<Vec<u8>, String>> {
    let inner = token
        .strip_prefix("0x[")
        .or_else(|| token.strip_prefix("0X["))?
        .strip_suffix(']')?;
    let hex = inner
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '_')
        .collect::<String>();
    if hex.is_empty() {
        return Some(Ok(Vec::new()));
    }
    if hex.len() % 2 != 0 {
        return Some(Err(
            "hex byte sequence must contain an even number of digits".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16)
            .map_err(|_| format!("invalid hex byte '{}'", &hex[index..index + 2]));
        match byte {
            Ok(byte) => bytes.push(byte),
            Err(err) => return Some(Err(err)),
        }
    }
    Some(Ok(bytes))
}

fn eval_supported_constant_bytes_predicate_call_pattern(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Vec<u8>, LabeledError> {
    let mut pattern_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if pattern_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts exactly one binary pattern argument in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    let Some(pattern_expr) = pattern_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` accepts exactly one binary pattern argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };
    eval_supported_constant_binary_argument(working_set, pattern_expr, env, cmd_name)
}

fn eval_supported_constant_bytes_predicate_external_pattern(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Vec<u8>, LabeledError> {
    let [pattern_arg] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` accepts exactly one binary pattern argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };

    let ExternalArgument::Regular(pattern_expr) = pattern_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` pattern argument cannot use spread syntax in compile-time global initializers"
                ),
                pattern_arg.expr().span,
            ),
        );
    };
    eval_supported_constant_binary_argument(working_set, pattern_expr, env, cmd_name)
}

fn eval_supported_constant_bytes_predicate(
    cmd_name: &str,
    input: Option<Value>,
    pattern: Vec<u8>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    let matches = |bytes: &[u8]| {
        if cmd_name == "bytes starts-with" {
            bytes.starts_with(&pattern)
        } else {
            bytes.ends_with(&pattern)
        }
    };

    match value {
        Value::Binary { val, .. } => Ok(Value::bool(matches(&val), value_span)),
        Value::List { vals, .. } => {
            let matched = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name}` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    Ok(Value::bool(matches(&val), value_span))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(matched, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires binary or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

#[derive(Clone)]
struct ConstantBytesIndexOfArgs {
    pattern: Vec<u8>,
    search_from_end: bool,
    all_matches: bool,
}

fn eval_supported_constant_bytes_index_of_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesIndexOfArgs, LabeledError> {
    let mut pattern_expr = None;
    let mut search_from_end = false;
    let mut all_matches = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if pattern_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes index-of` accepts exactly one binary pattern argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes index-of` flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                }
                match named.0.item.as_str() {
                    "all" => all_matches = true,
                    "end" => search_from_end = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes index-of` supports only --all and --end in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes index-of` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(pattern_expr) = pattern_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes index-of` requires exactly one binary pattern argument in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes index-of")?;
    eval_supported_constant_validate_bytes_index_of_pattern(&pattern, pattern_expr.span)?;

    Ok(ConstantBytesIndexOfArgs {
        pattern,
        search_from_end,
        all_matches,
    })
}

fn eval_supported_constant_bytes_index_of_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesIndexOfArgs, LabeledError> {
    let mut pattern_expr = None;
    let mut search_from_end = false;
    let mut all_matches = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes index-of` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--all" || val == "--end" =>
            {
                if val == "--all" {
                    all_matches = true;
                } else {
                    search_from_end = true;
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--") => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes index-of` supports only --all and --end in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => {
                if pattern_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes index-of` accepts exactly one binary pattern argument in compile-time global initializers",
                            expr.span,
                        ));
                }
            }
        }
    }

    let Some(pattern_expr) = pattern_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes index-of` requires exactly one binary pattern argument in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes index-of")?;
    eval_supported_constant_validate_bytes_index_of_pattern(&pattern, pattern_expr.span)?;

    Ok(ConstantBytesIndexOfArgs {
        pattern,
        search_from_end,
        all_matches,
    })
}

fn eval_supported_constant_validate_bytes_index_of_pattern(
    pattern: &[u8],
    span: Span,
) -> Result<(), LabeledError> {
    if pattern.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes index-of` requires a non-empty binary pattern in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(())
}

fn eval_supported_constant_bytes_index_of(
    input: Option<Value>,
    args: ConstantBytesIndexOfArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes index-of", input, span)?;
    let value_span = value.span();
    match value {
        Value::Binary { val, .. } => {
            if args.all_matches {
                Ok(Value::list(
                    eval_supported_constant_bytes_all_match_offsets(&val, &args)
                        .into_iter()
                        .map(|offset| Value::int(offset, value_span))
                        .collect(),
                    value_span,
                ))
            } else {
                Ok(Value::int(
                    eval_supported_constant_bytes_match_offset(&val, &args),
                    value_span,
                ))
            }
        }
        Value::List { vals, .. } => {
            let offsets = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`bytes index-of` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    if args.all_matches {
                        Ok(Value::list(
                            eval_supported_constant_bytes_all_match_offsets(&val, &args)
                                .into_iter()
                                .map(|offset| Value::int(offset, value_span))
                                .collect(),
                            value_span,
                        ))
                    } else {
                        Ok(Value::int(
                            eval_supported_constant_bytes_match_offset(&val, &args),
                            value_span,
                        ))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(offsets, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes index-of` in a compile-time global initializer requires binary or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bytes_match_offset(
    input: &[u8],
    args: &ConstantBytesIndexOfArgs,
) -> i64 {
    if args.pattern.len() > input.len() {
        return -1;
    }

    let last_offset = input.len() - args.pattern.len();
    let offsets: Box<dyn Iterator<Item = usize>> = if args.search_from_end {
        Box::new((0..=last_offset).rev())
    } else {
        Box::new(0..=last_offset)
    };
    offsets
        .filter(|offset| input[*offset..*offset + args.pattern.len()] == args.pattern)
        .map(|offset| offset as i64)
        .next()
        .unwrap_or(-1)
}

fn eval_supported_constant_bytes_all_match_offsets(
    input: &[u8],
    args: &ConstantBytesIndexOfArgs,
) -> Vec<i64> {
    if args.pattern.len() > input.len() {
        return Vec::new();
    }

    if args.search_from_end {
        eval_supported_constant_bytes_all_match_offsets_from_end(input, &args.pattern)
    } else {
        eval_supported_constant_bytes_all_match_offsets_from_start(input, &args.pattern)
    }
}

fn eval_supported_constant_bytes_all_match_offsets_from_start(
    input: &[u8],
    pattern: &[u8],
) -> Vec<i64> {
    let mut offsets = Vec::new();
    let mut offset = 0;
    while offset + pattern.len() <= input.len() {
        if input[offset..offset + pattern.len()] == *pattern {
            offsets.push(offset as i64);
            offset += pattern.len();
        } else {
            offset += 1;
        }
    }
    offsets
}

fn eval_supported_constant_bytes_all_match_offsets_from_end(
    input: &[u8],
    pattern: &[u8],
) -> Vec<i64> {
    let mut offsets = Vec::new();
    let mut offset = input.len() - pattern.len();
    loop {
        if input[offset..offset + pattern.len()] == *pattern {
            offsets.push(offset as i64);
            if offset < pattern.len() {
                break;
            }
            offset -= pattern.len();
        } else if offset == 0 {
            break;
        } else {
            offset -= 1;
        }
    }
    offsets
}

#[derive(Clone)]
struct ConstantBytesRemoveArgs {
    pattern: Vec<u8>,
    remove_all: bool,
    search_from_end: bool,
}

fn eval_supported_constant_bytes_remove_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesRemoveArgs, LabeledError> {
    let mut pattern_expr = None;
    let mut remove_all = false;
    let mut search_from_end = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if pattern_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes remove` accepts exactly one binary pattern argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes remove` flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                }
                match named.0.item.as_str() {
                    "all" => remove_all = true,
                    "end" => search_from_end = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bytes remove` supports only --all and --end in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes remove` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(pattern_expr) = pattern_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes remove` requires exactly one binary pattern argument in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes remove")?;
    eval_supported_constant_validate_bytes_pattern("bytes remove", &pattern, pattern_expr.span)?;

    Ok(ConstantBytesRemoveArgs {
        pattern,
        remove_all,
        search_from_end,
    })
}

fn eval_supported_constant_bytes_remove_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesRemoveArgs, LabeledError> {
    let mut pattern_expr = None;
    let mut remove_all = false;
    let mut search_from_end = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes remove` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--all" || val == "--end" =>
            {
                if val == "--all" {
                    remove_all = true;
                } else {
                    search_from_end = true;
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--") => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes remove` supports only --all and --end in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => {
                if pattern_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes remove` accepts exactly one binary pattern argument in compile-time global initializers",
                            expr.span,
                        ));
                }
            }
        }
    }

    let Some(pattern_expr) = pattern_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes remove` requires exactly one binary pattern argument in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes remove")?;
    eval_supported_constant_validate_bytes_pattern("bytes remove", &pattern, pattern_expr.span)?;

    Ok(ConstantBytesRemoveArgs {
        pattern,
        remove_all,
        search_from_end,
    })
}

fn eval_supported_constant_bytes_remove(
    input: Option<Value>,
    args: ConstantBytesRemoveArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    eval_supported_constant_bytes_transform_items("bytes remove", input, span, |bytes| {
        eval_supported_constant_remove_bytes(bytes, &args)
    })
}

fn eval_supported_constant_remove_bytes(input: Vec<u8>, args: &ConstantBytesRemoveArgs) -> Vec<u8> {
    if args.remove_all {
        return eval_supported_constant_replace_all_bytes(input, &args.pattern, &[]);
    }
    let index_args = ConstantBytesIndexOfArgs {
        pattern: args.pattern.clone(),
        search_from_end: args.search_from_end,
        all_matches: false,
    };
    let offset = eval_supported_constant_bytes_match_offset(&input, &index_args);
    if offset < 0 {
        return input;
    }
    eval_supported_constant_replace_bytes_at(input, offset as usize, &args.pattern, &[])
}

#[derive(Clone)]
struct ConstantBytesReplaceArgs {
    pattern: Vec<u8>,
    replacement: Vec<u8>,
    replace_all: bool,
}

fn eval_supported_constant_bytes_replace_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesReplaceArgs, LabeledError> {
    let mut positional = Vec::new();
    let mut replace_all = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => positional.push(expr),
            nu_protocol::ast::Argument::Named(named) => {
                if named.0.item != "all" || named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes replace` accepts only the --all flag in compile-time global initializers",
                            arg.span(),
                        ));
                }
                replace_all = true;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes replace` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let [pattern_expr, replacement_expr] = positional.as_slice() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes replace` requires exactly one binary pattern and one binary replacement in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes replace")?;
    eval_supported_constant_validate_bytes_pattern("bytes replace", &pattern, pattern_expr.span)?;
    let replacement = eval_supported_constant_binary_argument(
        working_set,
        replacement_expr,
        env,
        "bytes replace",
    )?;

    Ok(ConstantBytesReplaceArgs {
        pattern,
        replacement,
        replace_all,
    })
}

fn eval_supported_constant_bytes_replace_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBytesReplaceArgs, LabeledError> {
    let mut positional = Vec::new();
    let mut replace_all = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bytes replace` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } if val == "--all" => {
                replace_all = true;
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--") => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes replace` accepts only the --all flag in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => positional.push(expr),
        }
    }

    let [pattern_expr, replacement_expr] = positional.as_slice() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes replace` requires exactly one binary pattern and one binary replacement in compile-time global initializers",
                span,
            ),
        );
    };
    let pattern =
        eval_supported_constant_binary_argument(working_set, pattern_expr, env, "bytes replace")?;
    eval_supported_constant_validate_bytes_pattern("bytes replace", &pattern, pattern_expr.span)?;
    let replacement = eval_supported_constant_binary_argument(
        working_set,
        replacement_expr,
        env,
        "bytes replace",
    )?;

    Ok(ConstantBytesReplaceArgs {
        pattern,
        replacement,
        replace_all,
    })
}

fn eval_supported_constant_bytes_replace(
    input: Option<Value>,
    args: ConstantBytesReplaceArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    eval_supported_constant_bytes_transform_items("bytes replace", input, span, |bytes| {
        eval_supported_constant_replace_bytes(bytes, &args)
    })
}

fn eval_supported_constant_replace_bytes(
    input: Vec<u8>,
    args: &ConstantBytesReplaceArgs,
) -> Vec<u8> {
    if args.replace_all {
        return eval_supported_constant_replace_all_bytes(input, &args.pattern, &args.replacement);
    }
    let index_args = ConstantBytesIndexOfArgs {
        pattern: args.pattern.clone(),
        search_from_end: false,
        all_matches: false,
    };
    let offset = eval_supported_constant_bytes_match_offset(&input, &index_args);
    if offset < 0 {
        return input;
    }
    eval_supported_constant_replace_bytes_at(
        input,
        offset as usize,
        &args.pattern,
        &args.replacement,
    )
}

fn eval_supported_constant_validate_bytes_pattern(
    cmd_name: &str,
    pattern: &[u8],
    span: Span,
) -> Result<(), LabeledError> {
    if pattern.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` requires a non-empty binary pattern in compile-time global initializers"),
                span,
            ),
        );
    }
    Ok(())
}

fn eval_supported_constant_bytes_transform_items<F>(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
    mut transform: F,
) -> Result<Value, LabeledError>
where
    F: FnMut(Vec<u8>) -> Vec<u8>,
{
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::Binary { val, .. } => Ok(Value::binary(transform(val), value_span)),
        Value::List { vals, .. } => {
            let transformed = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Binary { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name}` requires binary list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    Ok(Value::binary(transform(val), value_span))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(transformed, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires binary or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_replace_all_bytes(
    input: Vec<u8>,
    pattern: &[u8],
    replacement: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while offset + pattern.len() <= input.len() {
        if input[offset..offset + pattern.len()] == *pattern {
            output.extend(replacement);
            offset += pattern.len();
        } else {
            output.push(input[offset]);
            offset += 1;
        }
    }
    output.extend_from_slice(&input[offset..]);
    output
}

fn eval_supported_constant_replace_bytes_at(
    input: Vec<u8>,
    offset: usize,
    pattern: &[u8],
    replacement: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() - pattern.len() + replacement.len());
    output.extend_from_slice(&input[..offset]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&input[offset + pattern.len()..]);
    output
}

fn eval_supported_constant_bytes_split_call_separator(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Vec<u8>, LabeledError> {
    let mut separator_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if separator_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bytes split` accepts exactly one separator argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`bytes split` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bytes split` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(separator_expr) = separator_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes split` requires exactly one separator argument in compile-time global initializers",
                span,
            ),
        );
    };
    eval_supported_constant_bytes_split_separator(working_set, separator_expr, env)
}

fn eval_supported_constant_bytes_split_external_separator(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Vec<u8>, LabeledError> {
    let [separator_arg] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes split` requires exactly one separator argument in compile-time global initializers",
                span,
            ),
        );
    };
    let ExternalArgument::Regular(separator_expr) = separator_arg else {
        return Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                "`bytes split` separator cannot use spread syntax in compile-time global initializers",
                separator_arg.expr().span,
            ));
    };
    eval_supported_constant_bytes_split_separator(working_set, separator_expr, env)
}

fn eval_supported_constant_bytes_split_separator(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Vec<u8>, LabeledError> {
    if let Expr::GlobPattern(token, _) = &expr.expr
        && let Some(bytes) = eval_supported_constant_binary_token(token)
    {
        let bytes = bytes.map_err(|err| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`bytes split` requires a valid binary separator literal: {err}"),
                expr.span,
            )
        })?;
        eval_supported_constant_validate_bytes_pattern("bytes split", &bytes, expr.span)?;
        return Ok(bytes);
    }

    let separator = match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Binary { val, .. } => val,
        Value::String { val, .. } | Value::Glob { val, .. } => val.into_bytes(),
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bytes split` separator must be a compile-time binary or string value in global initializers; got {}",
                        other.get_type()
                    ),
                    expr.span,
                ),
            );
        }
    };
    eval_supported_constant_validate_bytes_pattern("bytes split", &separator, expr.span)?;
    Ok(separator)
}

fn eval_supported_constant_bytes_split(
    input: Option<Value>,
    separator: Vec<u8>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("bytes split", input, span)?;
    let value_span = value.span();
    let Value::Binary { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes split` in a compile-time global initializer requires binary input; got {}",
                    value.get_type()
                ),
                span,
            ),
        );
    };
    let chunks = eval_supported_constant_split_bytes(val, &separator)
        .into_iter()
        .map(|chunk| Value::binary(chunk, value_span))
        .collect();
    Ok(Value::list(chunks, value_span))
}

fn eval_supported_constant_split_bytes(input: Vec<u8>, separator: &[u8]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut offset = 0;
    while offset + separator.len() <= input.len() {
        if input[offset..offset + separator.len()] == *separator {
            chunks.push(input[start..offset].to_vec());
            offset += separator.len();
            start = offset;
        } else {
            offset += 1;
        }
    }
    chunks.push(input[start..].to_vec());
    chunks
}

#[derive(Clone, Copy)]
enum ConstantBitsBinaryEndian {
    Little,
    Big,
}

#[derive(Clone)]
enum ConstantBitsBinaryTarget {
    Int(i64),
    Binary(Vec<u8>),
}

#[derive(Clone)]
struct ConstantBitsBinaryArgs {
    target: ConstantBitsBinaryTarget,
    endian: ConstantBitsBinaryEndian,
}

fn eval_supported_constant_bits_binary_call_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsBinaryArgs, LabeledError> {
    let mut target_expr = None;
    let mut endian = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if target_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts exactly one integer or binary target argument in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "endian" | "e" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name} --endian` requires a value in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                    };
                    let next = eval_supported_constant_bits_binary_endian_arg(
                        working_set,
                        cmd_name,
                        expr,
                        env,
                    )?;
                    if endian.replace(next).is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts only one --endian value in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` supports only --endian in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    let Some(target_expr) = target_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one integer or binary target argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };

    Ok(ConstantBitsBinaryArgs {
        target: eval_supported_constant_bits_binary_target(
            working_set,
            cmd_name,
            target_expr,
            env,
        )?,
        endian: endian.unwrap_or_else(eval_supported_constant_native_bits_binary_endian),
    })
}

fn eval_supported_constant_bits_binary_external_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsBinaryArgs, LabeledError> {
    let mut target_expr = None;
    let mut endian = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                    ),
                    arg.expr().span,
                ));
        };

        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--endian" || val == "-e" =>
            {
                index += 1;
                let Some(next_arg) = args.get(index) else {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`{cmd_name} --endian` requires a value in compile-time global initializers"
                                ),
                                expr.span,
                            ),
                    );
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name} --endian` value cannot use spread syntax in compile-time global initializers"
                            ),
                            next_arg.expr().span,
                        ));
                };
                let next = eval_supported_constant_bits_binary_endian_arg(
                    working_set,
                    cmd_name,
                    next_expr,
                    env,
                )?;
                if endian.replace(next).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` accepts only one --endian value in compile-time global initializers"
                        ),
                        next_expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with("--endian=") => {
                let raw = val
                    .split_once('=')
                    .map(|(_, value)| value)
                    .expect("starts_with --endian= prechecked");
                let next =
                    eval_supported_constant_bits_binary_endian_value(cmd_name, raw, expr.span)?;
                if endian.replace(next).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` accepts only one --endian value in compile-time global initializers"
                        ),
                        expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with('-') => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` supports only --endian in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
            _ => {
                if target_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts exactly one integer or binary target argument in compile-time global initializers"
                            ),
                            expr.span,
                        ));
                }
            }
        }
        index += 1;
    }

    let Some(target_expr) = target_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one integer or binary target argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };

    Ok(ConstantBitsBinaryArgs {
        target: eval_supported_constant_bits_binary_target(
            working_set,
            cmd_name,
            target_expr,
            env,
        )?,
        endian: endian.unwrap_or_else(eval_supported_constant_native_bits_binary_endian),
    })
}

fn eval_supported_constant_bits_binary_endian_arg(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantBitsBinaryEndian, LabeledError> {
    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    let raw = match value {
        Value::String { val, .. } | Value::Glob { val, .. } => val,
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name} --endian` requires a compile-time string value in global initializers; got {}",
                        other.get_type()
                    ),
                    expr.span,
                ),
            );
        }
    };
    eval_supported_constant_bits_binary_endian_value(cmd_name, &raw, expr.span)
}

fn eval_supported_constant_bits_binary_endian_value(
    cmd_name: &str,
    raw: &str,
    span: Span,
) -> Result<ConstantBitsBinaryEndian, LabeledError> {
    match raw {
        "native" => Ok(eval_supported_constant_native_bits_binary_endian()),
        "little" => Ok(ConstantBitsBinaryEndian::Little),
        "big" => Ok(ConstantBitsBinaryEndian::Big),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name} --endian` supports only native, little, or big in compile-time global initializers; got {raw:?}"
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_native_bits_binary_endian() -> ConstantBitsBinaryEndian {
    if cfg!(target_endian = "big") {
        ConstantBitsBinaryEndian::Big
    } else {
        ConstantBitsBinaryEndian::Little
    }
}

fn eval_supported_constant_bits_binary_target(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantBitsBinaryTarget, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Int { val, .. } => Ok(ConstantBitsBinaryTarget::Int(val)),
        Value::Binary { val, .. } => Ok(ConstantBitsBinaryTarget::Binary(val)),
        Value::String { val, .. } | Value::Glob { val, .. }
            if eval_supported_constant_binary_token(&val).is_some() =>
        {
            Ok(ConstantBitsBinaryTarget::Binary(
                eval_supported_constant_binary_token(&val)
                    .expect("binary token parser prechecked")
                    .map_err(|err| {
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!("`{cmd_name}` requires a valid binary literal: {err}"),
                                expr.span,
                            )
                    })?,
            ))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` target argument must be a compile-time integer or binary value in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_binary(
    cmd_name: &str,
    input: Option<Value>,
    args: ConstantBitsBinaryArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::Int { val, .. } => match args.target {
            ConstantBitsBinaryTarget::Int(rhs) => Ok(Value::int(
                eval_supported_constant_bits_binary_int_output(cmd_name, val, rhs),
                value_span,
            )),
            ConstantBitsBinaryTarget::Binary(_) => Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires input and target argument to both be integers or both be binaries in compile-time global initializers"
                    ),
                    span,
                ),
            ),
        },
        Value::Binary { val, .. } => match args.target {
            ConstantBitsBinaryTarget::Binary(rhs) => Ok(Value::binary(
                eval_supported_constant_bits_binary_bytes_output(
                    cmd_name,
                    &val,
                    &rhs,
                    args.endian,
                ),
                value_span,
            )),
            ConstantBitsBinaryTarget::Int(_) => Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires input and target argument to both be integers or both be binaries in compile-time global initializers"
                    ),
                    span,
                ),
            ),
        },
        Value::List { vals, .. } => eval_supported_constant_bits_binary_list(
            cmd_name,
            vals,
            args,
            value_span,
            span,
        ),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires integer, binary, list<int>, or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_binary_list(
    cmd_name: &str,
    vals: Vec<Value>,
    args: ConstantBitsBinaryArgs,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    let binary_list = vals
        .iter()
        .all(|value| matches!(value, Value::Binary { .. }))
        && (!vals.is_empty() || matches!(args.target, ConstantBitsBinaryTarget::Binary(_)));

    if binary_list {
        let ConstantBitsBinaryTarget::Binary(rhs) = args.target else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires a binary target argument for list<binary> input in compile-time global initializers"
                    ),
                    span,
                ),
            );
        };
        let output = vals
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let Value::Binary { val, .. } = value else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` requires binary list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
                };
                Ok(Value::binary(
                    eval_supported_constant_bits_binary_bytes_output(
                        cmd_name,
                        &val,
                        &rhs,
                        args.endian,
                    ),
                    value_span,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::list(output, value_span));
    }

    let ConstantBitsBinaryTarget::Int(rhs) = args.target else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires an integer target argument for list<int> input in compile-time global initializers"
                ),
                span,
            ),
        );
    };
    let output = vals
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let Value::Int { val, .. } = value else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` requires integer list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
            };
            Ok(Value::int(
                eval_supported_constant_bits_binary_int_output(cmd_name, val, rhs),
                value_span,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::list(output, value_span))
}

fn eval_supported_constant_bits_binary_int_output(cmd_name: &str, lhs: i64, rhs: i64) -> i64 {
    match cmd_name {
        "bits and" => lhs & rhs,
        "bits or" => lhs | rhs,
        "bits xor" => lhs ^ rhs,
        _ => unreachable!("validated bits binary command"),
    }
}

fn eval_supported_constant_bits_binary_byte_output(cmd_name: &str, lhs: u8, rhs: u8) -> u8 {
    match cmd_name {
        "bits and" => lhs & rhs,
        "bits or" => lhs | rhs,
        "bits xor" => lhs ^ rhs,
        _ => unreachable!("validated bits binary command"),
    }
}

fn eval_supported_constant_bits_binary_bytes_output(
    cmd_name: &str,
    lhs: &[u8],
    rhs: &[u8],
    endian: ConstantBitsBinaryEndian,
) -> Vec<u8> {
    let len = lhs.len().max(rhs.len());
    let mut output = Vec::with_capacity(len);
    match endian {
        ConstantBitsBinaryEndian::Little => {
            for index in 0..len {
                let lhs_byte = lhs.get(index).copied().unwrap_or(0);
                let rhs_byte = rhs.get(index).copied().unwrap_or(0);
                output.push(eval_supported_constant_bits_binary_byte_output(
                    cmd_name, lhs_byte, rhs_byte,
                ));
            }
        }
        ConstantBitsBinaryEndian::Big => {
            let lhs_padding = len.saturating_sub(lhs.len());
            let rhs_padding = len.saturating_sub(rhs.len());
            for index in 0..len {
                let lhs_byte = index
                    .checked_sub(lhs_padding)
                    .and_then(|lhs_index| lhs.get(lhs_index))
                    .copied()
                    .unwrap_or(0);
                let rhs_byte = index
                    .checked_sub(rhs_padding)
                    .and_then(|rhs_index| rhs.get(rhs_index))
                    .copied()
                    .unwrap_or(0);
                output.push(eval_supported_constant_bits_binary_byte_output(
                    cmd_name, lhs_byte, rhs_byte,
                ));
            }
        }
    }
    output
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstantBitsNotMode {
    Signed,
    Auto,
    Masked { mask: i64 },
}

const CONSTANT_BITS_NOT_UNSIGNED_I64_MASK: i64 = 0x7fff_ffff_ffff;

fn eval_supported_constant_bits_not_call_mode(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsNotMode, LabeledError> {
    let mut signed = false;
    let mut number_bytes = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "signed" | "s" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bits not --signed` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    signed = true;
                }
                "number-bytes" | "n" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bits not --number-bytes` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    let next =
                        eval_supported_constant_bits_not_number_bytes_arg(working_set, expr, env)?;
                    if number_bytes.replace((next, expr.span)).is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`bits not` accepts only one --number-bytes value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bits not` supports only --signed and --number-bytes in compile-time global initializers",
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bits not` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bits not` accepts no positional arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }

    eval_supported_constant_bits_not_mode(signed, number_bytes, span)
}

fn eval_supported_constant_bits_not_external_mode(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsNotMode, LabeledError> {
    let mut signed = false;
    let mut number_bytes = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`bits not` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--signed" || val == "-s" =>
            {
                signed = true;
            }
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--number-bytes" || val == "-n" =>
            {
                index += 1;
                let Some(next_arg) = args.get(index) else {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                "`bits not --number-bytes` requires a value in compile-time global initializers",
                                expr.span,
                            ),
                    );
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bits not --number-bytes` value cannot use spread syntax in compile-time global initializers",
                            next_arg.expr().span,
                        ));
                };
                let next =
                    eval_supported_constant_bits_not_number_bytes_arg(working_set, next_expr, env)?;
                if number_bytes.replace((next, next_expr.span)).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bits not` accepts only one --number-bytes value in compile-time global initializers",
                        next_expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. }
                if val.starts_with("--number-bytes=") =>
            {
                let raw = val
                    .split_once('=')
                    .map(|(_, value)| value)
                    .expect("starts_with --number-bytes= prechecked");
                let next = raw.parse::<i64>().map_err(|_| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`bits not --number-bytes` requires a compile-time integer value in global initializers",
                            expr.span,
                        )
                })?;
                if number_bytes.replace((next, expr.span)).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`bits not` accepts only one --number-bytes value in compile-time global initializers",
                        expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with('-') => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bits not` supports only --signed and --number-bytes in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`bits not` accepts no positional arguments in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
        index += 1;
    }

    eval_supported_constant_bits_not_mode(signed, number_bytes, span)
}

fn eval_supported_constant_bits_not_number_bytes_arg(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<i64, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Int { val, .. } => Ok(val),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bits not --number-bytes` requires a compile-time integer value in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_not_mode(
    signed: bool,
    number_bytes: Option<(i64, Span)>,
    _span: Span,
) -> Result<ConstantBitsNotMode, LabeledError> {
    if signed {
        if let Some((number_bytes, number_bytes_span)) = number_bytes
            && !matches!(number_bytes, 1 | 2 | 4 | 8)
        {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bits not --signed` supports --number-bytes 1, 2, 4, or 8 in compile-time global initializers; got {number_bytes}"
                    ),
                    number_bytes_span,
                ),
            );
        }
        return Ok(ConstantBitsNotMode::Signed);
    }

    let Some((number_bytes, number_bytes_span)) = number_bytes else {
        return Ok(ConstantBitsNotMode::Auto);
    };
    let mask = match number_bytes {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        8 => CONSTANT_BITS_NOT_UNSIGNED_I64_MASK,
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bits not` masked integer mode supports --number-bytes 1, 2, 4, or 8 in compile-time global initializers; got {number_bytes}"
                    ),
                    number_bytes_span,
                ),
            );
        }
    };
    Ok(ConstantBitsNotMode::Masked { mask })
}

fn eval_supported_constant_bits_not(
    cmd_name: &str,
    input: Option<Value>,
    mode: ConstantBitsNotMode,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::Int { val, .. } => Ok(Value::int(
            eval_supported_constant_bits_not_int_output(val, mode),
            value_span,
        )),
        Value::Binary { val, .. } => {
            Ok(Value::binary(
                eval_supported_constant_bits_not_binary_output(&val),
                value_span,
            ))
        }
        Value::List { vals, .. } => {
            eval_supported_constant_bits_not_list(vals, mode, value_span, span)
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bits not` in a compile-time global initializer requires integer, binary, list<int>, or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_not_list(
    vals: Vec<Value>,
    mode: ConstantBitsNotMode,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    if !vals.is_empty()
        && vals
            .iter()
            .all(|value| matches!(value, Value::Binary { .. }))
    {
        let output = vals
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let Value::Binary { val, .. } = value else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`bits not` requires binary list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
                };
                Ok(Value::binary(
                    eval_supported_constant_bits_not_binary_output(&val),
                    value_span,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::list(output, value_span));
    }

    let output = vals
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let Value::Int { val, .. } = value else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`bits not` requires integer list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
            };
            Ok(Value::int(
                eval_supported_constant_bits_not_int_output(val, mode),
                value_span,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::list(output, value_span))
}

fn eval_supported_constant_bits_not_int_output(input: i64, mode: ConstantBitsNotMode) -> i64 {
    match mode {
        ConstantBitsNotMode::Signed => !input,
        ConstantBitsNotMode::Auto => eval_supported_constant_bits_not_auto_output(input),
        ConstantBitsNotMode::Masked { mask } => {
            if input < 0 {
                !input
            } else {
                (!input) & mask
            }
        }
    }
}

fn eval_supported_constant_bits_not_auto_output(input: i64) -> i64 {
    if input < 0 {
        return !input;
    }

    let mask = match input {
        0..=0xff => 0xff,
        0x100..=0xffff => 0xffff,
        0x1_0000..=0xffff_ffff => 0xffff_ffff,
        _ => CONSTANT_BITS_NOT_UNSIGNED_I64_MASK,
    };
    (!input) & mask
}

fn eval_supported_constant_bits_not_binary_output(input: &[u8]) -> Vec<u8> {
    input.iter().map(|byte| !byte).collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstantBitsShiftMode {
    SignedI64,
    UnsignedI64,
    FixedWidth { bits: i64, mask: i64, sign_bit: i64 },
    SignedFixedWidth { bits: i64, mask: i64, sign_bit: i64 },
}

#[derive(Clone, Copy)]
struct ConstantBitsShiftRotateArgs {
    count: i64,
    signed: bool,
    number_bytes: Option<(i64, Span)>,
}

#[derive(Clone, Copy)]
struct ConstantBitsShiftSpec {
    count: i64,
    mode: ConstantBitsShiftMode,
}

#[derive(Clone, Copy)]
struct ConstantBitsRotateSpec {
    count: i64,
    mode: ConstantBitsShiftMode,
}

fn eval_supported_constant_bits_shift_rotate_call_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsShiftRotateArgs, LabeledError> {
    let mut count_expr = None;
    let mut signed = false;
    let mut number_bytes = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if count_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires exactly one count argument in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "signed" | "s" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name} --signed` cannot receive a value in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                    }
                    signed = true;
                }
                "number-bytes" | "n" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name} --number-bytes` requires a value in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                    };
                    let next = eval_supported_constant_bits_shift_rotate_number_bytes_arg(
                        working_set,
                        cmd_name,
                        expr,
                        env,
                    )?;
                    if number_bytes.replace((next, expr.span)).is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts only one --number-bytes value in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` supports only --signed and --number-bytes in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    let Some(count_expr) = count_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one count argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };
    let count = eval_supported_constant_bits_shift_rotate_count_arg(
        working_set,
        cmd_name,
        count_expr,
        env,
    )?;

    Ok(ConstantBitsShiftRotateArgs {
        count,
        signed,
        number_bytes,
    })
}

fn eval_supported_constant_bits_shift_rotate_external_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantBitsShiftRotateArgs, LabeledError> {
    let mut count_expr = None;
    let mut signed = false;
    let mut number_bytes = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                    ),
                    arg.expr().span,
                ));
        };

        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--signed" || val == "-s" =>
            {
                signed = true;
            }
            Value::String { val, .. } | Value::Glob { val, .. }
                if val == "--number-bytes" || val == "-n" =>
            {
                index += 1;
                let Some(next_arg) = args.get(index) else {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`{cmd_name} --number-bytes` requires a value in compile-time global initializers"
                                ),
                                expr.span,
                            ),
                    );
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name} --number-bytes` value cannot use spread syntax in compile-time global initializers"
                            ),
                            next_arg.expr().span,
                        ));
                };
                let next = eval_supported_constant_bits_shift_rotate_number_bytes_arg(
                    working_set,
                    cmd_name,
                    next_expr,
                    env,
                )?;
                if number_bytes.replace((next, next_expr.span)).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` accepts only one --number-bytes value in compile-time global initializers"
                        ),
                        next_expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. }
                if val.starts_with("--number-bytes=") =>
            {
                let raw = val
                    .split_once('=')
                    .map(|(_, value)| value)
                    .expect("starts_with --number-bytes= prechecked");
                let next = raw.parse::<i64>().map_err(|_| {
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name} --number-bytes` requires a compile-time integer value in global initializers"
                            ),
                            expr.span,
                        )
                })?;
                if number_bytes.replace((next, expr.span)).is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` accepts only one --number-bytes value in compile-time global initializers"
                        ),
                        expr.span,
                    ));
                }
            }
            Value::String { val, .. } | Value::Glob { val, .. } if val.starts_with('-') => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` supports only --signed and --number-bytes in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
            _ => {
                if count_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires exactly one count argument in compile-time global initializers"
                            ),
                            expr.span,
                        ));
                }
            }
        }
        index += 1;
    }

    let Some(count_expr) = count_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one count argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };
    let count = eval_supported_constant_bits_shift_rotate_count_arg(
        working_set,
        cmd_name,
        count_expr,
        env,
    )?;

    Ok(ConstantBitsShiftRotateArgs {
        count,
        signed,
        number_bytes,
    })
}

fn eval_supported_constant_bits_shift_rotate_count_arg(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<i64, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Int { val, .. } => Ok(val),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` count argument must be a compile-time integer in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_shift_rotate_number_bytes_arg(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<i64, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::Int { val, .. } => Ok(val),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name} --number-bytes` requires a compile-time integer value in global initializers; got {}",
                    other.get_type()
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_fixed_width_mode(
    cmd_name: &str,
    number_bytes: i64,
    signed: bool,
    span: Span,
) -> Result<ConstantBitsShiftMode, LabeledError> {
    match (number_bytes, signed) {
        (1, false) => Ok(ConstantBitsShiftMode::FixedWidth {
            bits: 8,
            mask: 0xff,
            sign_bit: 0x80,
        }),
        (2, false) => Ok(ConstantBitsShiftMode::FixedWidth {
            bits: 16,
            mask: 0xffff,
            sign_bit: 0x8000,
        }),
        (4, false) => Ok(ConstantBitsShiftMode::FixedWidth {
            bits: 32,
            mask: 0xffff_ffff,
            sign_bit: 0x8000_0000,
        }),
        (8, false) => Ok(ConstantBitsShiftMode::UnsignedI64),
        (1, true) => Ok(ConstantBitsShiftMode::SignedFixedWidth {
            bits: 8,
            mask: 0xff,
            sign_bit: 0x80,
        }),
        (2, true) => Ok(ConstantBitsShiftMode::SignedFixedWidth {
            bits: 16,
            mask: 0xffff,
            sign_bit: 0x8000,
        }),
        (4, true) => Ok(ConstantBitsShiftMode::SignedFixedWidth {
            bits: 32,
            mask: 0xffff_ffff,
            sign_bit: 0x8000_0000,
        }),
        (8, true) => Ok(ConstantBitsShiftMode::SignedI64),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` integer mode supports --number-bytes 1, 2, 4, or 8 in compile-time global initializers; got {number_bytes}"
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_auto_width_mode(input: i64) -> ConstantBitsShiftMode {
    if input < 0 {
        if input >= i8::MIN as i64 {
            ConstantBitsShiftMode::FixedWidth {
                bits: 8,
                mask: 0xff,
                sign_bit: 0x80,
            }
        } else if input >= i16::MIN as i64 {
            ConstantBitsShiftMode::FixedWidth {
                bits: 16,
                mask: 0xffff,
                sign_bit: 0x8000,
            }
        } else if input >= i32::MIN as i64 {
            ConstantBitsShiftMode::FixedWidth {
                bits: 32,
                mask: 0xffff_ffff,
                sign_bit: 0x8000_0000,
            }
        } else {
            ConstantBitsShiftMode::SignedI64
        }
    } else if input <= u8::MAX as i64 {
        ConstantBitsShiftMode::FixedWidth {
            bits: 8,
            mask: 0xff,
            sign_bit: 0x80,
        }
    } else if input <= u16::MAX as i64 {
        ConstantBitsShiftMode::FixedWidth {
            bits: 16,
            mask: 0xffff,
            sign_bit: 0x8000,
        }
    } else if input <= u32::MAX as i64 {
        ConstantBitsShiftMode::FixedWidth {
            bits: 32,
            mask: 0xffff_ffff,
            sign_bit: 0x8000_0000,
        }
    } else {
        ConstantBitsShiftMode::UnsignedI64
    }
}

fn eval_supported_constant_bits_shift_spec(
    cmd_name: &str,
    input: i64,
    args: ConstantBitsShiftRotateArgs,
    span: Span,
) -> Result<ConstantBitsShiftSpec, LabeledError> {
    let mode = eval_supported_constant_bits_shift_rotate_mode(cmd_name, input, args, span)?;
    let max_count = match mode {
        ConstantBitsShiftMode::SignedI64 | ConstantBitsShiftMode::UnsignedI64 => 63,
        ConstantBitsShiftMode::FixedWidth { bits, .. }
        | ConstantBitsShiftMode::SignedFixedWidth { bits, .. } => bits - 1,
    };
    if !(0..=max_count).contains(&args.count) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a shift count from 0 through {max_count} in compile-time global initializers; got {}",
                    args.count
                ),
                span,
            ),
        );
    }

    Ok(ConstantBitsShiftSpec {
        count: args.count,
        mode,
    })
}

fn eval_supported_constant_bits_rotate_spec(
    cmd_name: &str,
    input: i64,
    args: ConstantBitsShiftRotateArgs,
    span: Span,
) -> Result<ConstantBitsRotateSpec, LabeledError> {
    let mode = eval_supported_constant_bits_shift_rotate_mode(cmd_name, input, args, span)?;
    let max_count = match mode {
        ConstantBitsShiftMode::SignedI64 | ConstantBitsShiftMode::UnsignedI64 => 64,
        ConstantBitsShiftMode::FixedWidth { bits, .. }
        | ConstantBitsShiftMode::SignedFixedWidth { bits, .. } => bits,
    };
    if !(0..=max_count).contains(&args.count) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a rotate count from 0 through {max_count} in compile-time global initializers; got {}",
                    args.count
                ),
                span,
            ),
        );
    }

    Ok(ConstantBitsRotateSpec {
        count: args.count,
        mode,
    })
}

fn eval_supported_constant_bits_shift_rotate_mode(
    cmd_name: &str,
    input: i64,
    args: ConstantBitsShiftRotateArgs,
    _span: Span,
) -> Result<ConstantBitsShiftMode, LabeledError> {
    if let Some((number_bytes, number_bytes_span)) = args.number_bytes {
        eval_supported_constant_bits_fixed_width_mode(
            cmd_name,
            number_bytes,
            args.signed,
            number_bytes_span,
        )
    } else if args.signed {
        Ok(ConstantBitsShiftMode::SignedI64)
    } else {
        Ok(eval_supported_constant_bits_auto_width_mode(input))
    }
}

fn eval_supported_constant_bits_shift_rotate(
    cmd_name: &str,
    input: Option<Value>,
    args: ConstantBitsShiftRotateArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::Int { val, .. } => {
            let output = if matches!(cmd_name, "bits shl" | "bits shr") {
                let spec = eval_supported_constant_bits_shift_spec(cmd_name, val, args, span)?;
                eval_supported_constant_bits_shift_int_output(cmd_name, val, spec, span)?
            } else {
                let spec = eval_supported_constant_bits_rotate_spec(cmd_name, val, args, span)?;
                eval_supported_constant_bits_rotate_int_output(cmd_name, val, spec, span)?
            };
            Ok(Value::int(output, value_span))
        }
        Value::Binary { val, .. } => Ok(Value::binary(
            eval_supported_constant_bits_binary_shift_rotate_output(
                cmd_name,
                &val,
                args.count,
                span,
            )?,
            value_span,
        )),
        Value::List { vals, .. } => {
            eval_supported_constant_bits_shift_rotate_list(cmd_name, vals, args, value_span, span)
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires integer, binary, list<int>, or list<binary> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_bits_shift_rotate_list(
    cmd_name: &str,
    vals: Vec<Value>,
    args: ConstantBitsShiftRotateArgs,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    if !vals.is_empty()
        && vals
            .iter()
            .all(|value| matches!(value, Value::Binary { .. }))
    {
        let output = vals
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let Value::Binary { val, .. } = value else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        format!(
                            "`{cmd_name}` requires binary list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
                };
                Ok(Value::binary(
                    eval_supported_constant_bits_binary_shift_rotate_output(
                        cmd_name, &val, args.count, span,
                    )?,
                    value_span,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Value::list(output, value_span));
    }

    let output = vals
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let Value::Int { val, .. } = value else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` requires integer list items in compile-time global initializers; item {index} has type {}",
                            value.get_type()
                        ),
                        span,
                    ));
            };
            let output = if matches!(cmd_name, "bits shl" | "bits shr") {
                let spec = eval_supported_constant_bits_shift_spec(cmd_name, val, args, span)?;
                eval_supported_constant_bits_shift_int_output(cmd_name, val, spec, span)?
            } else {
                let spec = eval_supported_constant_bits_rotate_spec(cmd_name, val, args, span)?;
                eval_supported_constant_bits_rotate_int_output(cmd_name, val, spec, span)?
            };
            Ok(Value::int(output, value_span))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::list(output, value_span))
}

fn eval_supported_constant_bits_shift_int_output(
    cmd_name: &str,
    lhs: i64,
    spec: ConstantBitsShiftSpec,
    span: Span,
) -> Result<i64, LabeledError> {
    debug_assert!(spec.count >= 0);
    let shift = spec.count as u32;
    match spec.mode {
        ConstantBitsShiftMode::SignedI64 => {
            debug_assert!(spec.count < 64);
            Ok(match cmd_name {
                "bits shl" => lhs.wrapping_shl(shift),
                "bits shr" => lhs >> shift,
                _ => unreachable!("validated bits shift command"),
            })
        }
        ConstantBitsShiftMode::UnsignedI64 => {
            debug_assert!(spec.count < 64);
            if lhs < 0 {
                return Ok(match cmd_name {
                    "bits shl" => lhs.wrapping_shl(shift),
                    "bits shr" => lhs >> shift,
                    _ => unreachable!("validated bits shift command"),
                });
            }

            let output = match cmd_name {
                "bits shl" => (lhs as u64) << shift,
                "bits shr" => (lhs as u64) >> shift,
                _ => unreachable!("validated bits shift command"),
            };
            i64::try_from(output).map_err(|_| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` unsigned 8-byte output exceeds Nushell's integer range in compile-time global initializers; use --signed --number-bytes 8 for signed two's-complement output"
                    ),
                    span,
                )
            })
        }
        ConstantBitsShiftMode::FixedWidth { mask, sign_bit, .. } => {
            let truncated = lhs & mask;
            Ok(if lhs < 0 {
                match cmd_name {
                    "bits shl" => {
                        let shifted = (truncated << shift) & mask;
                        eval_supported_constant_sign_extend_width(shifted, sign_bit)
                    }
                    "bits shr" => {
                        let signed = eval_supported_constant_sign_extend_width(truncated, sign_bit);
                        signed >> shift
                    }
                    _ => unreachable!("validated bits shift command"),
                }
            } else {
                match cmd_name {
                    "bits shl" => (truncated << shift) & mask,
                    "bits shr" => truncated >> shift,
                    _ => unreachable!("validated bits shift command"),
                }
            })
        }
        ConstantBitsShiftMode::SignedFixedWidth { mask, sign_bit, .. } => {
            let truncated = lhs & mask;
            let signed = eval_supported_constant_sign_extend_width(truncated, sign_bit);
            Ok(match cmd_name {
                "bits shl" => {
                    let shifted = (signed << shift) & mask;
                    eval_supported_constant_sign_extend_width(shifted, sign_bit)
                }
                "bits shr" => signed >> shift,
                _ => unreachable!("validated bits shift command"),
            })
        }
    }
}

fn eval_supported_constant_bits_rotate_int_output(
    cmd_name: &str,
    lhs: i64,
    spec: ConstantBitsRotateSpec,
    span: Span,
) -> Result<i64, LabeledError> {
    debug_assert!(spec.count >= 0);
    match spec.mode {
        ConstantBitsShiftMode::SignedI64 => {
            debug_assert!(spec.count <= 64);
            let rotate = spec.count as u32;
            Ok(match cmd_name {
                "bits rol" => lhs.rotate_left(rotate),
                "bits ror" => lhs.rotate_right(rotate),
                _ => unreachable!("validated bits rotate command"),
            })
        }
        ConstantBitsShiftMode::UnsignedI64 => {
            debug_assert!(spec.count <= 64);
            if lhs < 0 {
                let rotate = spec.count as u32;
                return Ok(match cmd_name {
                    "bits rol" => lhs.rotate_left(rotate),
                    "bits ror" => lhs.rotate_right(rotate),
                    _ => unreachable!("validated bits rotate command"),
                });
            }

            let rotate = (spec.count % 64) as u32;
            let output = match cmd_name {
                "bits rol" => (lhs as u64).rotate_left(rotate),
                "bits ror" => (lhs as u64).rotate_right(rotate),
                _ => unreachable!("validated bits rotate command"),
            };
            i64::try_from(output).map_err(|_| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` unsigned 8-byte output exceeds Nushell's integer range in compile-time global initializers; use --signed --number-bytes 8 for signed two's-complement output"
                    ),
                    span,
                )
            })
        }
        ConstantBitsShiftMode::FixedWidth {
            bits,
            mask,
            sign_bit,
        } => {
            let truncated = lhs & mask;
            let rotate = (spec.count % bits) as u32;
            let width = bits as u32;
            let rotated = if rotate == 0 {
                truncated
            } else {
                match cmd_name {
                    "bits rol" => ((truncated << rotate) | (truncated >> (width - rotate))) & mask,
                    "bits ror" => ((truncated >> rotate) | (truncated << (width - rotate))) & mask,
                    _ => unreachable!("validated bits rotate command"),
                }
            };
            if lhs < 0 {
                Ok(eval_supported_constant_sign_extend_width(rotated, sign_bit))
            } else {
                Ok(rotated)
            }
        }
        ConstantBitsShiftMode::SignedFixedWidth {
            bits,
            mask,
            sign_bit,
        } => {
            let truncated = lhs & mask;
            let rotate = (spec.count % bits) as u32;
            let width = bits as u32;
            let rotated = if rotate == 0 {
                truncated
            } else {
                match cmd_name {
                    "bits rol" => ((truncated << rotate) | (truncated >> (width - rotate))) & mask,
                    "bits ror" => ((truncated >> rotate) | (truncated << (width - rotate))) & mask,
                    _ => unreachable!("validated bits rotate command"),
                }
            };
            Ok(eval_supported_constant_sign_extend_width(rotated, sign_bit))
        }
    }
}

fn eval_supported_constant_sign_extend_width(value: i64, sign_bit: i64) -> i64 {
    (value ^ sign_bit) - sign_bit
}

fn eval_supported_constant_bits_binary_shift_rotate_output(
    cmd_name: &str,
    input: &[u8],
    count: i64,
    span: Span,
) -> Result<Vec<u8>, LabeledError> {
    let count_name = if matches!(cmd_name, "bits shl" | "bits shr") {
        "shift"
    } else {
        "rotate"
    };
    if count < 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a non-negative {count_name} count in compile-time global initializers; got {count}"
                ),
                span,
            ),
        );
    }
    let count = usize::try_from(count).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` {count_name} count is too large for binary input in compile-time global initializers"
            ),
            span,
        )
    })?;
    let bit_len = input.len().checked_mul(8).ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{cmd_name}` binary input is too large to transform in compile-time global initializers"),
            span,
        )
    })?;
    if count > bit_len {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a {count_name} count from 0 through {bit_len} for binary input in compile-time global initializers; got {count}"
                ),
                span,
            ),
        );
    }

    if bit_len == 0 {
        return Ok(Vec::new());
    }

    let mut output = vec![0u8; input.len()];
    let rotate = count % bit_len;
    for out_bit in 0..bit_len {
        let src_bit = match cmd_name {
            "bits shl" => (out_bit + count < bit_len).then_some(out_bit + count),
            "bits shr" => out_bit.checked_sub(count),
            "bits rol" => Some((out_bit + rotate) % bit_len),
            "bits ror" => Some((out_bit + bit_len - rotate) % bit_len),
            _ => unreachable!("validated bits shift/rotate command"),
        };
        if let Some(src_bit) = src_bit
            && eval_supported_constant_bits_binary_get_bit(input, src_bit)
        {
            eval_supported_constant_bits_binary_set_bit(&mut output, out_bit);
        }
    }
    Ok(output)
}

fn eval_supported_constant_bits_binary_get_bit(input: &[u8], bit_index: usize) -> bool {
    let byte = input[bit_index / 8];
    let mask = 1u8 << (7 - (bit_index % 8));
    byte & mask != 0
}

fn eval_supported_constant_bits_binary_set_bit(output: &mut [u8], bit_index: usize) {
    let mask = 1u8 << (7 - (bit_index % 8));
    output[bit_index / 8] |= mask;
}

fn eval_supported_constant_bits_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let Some((subcommand_arg, remaining_args)) = args.split_first() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bits` requires a subcommand in compile-time global initializers",
                span,
            ),
        );
    };
    let ExternalArgument::Regular(subcommand_expr) = subcommand_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bits` subcommand cannot use spread syntax in compile-time global initializers",
                subcommand_arg.expr().span,
            ),
        );
    };
    let subcommand = match eval_supported_constant_value_with_env(
        working_set,
        subcommand_expr,
        env,
    )? {
        Value::String { val, .. } | Value::Glob { val, .. } => val,
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`bits` subcommand must be a compile-time string in global initializers; got {}",
                        other.get_type()
                    ),
                    subcommand_expr.span,
                ),
            );
        }
    };
    let cmd_name = format!("bits {subcommand}");
    match cmd_name.as_str() {
        "bits and" | "bits or" | "bits xor" => {
            let args = eval_supported_constant_bits_binary_external_args(
                working_set,
                &cmd_name,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bits_binary(&cmd_name, input, args, span)
        }
        "bits not" => {
            let mode = eval_supported_constant_bits_not_external_mode(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bits_not(&cmd_name, input, mode, span)
        }
        "bits shl" | "bits shr" | "bits rol" | "bits ror" => {
            let args = eval_supported_constant_bits_shift_rotate_external_args(
                working_set,
                &cmd_name,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bits_shift_rotate(&cmd_name, input, args, span)
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`bits {subcommand}` is not supported in compile-time global initializers"),
                subcommand_expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_math_abs(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("math abs", input, span)?;
    let value_span = value.span();
    match value {
        Value::Int { val, .. } => Ok(Value::int(val.wrapping_abs(), value_span)),
        Value::List { vals, .. } => {
            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let Value::Int { val, .. } = value else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`math abs` requires integer list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ));
                    };
                    Ok(Value::int(val.wrapping_abs(), value_span))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(output, value_span))
        }
        Value::Float { val, .. } if !val.is_finite() => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`math abs` requires finite float input in compile-time global initializers; input is {val}"
                ),
                span,
            ),
        ),
        Value::Float { .. } => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math abs` compile-time result has type float; mutable global initializers support only materializable eBPF values",
                span,
            ),
        ),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`math abs` in a compile-time global initializer requires integer or list<int> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstantMathI64Unit {
    Filesize,
    Duration,
}

fn eval_supported_constant_math_i64_unit_value(
    value: &Value,
) -> Option<(i64, ConstantMathI64Unit)> {
    match value {
        Value::Filesize { val, .. } => Some((val.get(), ConstantMathI64Unit::Filesize)),
        Value::Duration { val, .. } => Some((*val, ConstantMathI64Unit::Duration)),
        _ => None,
    }
}

fn eval_supported_constant_math_i64_value(value: &Value) -> Option<i64> {
    match value {
        Value::Int { val, .. } => Some(*val),
        Value::Filesize { val, .. } => Some(val.get()),
        Value::Duration { val, .. } => Some(*val),
        _ => None,
    }
}

fn eval_supported_constant_math_unit_value(
    value: i64,
    unit: ConstantMathI64Unit,
    span: Span,
) -> Value {
    match unit {
        ConstantMathI64Unit::Filesize => Value::filesize(nu_protocol::Filesize::new(value), span),
        ConstantMathI64Unit::Duration => Value::duration(value, span),
    }
}

fn eval_supported_constant_math_avg(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("math avg", input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math avg` in a compile-time global initializer requires non-empty numeric list input",
                span,
            ),
        );
    };

    if vals.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math avg` requires a non-empty numeric list in compile-time global initializers",
                span,
            ),
        );
    }

    if vals
        .iter()
        .any(|value| eval_supported_constant_math_i64_unit_value(value).is_some())
    {
        return eval_supported_constant_math_unit_avg(vals, value_span, span);
    }

    for (index, value) in vals.into_iter().enumerate() {
        match value {
            Value::Int { .. } => {}
            Value::Float { val, .. } if val.is_finite() => {}
            Value::Float { val, .. } => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math avg` requires finite float list items in compile-time global initializers; item {index} is {val}"
                            ),
                            span,
                        ),
                );
            }
            other => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math avg` requires integer, finite float, filesize, or duration list items in compile-time global initializers; item {index} has type {}",
                                other.get_type()
                            ),
                            span,
                        ),
                );
            }
        }
    }

    Err(
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`math avg` compile-time list result has type float; mutable global initializers support only materializable eBPF values",
            span,
        ),
    )
}

fn eval_supported_constant_math_unit_avg(
    vals: Vec<Value>,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    let len = vals.len() as i128;
    let mut unit = None;
    let mut total = 0i128;
    for (index, value) in vals.into_iter().enumerate() {
        let Some((raw, value_unit)) = eval_supported_constant_math_i64_unit_value(&value) else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`math avg` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        if let Some(unit) = unit {
            if unit != value_unit {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math avg` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ),
                );
            }
        } else {
            unit = Some(value_unit);
        }
        total += raw as i128;
    }

    let avg = total / len;
    let avg = i64::try_from(avg).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`math avg` filesize/duration result overflows i64 in compile-time global initializers",
            span,
        )
    })?;
    Ok(eval_supported_constant_math_unit_value(
        avg,
        unit.expect("non-empty unit avg has a unit"),
        value_span,
    ))
}

fn eval_supported_constant_math_int_reduce(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires non-empty list<int> input"
                ),
                span,
            ),
        );
    };

    if vals.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a non-empty list<int> input in compile-time global initializers"
                ),
                span,
            ),
        );
    }

    if vals
        .iter()
        .any(|value| eval_supported_constant_math_i64_unit_value(value).is_some())
    {
        return eval_supported_constant_math_unit_reduce(cmd_name, vals, value_span, span);
    }

    if matches!(cmd_name, "math max" | "math min") {
        return eval_supported_constant_math_min_max(cmd_name, vals, value_span, span);
    }

    let ints = vals
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let Value::Int { val, .. } = value else {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires integer list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ),
                );
            };
            Ok(val)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let result = match cmd_name {
        "math max" => ints
            .into_iter()
            .max()
            .expect("math max validates non-empty input"),
        "math min" => ints
            .into_iter()
            .min()
            .expect("math min validates non-empty input"),
        "math product" => ints
            .into_iter()
            .fold(1_i64, |acc, value| acc.wrapping_mul(value)),
        "math sum" => ints
            .into_iter()
            .fold(0_i64, |acc, value| acc.wrapping_add(value)),
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` is not a supported integer reduction command in compile-time global initializers"
                    ),
                    span,
                ),
            );
        }
    };

    Ok(Value::int(result, value_span))
}

fn eval_supported_constant_math_unit_reduce(
    cmd_name: &str,
    vals: Vec<Value>,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    match cmd_name {
        "math sum" => eval_supported_constant_math_unit_sum(cmd_name, vals, value_span, span),
        "math min" | "math max" => {
            eval_supported_constant_math_unit_min_max(cmd_name, vals, span)
        }
        "math product" => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math product` does not support filesize or duration list input in compile-time global initializers",
                span,
            ),
        ),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` is not a supported filesize/duration reducer in compile-time global initializers"
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_math_unit_sum(
    cmd_name: &str,
    vals: Vec<Value>,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut unit = None;
    let mut total = 0i64;
    for (index, value) in vals.into_iter().enumerate() {
        let Some((raw, value_unit)) = eval_supported_constant_math_i64_unit_value(&value) else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        if let Some(unit) = unit {
            if unit != value_unit {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ),
                );
            }
        } else {
            unit = Some(value_unit);
        }
        total = total.checked_add(raw).ok_or_else(|| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` filesize/duration result overflows i64 in compile-time global initializers"
                ),
                span,
            )
        })?;
    }

    Ok(eval_supported_constant_math_unit_value(
        total,
        unit.expect("non-empty unit sum has a unit"),
        value_span,
    ))
}

fn eval_supported_constant_math_unit_min_max(
    cmd_name: &str,
    vals: Vec<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut selected = None::<(i64, Value)>;
    for (index, value) in vals.into_iter().enumerate() {
        let Some(raw) = eval_supported_constant_math_i64_value(&value) else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` requires integer, filesize, or duration list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        let should_update = selected.as_ref().is_none_or(|(selected_raw, _)| {
            if cmd_name == "math min" {
                raw < *selected_raw
            } else {
                raw > *selected_raw
            }
        });
        if should_update {
            selected = Some((raw, value));
        }
    }

    Ok(selected.expect("non-empty min/max has a selected value").1)
}

fn eval_supported_constant_math_min_max(
    cmd_name: &str,
    vals: Vec<Value>,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut selected = None::<Value>;
    for (index, value) in vals.into_iter().enumerate() {
        match &value {
            Value::Int { .. } => {}
            Value::Float { val, .. } if val.is_finite() => {}
            Value::Float { val, .. } => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires finite float list items in compile-time global initializers; item {index} is {val}"
                            ),
                            span,
                        ),
                );
            }
            other => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` requires integer or finite float list items in compile-time global initializers; item {index} has type {}",
                                other.get_type()
                            ),
                            span,
                        ),
                );
            }
        }

        let should_update = selected.as_ref().is_none_or(|current| {
            let ordering = value
                .partial_cmp(current)
                .expect("min/max float values are validated as finite");
            matches!(
                (cmd_name, ordering),
                ("math min", std::cmp::Ordering::Less) | ("math max", std::cmp::Ordering::Greater)
            )
        });
        if should_update {
            selected = Some(value);
        }
    }

    match selected.expect("math min/max validates non-empty input") {
        Value::Int { val, .. } => Ok(Value::int(val, value_span)),
        Value::Float { .. } => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` compile-time list result has type float; mutable global initializers support only materializable eBPF values"
                ),
                span,
            ),
        ),
        _ => unreachable!("min/max values were validated as integer or finite float"),
    }
}

fn eval_supported_constant_math_median(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("math median", input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math median` in a compile-time global initializer requires non-empty numeric list input",
                span,
            ),
        );
    };

    if vals.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math median` requires a non-empty numeric list in compile-time global initializers",
                span,
            ),
        );
    }

    if vals
        .iter()
        .any(|value| eval_supported_constant_math_i64_unit_value(value).is_some())
    {
        return eval_supported_constant_math_unit_median(vals, value_span, span);
    }
    if vals.len() % 2 == 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math median` compile-time list median has type float for even-length lists; mutable global initializers support only materializable eBPF values",
                span,
            ),
        );
    }

    let mut values = Vec::with_capacity(vals.len());
    for (index, value) in vals.into_iter().enumerate() {
        match &value {
            Value::Int { .. } => {}
            Value::Float { val, .. } if val.is_finite() => {}
            Value::Float { val, .. } => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math median` requires finite float list items in compile-time global initializers; item {index} is {val}"
                            ),
                            span,
                        ),
                );
            }
            other => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math median` requires integer or finite float list items in compile-time global initializers; item {index} has type {}",
                                other.get_type()
                            ),
                            span,
                        ),
                );
            }
        }
        values.push(value);
    }

    values.sort_by(|lhs, rhs| {
        lhs.partial_cmp(rhs)
            .expect("median float values are validated as finite")
    });
    match &values[values.len() / 2] {
        Value::Int { val, .. } => Ok(Value::int(*val, value_span)),
        Value::Float { .. } => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math median` compile-time list median has type float; mutable global initializers support only materializable eBPF values",
                span,
            ),
        ),
        _ => unreachable!("median values were validated as integer or finite float"),
    }
}

fn eval_supported_constant_math_unit_median(
    vals: Vec<Value>,
    value_span: Span,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut unit = None;
    let mut values = Vec::with_capacity(vals.len());
    for (index, value) in vals.into_iter().enumerate() {
        let Some((raw, value_unit)) = eval_supported_constant_math_i64_unit_value(&value) else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`math median` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        if let Some(unit) = unit {
            if unit != value_unit {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`math median` requires homogeneous filesize or duration list items in compile-time global initializers; item {index} has type {}",
                                value.get_type()
                            ),
                            span,
                        ),
                );
            }
        } else {
            unit = Some(value_unit);
        }
        values.push(raw);
    }

    values.sort_unstable();
    let median = if values.len() % 2 == 1 {
        values[values.len() / 2]
    } else {
        let upper = values.len() / 2;
        ((values[upper - 1] as i128 + values[upper] as i128) / 2) as i64
    };
    Ok(eval_supported_constant_math_unit_value(
        median,
        unit.expect("non-empty unit median has a unit"),
        value_span,
    ))
}

fn eval_supported_constant_math_mode(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    const MAX_MODE_STACK_LIST_CAPACITY: usize = 60;

    let value = eval_supported_constant_required_pipeline_input("math mode", input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math mode` in a compile-time global initializer requires list<int> input",
                span,
            ),
        );
    };

    let mut counts = BTreeMap::<i64, usize>::new();
    for (index, value) in vals.into_iter().enumerate() {
        let Value::Int { val, .. } = value else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`math mode` requires integer list items in compile-time global initializers; item {index} has type {}",
                        value.get_type()
                    ),
                    span,
                ),
            );
        };
        *counts.entry(val).or_default() += 1;
    }

    let max_count = counts.values().copied().max().unwrap_or(0);
    let modes = counts
        .into_iter()
        .filter_map(|(value, count)| (count == max_count).then_some(Value::int(value, value_span)))
        .collect::<Vec<_>>();
    if modes.len() > MAX_MODE_STACK_LIST_CAPACITY {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`math mode` output exceeds stack-backed numeric list capacity {MAX_MODE_STACK_LIST_CAPACITY} in compile-time global initializers"
                ),
                span,
            ),
        );
    }

    Ok(Value::list(modes, value_span))
}

fn eval_supported_constant_math_rounding(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::Int { .. } | Value::Float { .. } => {
            eval_supported_constant_math_rounding_value(cmd_name, value, None, span)
        }
        Value::List { vals, .. } => {
            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    eval_supported_constant_math_rounding_value(cmd_name, value, Some(index), span)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(output, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires integer, finite float, list<int>, or list<float> input; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_math_rounding_value(
    cmd_name: &str,
    value: Value,
    list_index: Option<usize>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value_span = value.span();
    match value {
        Value::Int { .. } => Ok(value),
        Value::Float { val, .. } => {
            let rounded = match cmd_name {
                "math ceil" => val.ceil(),
                "math floor" => val.floor(),
                "math round" => val.round(),
                _ => {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`{cmd_name}` is not a supported integer rounding command in compile-time global initializers"
                                ),
                                span,
                            ),
                    );
                }
            };
            let val =
                eval_supported_constant_math_rounding_i64(cmd_name, rounded, list_index, span)?;
            Ok(Value::int(val, value_span))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                match list_index {
                    Some(index) => format!(
                        "`{cmd_name}` requires integer or finite float list items in compile-time global initializers; item {index} has type {}",
                        other.get_type()
                    ),
                    None => format!(
                        "`{cmd_name}` in a compile-time global initializer requires integer or finite float input; got {}",
                        other.get_type()
                    ),
                },
                span,
            ),
        ),
    }
}

fn eval_supported_constant_math_rounding_i64(
    cmd_name: &str,
    value: f64,
    list_index: Option<usize>,
    span: Span,
) -> Result<i64, LabeledError> {
    const I64_MIN_F64: f64 = -9_223_372_036_854_775_808.0;
    const I64_MAX_PLUS_ONE_F64: f64 = 9_223_372_036_854_775_808.0;

    if !value.is_finite() || !(I64_MIN_F64..I64_MAX_PLUS_ONE_F64).contains(&value) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                match list_index {
                    Some(index) => format!(
                        "`{cmd_name}` compile-time float list item {index} result {value} cannot be represented as an i64"
                    ),
                    None => format!(
                        "`{cmd_name}` compile-time float result {value} cannot be represented as an i64"
                    ),
                },
                span,
            ),
        );
    }

    Ok(value as i64)
}

fn eval_supported_constant_math_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let Some((subcommand_arg, remaining_args)) = args.split_first() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math` requires a subcommand in compile-time global initializers",
                span,
            ),
        );
    };
    let ExternalArgument::Regular(subcommand_expr) = subcommand_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`math` subcommand cannot use spread syntax in compile-time global initializers",
                subcommand_arg.expr().span,
            ),
        );
    };
    let subcommand = match eval_supported_constant_value_with_env(
        working_set,
        subcommand_expr,
        env,
    )? {
        Value::String { val, .. } | Value::Glob { val, .. } => val,
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`math` subcommand must be a compile-time string in global initializers; got {}",
                        other.get_type()
                    ),
                    subcommand_expr.span,
                ),
            );
        }
    };
    let cmd_name = format!("math {subcommand}");
    match cmd_name.as_str() {
        "math abs" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_abs(input, span)
        }
        "math avg" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_avg(input, span)
        }
        "math max" | "math min" | "math product" | "math sum" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_int_reduce(&cmd_name, input, span)
        }
        "math median" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_median(input, span)
        }
        "math mode" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_mode(input, span)
        }
        "math ceil" | "math floor" | "math round" => {
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_math_rounding(&cmd_name, input, span)
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`math {subcommand}` is not supported in compile-time global initializers"),
                subcommand_expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_bytes_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let [subcommand_arg, remaining_args @ ..] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes` requires a supported subcommand in compile-time global initializers",
                span,
            ),
        );
    };

    let ExternalArgument::Regular(subcommand_expr) = subcommand_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`bytes` subcommand cannot use spread syntax in compile-time global initializers",
                subcommand_arg.expr().span,
            ),
        );
    };
    let subcommand = eval_supported_constant_record_field_name(working_set, subcommand_expr, env)?;

    match subcommand.as_str() {
        "length" => {
            eval_supported_constant_no_external_args("bytes length", remaining_args, span)?;
            eval_supported_constant_bytes_length(input, span)
        }
        "at" => {
            let range = eval_supported_constant_bytes_at_external_range(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_at(input, range, span)
        }
        "add" => {
            let args = eval_supported_constant_bytes_add_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_add(input, args, span)
        }
        "build" => {
            let bytes = eval_supported_constant_bytes_build_external_args(
                working_set,
                remaining_args,
                env,
            )?;
            eval_supported_constant_bytes_build(input, bytes, span)
        }
        "collect" => {
            let separator = eval_supported_constant_bytes_collect_external_separator(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_collect(input, separator, span)
        }
        "reverse" => {
            eval_supported_constant_no_external_args("bytes reverse", remaining_args, span)?;
            eval_supported_constant_bytes_reverse(input, span)
        }
        "starts-with" | "ends-with" => {
            let cmd_name = format!("bytes {subcommand}");
            let pattern = eval_supported_constant_bytes_predicate_external_pattern(
                working_set,
                &cmd_name,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_predicate(&cmd_name, input, pattern, span)
        }
        "index-of" => {
            let args = eval_supported_constant_bytes_index_of_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_index_of(input, args, span)
        }
        "remove" => {
            let args = eval_supported_constant_bytes_remove_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_remove(input, args, span)
        }
        "replace" => {
            let args = eval_supported_constant_bytes_replace_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_replace(input, args, span)
        }
        "split" => {
            let separator = eval_supported_constant_bytes_split_external_separator(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_bytes_split(input, separator, span)
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`bytes {subcommand}` is not supported in compile-time global initializers"
                ),
                subcommand_expr.span,
            ),
        ),
    }
}

#[derive(Clone, Copy)]
enum ConstantCharMode {
    Named,
    Unicode,
    Integer,
}

enum ConstantCharArg {
    String { val: String, span: Span },
    Int { val: i64, span: Span },
    Other { span: Span },
}

fn eval_supported_constant_char_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<String, LabeledError> {
    let mut positional = Vec::new();
    let mut unicode = false;
    let mut integer = false;
    let mut list = false;

    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                positional.push(eval_supported_constant_char_arg(working_set, expr, env)?);
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`char` flags cannot receive values in compile-time global initializers",
                        arg.span(),
                    ));
                }
                match named.0.item.as_str() {
                    "unicode" => unicode = true,
                    "integer" => integer = true,
                    "list" => list = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`char` supports only --unicode and --integer in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`char` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let mode = eval_supported_constant_char_mode(unicode, integer, list, span)?;
    eval_supported_constant_char_output(mode, &positional, span)
}

fn eval_supported_constant_char_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<String, LabeledError> {
    let mut positional = Vec::new();
    let mut unicode = false;
    let mut integer = false;
    let mut list = false;

    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`char` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ),
            );
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } => match val.as_str() {
                "--unicode" => unicode = true,
                "--integer" => integer = true,
                "--list" => list = true,
                _ if val.starts_with("--") => {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`char` supports only --unicode and --integer in compile-time global initializers",
                        expr.span,
                    ));
                }
                _ => positional.push(ConstantCharArg::String {
                    val,
                    span: expr.span,
                }),
            },
            Value::Int { val, .. } => positional.push(ConstantCharArg::Int {
                val,
                span: expr.span,
            }),
            _ => positional.push(ConstantCharArg::Other { span: expr.span }),
        }
    }

    let mode = eval_supported_constant_char_mode(unicode, integer, list, span)?;
    eval_supported_constant_char_output(mode, &positional, span)
}

fn eval_supported_constant_char_arg(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantCharArg, LabeledError> {
    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    Ok(match value {
        Value::String { val, .. } | Value::Glob { val, .. } => ConstantCharArg::String {
            val,
            span: expr.span,
        },
        Value::Int { val, .. } => ConstantCharArg::Int {
            val,
            span: expr.span,
        },
        _ => ConstantCharArg::Other { span: expr.span },
    })
}

fn eval_supported_constant_char_mode(
    unicode: bool,
    integer: bool,
    list: bool,
    span: Span,
) -> Result<ConstantCharMode, LabeledError> {
    if list {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`char --list` produces a table and is not supported in compile-time global initializers",
                span,
            ),
        );
    }
    if unicode && integer {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`char` supports only one of --unicode or --integer in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(if unicode {
        ConstantCharMode::Unicode
    } else if integer {
        ConstantCharMode::Integer
    } else {
        ConstantCharMode::Named
    })
}

fn eval_supported_constant_char_output(
    mode: ConstantCharMode,
    args: &[ConstantCharArg],
    span: Span,
) -> Result<String, LabeledError> {
    if args.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`char` requires at least one character argument in compile-time global initializers",
                span,
            ),
        );
    }

    let output = match mode {
        ConstantCharMode::Named => eval_supported_constant_named_char_output(args, span)?,
        ConstantCharMode::Unicode => eval_supported_constant_unicode_char_output(args)?,
        ConstantCharMode::Integer => eval_supported_constant_integer_char_output(args)?,
    };
    if output.as_bytes().contains(&0) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`char` output containing NUL bytes is not supported in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(output)
}

fn eval_supported_constant_named_char_output(
    args: &[ConstantCharArg],
    span: Span,
) -> Result<String, LabeledError> {
    let name = match &args[0] {
        ConstantCharArg::String { val, .. } => val,
        ConstantCharArg::Int { span, .. } | ConstantCharArg::Other { span, .. } => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`char` named character argument must be a compile-time string in global initializers",
                    *span,
                ),
            );
        }
    };
    for arg in &args[1..] {
        match arg {
            ConstantCharArg::String { .. } => {}
            ConstantCharArg::Int { span, .. } | ConstantCharArg::Other { span, .. } => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`char` named-character extra argument must be a compile-time string in global initializers",
                        *span,
                    ));
            }
        }
    }
    eval_supported_constant_known_named_char(name).ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`char` named character '{name}' is not supported in global initializers"),
            span,
        )
    })
}

fn eval_supported_constant_unicode_char_output(
    args: &[ConstantCharArg],
) -> Result<String, LabeledError> {
    let mut output = String::new();
    for arg in args {
        let (raw, span) = match arg {
            ConstantCharArg::String { val, span } => (val, *span),
            ConstantCharArg::Int { span, .. } | ConstantCharArg::Other { span, .. } => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`char --unicode` requires compile-time string hexadecimal codepoints in global initializers",
                        *span,
                    ));
            }
        };
        let codepoint = u32::from_str_radix(raw.trim(), 16).map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`char --unicode` requires hexadecimal codepoints, got '{raw}'"),
                span,
            )
        })?;
        output.push(eval_supported_constant_char_from_codepoint(
            codepoint,
            "char --unicode",
            span,
        )?);
    }
    Ok(output)
}

fn eval_supported_constant_integer_char_output(
    args: &[ConstantCharArg],
) -> Result<String, LabeledError> {
    let mut output = String::new();
    for arg in args {
        let (raw, span) = match arg {
            ConstantCharArg::Int { val, span } => (*val, *span),
            ConstantCharArg::String { span, .. } | ConstantCharArg::Other { span, .. } => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`char --integer` requires compile-time integer codepoints in global initializers",
                        *span,
                    ));
            }
        };
        let codepoint = u32::try_from(raw).map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`char --integer` codepoint {raw} is outside the valid Unicode range"),
                span,
            )
        })?;
        output.push(eval_supported_constant_char_from_codepoint(
            codepoint,
            "char --integer",
            span,
        )?);
    }
    Ok(output)
}

fn eval_supported_constant_known_named_char(name: &str) -> Option<String> {
    let hex = match name {
        "nul" | "null_byte" | "zero_byte" => "0",
        "newline" | "enter" | "nl" | "line_feed" | "lf" | "eol" | "lsep" | "line_sep" => "a",
        "carriage_return" | "cr" => "d",
        "crlf" => "d a",
        "tab" => "9",
        "sp" | "space" => "20",
        "pipe" => "7c",
        "left_brace" | "lbrace" => "7b",
        "right_brace" | "rbrace" => "7d",
        "left_paren" | "lp" | "lparen" => "28",
        "right_paren" | "rparen" | "rp" => "29",
        "left_bracket" | "lbracket" => "5b",
        "right_bracket" | "rbracket" => "5d",
        "single_quote" | "squote" | "sq" => "27",
        "double_quote" | "dquote" | "dq" => "22",
        "path_sep" | "psep" | "separator" => "2f",
        "esep" | "env_sep" => "3a",
        "tilde" | "twiddle" | "squiggly" | "home" => "7e",
        "hash" | "hashtag" | "pound_sign" | "sharp" | "root" => "23",
        "nf_branch" => "e0a0",
        "nf_segment" | "nf_left_segment" => "e0b0",
        "nf_left_segment_thin" => "e0b1",
        "nf_right_segment" => "e0b2",
        "nf_right_segment_thin" => "e0b3",
        "nf_git" => "f1d3",
        "nf_git_branch" => "e709 e0a0",
        "nf_folder1" => "f07c",
        "nf_folder2" => "f115",
        "nf_house1" => "f015",
        "nf_house2" => "f7db",
        "identical_to" | "hamburger" => "2261",
        "not_identical_to" | "branch_untracked" => "2262",
        "strictly_equivalent_to" | "branch_identical" => "2263",
        "upwards_arrow" | "branch_ahead" => "2191",
        "downwards_arrow" | "branch_behind" => "2193",
        "up_down_arrow" | "branch_ahead_behind" => "2195",
        "black_right_pointing_triangle" | "prompt" => "25b6",
        "vector_or_cross_product" | "failed" => "2a2f",
        "high_voltage_sign" | "elevated" => "26a1",
        "sun" | "sunny" | "sunrise" => "2600 fe0f",
        "moon" => "1f31b",
        "cloudy" | "cloud" | "clouds" => "2601 fe0f",
        "rainy" | "rain" => "1f326 fe0f",
        "foggy" | "fog" => "1f32b fe0f",
        "mist" | "haze" => "2591",
        "snowy" | "snow" => "2744 fe0f",
        "thunderstorm" | "thunder" => "1f329 fe0f",
        "bel" => "7",
        "backspace" => "8",
        "file_separator" | "file_sep" | "fs" => "1c",
        "group_separator" | "group_sep" | "gs" => "1d",
        "record_separator" | "record_sep" | "rs" => "1e",
        "unit_separator" | "unit_sep" | "us" => "1f",
        _ => return None,
    };
    eval_supported_constant_chars_from_hex_sequence(hex).ok()
}

fn eval_supported_constant_chars_from_hex_sequence(hex: &str) -> Result<String, LabeledError> {
    let mut output = String::new();
    for part in hex.split_whitespace() {
        let codepoint = u32::from_str_radix(part, 16).map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("invalid `char` codepoint '{part}' in global initializers"),
                Span::unknown(),
            )
        })?;
        output.push(eval_supported_constant_char_from_codepoint(
            codepoint,
            "char",
            Span::unknown(),
        )?);
    }
    Ok(output)
}

fn eval_supported_constant_char_from_codepoint(
    codepoint: u32,
    context: &str,
    span: Span,
) -> Result<char, LabeledError> {
    char::from_u32(codepoint).ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{context}` codepoint U+{codepoint:X} is outside the valid Unicode range"),
            span,
        )
    })
}

fn eval_supported_constant_char(
    input: Option<Value>,
    output: String,
    span: Span,
) -> Result<Value, LabeledError> {
    if input.is_some() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`char` does not accept pipeline input in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(Value::string(output, span))
}

#[derive(Debug, Clone, Copy)]
enum ConstantFillAlignment {
    Left,
    Right,
    Center,
    CenterRight,
}

#[derive(Debug, Clone, Copy)]
enum ConstantFillOption {
    Width,
    Alignment,
    Character,
}

struct ConstantFillArgs {
    width: usize,
    alignment: ConstantFillAlignment,
    character: String,
}

fn eval_supported_constant_fill_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantFillArgs, LabeledError> {
    let mut width = None;
    let mut alignment = None;
    let mut character = None;

    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                let option = eval_supported_constant_fill_option(
                    &named.0.item,
                    named.1.as_ref().map(|short| short.item.as_str()),
                    arg.span(),
                )?;
                let Some(value_expr) = named.2.as_ref() else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`fill` named options require values in compile-time global initializers",
                        arg.span(),
                    ));
                };
                eval_supported_constant_fill_set_option(
                    working_set,
                    env,
                    option,
                    value_expr,
                    &mut width,
                    &mut alignment,
                    &mut character,
                )?;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`fill` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`fill` supports only named options in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }

    Ok(ConstantFillArgs {
        width: width.unwrap_or(1),
        alignment: alignment.unwrap_or(ConstantFillAlignment::Left),
        character: character.unwrap_or_else(|| " ".to_string()),
    })
}

fn eval_supported_constant_fill_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantFillArgs, LabeledError> {
    let mut width = None;
    let mut alignment = None;
    let mut character = None;
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`fill` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ),
            );
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`fill` external arguments must be compile-time string flags in global initializers",
                        expr.span,
                    ));
            }
        };
        let option = eval_supported_constant_fill_external_option(&flag, expr.span)?;
        let Some(next_arg) = iter.next() else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`fill {flag}` requires a value in compile-time global initializers"),
                    expr.span,
                ),
            );
        };
        let ExternalArgument::Regular(value_expr) = next_arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`fill` option values cannot use spread syntax in compile-time global initializers",
                    next_arg.expr().span,
                ));
        };
        eval_supported_constant_fill_set_option(
            working_set,
            env,
            option,
            value_expr,
            &mut width,
            &mut alignment,
            &mut character,
        )?;
    }

    Ok(ConstantFillArgs {
        width: width.unwrap_or(1),
        alignment: alignment.unwrap_or(ConstantFillAlignment::Left),
        character: character.unwrap_or_else(|| " ".to_string()),
    })
}

fn eval_supported_constant_fill_option(
    name: &str,
    short: Option<&str>,
    span: Span,
) -> Result<ConstantFillOption, LabeledError> {
    match (name, short) {
        ("width", _) | ("w", _) | (_, Some("w")) => Ok(ConstantFillOption::Width),
        ("alignment", _) | ("a", _) | (_, Some("a")) => Ok(ConstantFillOption::Alignment),
        ("character", _) | ("c", _) | (_, Some("c")) => Ok(ConstantFillOption::Character),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`fill` supports only --width, --alignment, and --character in compile-time global initializers",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_fill_external_option(
    flag: &str,
    span: Span,
) -> Result<ConstantFillOption, LabeledError> {
    match flag {
        "--width" | "--w" | "-w" => Ok(ConstantFillOption::Width),
        "--alignment" | "--a" | "-a" => Ok(ConstantFillOption::Alignment),
        "--character" | "--c" | "-c" => Ok(ConstantFillOption::Character),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`fill` supports only --width, --alignment, and --character in compile-time global initializers",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_fill_set_option(
    working_set: &StateWorkingSet,
    env: &HashMap<nu_protocol::VarId, Value>,
    option: ConstantFillOption,
    value_expr: &nu_protocol::ast::Expression,
    width: &mut Option<usize>,
    alignment: &mut Option<ConstantFillAlignment>,
    character: &mut Option<String>,
) -> Result<(), LabeledError> {
    match option {
        ConstantFillOption::Width => {
            let value = eval_supported_constant_non_negative_usize_argument(
                working_set,
                value_expr,
                env,
                "fill --width",
            )?;
            if width.replace(value).is_some() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`fill` accepts only one --width value in compile-time global initializers",
                        value_expr.span,
                    ));
            }
        }
        ConstantFillOption::Alignment => {
            let raw = eval_supported_constant_string_argument(
                working_set,
                value_expr,
                env,
                "fill --alignment",
            )?;
            let value = eval_supported_constant_fill_alignment(&raw);
            if alignment.replace(value).is_some() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`fill` accepts only one --alignment value in compile-time global initializers",
                        value_expr.span,
                    ));
            }
        }
        ConstantFillOption::Character => {
            let value = eval_supported_constant_string_argument(
                working_set,
                value_expr,
                env,
                "fill --character",
            )?;
            eval_supported_constant_reject_nul_string_argument(
                "fill --character",
                &value,
                value_expr.span,
            )?;
            if character.replace(value).is_some() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`fill` accepts only one --character value in compile-time global initializers",
                        value_expr.span,
                    ));
            }
        }
    }

    Ok(())
}

fn eval_supported_constant_fill_alignment(value: &str) -> ConstantFillAlignment {
    match value.to_ascii_lowercase().as_str() {
        "right" | "r" => ConstantFillAlignment::Right,
        "center" | "middle" | "c" | "m" => ConstantFillAlignment::Center,
        "cr" | "mr" => ConstantFillAlignment::CenterRight,
        _ => ConstantFillAlignment::Left,
    }
}

fn eval_supported_constant_fill(
    input: Option<Value>,
    args: ConstantFillArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("fill", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let text = eval_supported_constant_fill_value_text(value, Some(index), span)?;
                    Ok(Value::string(
                        eval_supported_constant_fill_known_string(&text, &args),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, LabeledError>>()?;
            Ok(Value::list(values, value_span))
        }
        value => {
            let text = eval_supported_constant_fill_value_text(value, None, span)?;
            Ok(Value::string(
                eval_supported_constant_fill_known_string(&text, &args),
                value_span,
            ))
        }
    }
}

fn eval_supported_constant_fill_value_text(
    value: Value,
    list_index: Option<usize>,
    span: Span,
) -> Result<String, LabeledError> {
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val),
        Value::Int { val, .. } => Ok(val.to_string()),
        Value::Float { val, .. } => Ok(val.to_string()),
        Value::Filesize { val, .. } => Ok(val.get().to_string()),
        other => {
            let supported = "string, int, float, and filesize";
            Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    match list_index {
                        Some(index) => format!(
                            "`fill` supports only {supported} compile-time list items in global initializers; item {index} has type {}",
                            other.get_type()
                        ),
                        None => format!(
                            "`fill` requires compile-time known {supported} input in global initializers; input has type {}",
                            other.get_type()
                        ),
                    },
                    span,
                ),
            )
        }
    }
}

fn eval_supported_constant_fill_known_string(input: &str, args: &ConstantFillArgs) -> String {
    let input_width = input.chars().count();
    let pad_width = args.width.saturating_sub(input_width);
    if pad_width == 0 || args.character.is_empty() {
        return input.to_string();
    }

    let (left_pad, right_pad) = match args.alignment {
        ConstantFillAlignment::Left => (0, pad_width),
        ConstantFillAlignment::Right => (pad_width, 0),
        ConstantFillAlignment::Center => (pad_width / 2, pad_width - (pad_width / 2)),
        ConstantFillAlignment::CenterRight => (pad_width.div_ceil(2), pad_width / 2),
    };
    let mut output = String::with_capacity(input.len() + args.character.len() * pad_width);
    output.push_str(&args.character.repeat(left_pad));
    output.push_str(input);
    output.push_str(&args.character.repeat(right_pad));
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstantStringLengthMode {
    Utf8Bytes,
    Chars,
    GraphemeClusters,
}

fn eval_supported_constant_str_length_mode_call(
    args: &[nu_protocol::ast::Argument],
) -> Result<ConstantStringLengthMode, LabeledError> {
    let mut mode = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str length` mode flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                }
                let next = eval_supported_constant_str_length_mode_flag(&named.0.item)
                    .ok_or_else(|| {
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                "`str length` supports only --utf-8-bytes, --chars, and --grapheme-clusters in compile-time global initializers",
                                arg.span(),
                            )
                    })?;
                if mode.replace(next).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str length` accepts only one length mode flag in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str length` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str length` does not accept arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }

    Ok(mode.unwrap_or(ConstantStringLengthMode::Utf8Bytes))
}

fn eval_supported_constant_str_length_mode_external_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStringLengthMode, LabeledError> {
    let mut mode = None;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                    ),
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` accepts only string mode flags in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        };
        let Some(flag) = flag.strip_prefix("--") else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` does not accept arguments in compile-time global initializers"
                    ),
                    span,
                ),
            );
        };
        let next = eval_supported_constant_str_length_mode_flag(flag).ok_or_else(|| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` supports only --utf-8-bytes, --chars, and --grapheme-clusters in compile-time global initializers"
                ),
                expr.span,
            )
        })?;
        if mode.replace(next).is_some() {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` accepts only one length mode flag in compile-time global initializers"
                    ),
                    expr.span,
                ));
        }
    }

    Ok(mode.unwrap_or(ConstantStringLengthMode::Utf8Bytes))
}

fn eval_supported_constant_str_length_mode_flag(flag: &str) -> Option<ConstantStringLengthMode> {
    match flag {
        "utf-8-bytes" => Some(ConstantStringLengthMode::Utf8Bytes),
        "chars" => Some(ConstantStringLengthMode::Chars),
        "grapheme-clusters" => Some(ConstantStringLengthMode::GraphemeClusters),
        _ => None,
    }
}

fn eval_supported_constant_str_length(
    input: Option<Value>,
    mode: ConstantStringLengthMode,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str length", input, span)?;
    let value_span = value.span();
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => {
            Ok(Value::int(eval_supported_constant_known_string_length(&val, mode), span))
        }
        Value::Binary { val, .. } if mode != ConstantStringLengthMode::Utf8Bytes => {
            let val = String::from_utf8(val).map_err(|_| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`str length` requires valid UTF-8 binary input for character length modes in compile-time global initializers",
                    span,
                )
            })?;
            Ok(Value::int(eval_supported_constant_known_string_length(&val, mode), span))
        }
        Value::List { vals, .. } => {
            let lengths = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let val = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`str length` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::int(
                        eval_supported_constant_known_string_length(&val, mode),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(lengths, value_span))
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str length` in a compile-time global initializer requires string or list<string> input",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_known_string_length(input: &str, mode: ConstantStringLengthMode) -> i64 {
    match mode {
        ConstantStringLengthMode::Utf8Bytes => input.len() as i64,
        ConstantStringLengthMode::Chars => input.chars().count() as i64,
        ConstantStringLengthMode::GraphemeClusters => {
            UnicodeSegmentation::graphemes(input, true).count() as i64
        }
    }
}

struct ConstantStringPredicateArgs {
    needle: String,
    ignore_case: bool,
}

fn eval_supported_constant_str_predicate_call_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantStringPredicateArgs, LabeledError> {
    let mut needle_expr = None;
    let mut ignore_case = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if needle_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts exactly one string argument in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.0.item != "ignore-case" || named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts only the --ignore-case flag in compile-time global initializers"
                            ),
                            arg.span(),
                        ));
                }
                ignore_case = true;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    let Some(needle_expr) = needle_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one string argument in compile-time global initializers"
                ),
                Span::unknown(),
            ),
        );
    };
    let needle = eval_supported_constant_string_argument(working_set, needle_expr, env, cmd_name)?;
    eval_supported_constant_reject_nul_string_argument(cmd_name, &needle, needle_expr.span)?;

    Ok(ConstantStringPredicateArgs {
        needle,
        ignore_case,
    })
}

fn eval_supported_constant_str_predicate_external_args(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStringPredicateArgs, LabeledError> {
    let mut needle_expr = None;
    let mut ignore_case = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`{cmd_name}` arguments cannot use spread syntax in compile-time global initializers"
                    ),
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } if val == "--ignore-case" => {
                ignore_case = true;
            }
            Value::String { val, .. } | Value::Glob { val, .. } => {
                if needle_expr.replace((expr, val)).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`{cmd_name}` accepts exactly one string argument in compile-time global initializers"
                            ),
                            span,
                        ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` argument must be a compile-time string in global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    let Some((needle_expr, needle)) = needle_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires exactly one string argument in compile-time global initializers"
                ),
                span,
            ),
        );
    };
    eval_supported_constant_reject_nul_string_argument(cmd_name, &needle, needle_expr.span)?;

    Ok(ConstantStringPredicateArgs {
        needle,
        ignore_case,
    })
}

fn eval_supported_constant_string_argument(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    cmd_name: &str,
) -> Result<String, LabeledError> {
    match eval_supported_constant_value_with_env(working_set, expr, env)? {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` argument must be a compile-time string in global initializers"
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_reject_nul_string_argument(
    cmd_name: &str,
    value: &str,
    span: Span,
) -> Result<(), LabeledError> {
    if value.as_bytes().contains(&0) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` does not support NUL bytes in compile-time global initializers"
                ),
                span,
            ),
        );
    }
    Ok(())
}

fn eval_supported_constant_str_predicate(
    cmd_name: &str,
    input: Option<Value>,
    args: ConstantStringPredicateArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(Value::bool(
            eval_supported_constant_string_predicate_matches(cmd_name, &val, &args),
            span,
        )),
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let val = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`{cmd_name}` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::bool(
                        eval_supported_constant_string_predicate_matches(cmd_name, &val, &args),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires string or list<string> input"
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_string_predicate_matches(
    cmd_name: &str,
    input: &str,
    args: &ConstantStringPredicateArgs,
) -> bool {
    if args.ignore_case {
        let input = input.to_lowercase();
        let needle = args.needle.to_lowercase();
        return eval_supported_constant_string_predicate_matches_case_sensitive(
            cmd_name, &input, &needle,
        );
    }

    eval_supported_constant_string_predicate_matches_case_sensitive(cmd_name, input, &args.needle)
}

fn eval_supported_constant_string_predicate_matches_case_sensitive(
    cmd_name: &str,
    input: &str,
    needle: &str,
) -> bool {
    match cmd_name {
        "str starts-with" => input.starts_with(needle),
        "str ends-with" => input.ends_with(needle),
        "str contains" => input.contains(needle),
        _ => unreachable!("unsupported constant string predicate command: {cmd_name}"),
    }
}

#[derive(Clone)]
struct ConstantStrIndexOfArgs {
    needle: String,
    search_from_end: bool,
    range: Option<ConstantMaybeOpenRange>,
    use_grapheme_clusters: bool,
}

fn eval_supported_constant_str_index_of_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrIndexOfArgs, LabeledError> {
    let mut needle_expr = None;
    let mut search_from_end = false;
    let mut range = None;
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if needle_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str index-of` accepts exactly one substring argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "end" | "utf-8-bytes" | "grapheme-clusters" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str index-of` mode flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    match named.0.item.as_str() {
                        "end" => search_from_end = true,
                        "utf-8-bytes" => use_utf8_bytes = true,
                        "grapheme-clusters" => use_grapheme_clusters = true,
                        _ => unreachable!("validated str index-of mode flag"),
                    }
                }
                "range" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str index-of --range` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    if range
                        .replace(eval_supported_constant_range_argument(
                            working_set,
                            expr,
                            env,
                            "str index-of --range",
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str index-of` accepts only one --range value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str index-of` supports only --end, --range, --utf-8-bytes, and --grapheme-clusters in compile-time global initializers",
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str index-of` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(needle_expr) = needle_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str index-of` requires a string substring argument in compile-time global initializers",
                span,
            ),
        );
    };
    let needle =
        eval_supported_constant_string_argument(working_set, needle_expr, env, "str index-of")?;
    eval_supported_constant_reject_nul_string_argument("str index-of", &needle, needle_expr.span)?;
    let use_grapheme_clusters = eval_supported_constant_str_indexing_validate_modes(
        "str index-of",
        use_utf8_bytes,
        use_grapheme_clusters,
        span,
    )?;

    Ok(ConstantStrIndexOfArgs {
        needle,
        search_from_end,
        range,
        use_grapheme_clusters,
    })
}

fn eval_supported_constant_str_index_of_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrIndexOfArgs, LabeledError> {
    let mut needle_expr = None;
    let mut needle = None;
    let mut search_from_end = false;
    let mut range = None;
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`str index-of` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } => {
                let Some(flag) = val.strip_prefix("--") else {
                    if needle.replace(val).is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str index-of` accepts exactly one substring argument in compile-time global initializers",
                            expr.span,
                        ));
                    }
                    needle_expr = Some(expr);
                    continue;
                };
                match flag {
                    "end" => search_from_end = true,
                    "utf-8-bytes" => use_utf8_bytes = true,
                    "grapheme-clusters" => use_grapheme_clusters = true,
                    "range" => {
                        let Some(next_arg) = iter.next() else {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                "`str index-of --range` requires a value in compile-time global initializers",
                                expr.span,
                            ));
                        };
                        let ExternalArgument::Regular(next_expr) = next_arg else {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                "`str index-of --range` value cannot use spread syntax in compile-time global initializers",
                                next_arg.expr().span,
                            ));
                        };
                        if range
                            .replace(eval_supported_constant_range_argument(
                                working_set,
                                next_expr,
                                env,
                                "str index-of --range",
                            )?)
                            .is_some()
                        {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                "`str index-of` accepts only one --range value in compile-time global initializers",
                                next_expr.span,
                            ));
                        }
                    }
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str index-of` supports only --end, --range, --utf-8-bytes, and --grapheme-clusters in compile-time global initializers",
                            expr.span,
                        ));
                    }
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str index-of` substring argument must be a compile-time string in global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(needle) = needle else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str index-of` requires a string substring argument in compile-time global initializers",
                span,
            ),
        );
    };
    eval_supported_constant_reject_nul_string_argument(
        "str index-of",
        &needle,
        needle_expr.map(|expr| expr.span).unwrap_or(span),
    )?;
    let use_grapheme_clusters = eval_supported_constant_str_indexing_validate_modes(
        "str index-of",
        use_utf8_bytes,
        use_grapheme_clusters,
        span,
    )?;

    Ok(ConstantStrIndexOfArgs {
        needle,
        search_from_end,
        range,
        use_grapheme_clusters,
    })
}

fn eval_supported_constant_str_indexing_validate_modes(
    cmd_name: &str,
    use_utf8_bytes: bool,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<bool, LabeledError> {
    if use_utf8_bytes && use_grapheme_clusters {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` accepts either --utf-8-bytes or --grapheme-clusters, not both, in compile-time global initializers"
                ),
                span,
            ),
        );
    }
    Ok(use_grapheme_clusters)
}

fn eval_supported_constant_str_index_of(
    input: Option<Value>,
    args: ConstantStrIndexOfArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str index-of", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`str index-of` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::int(
                        eval_supported_constant_index_of_known_string(&input, &args, span)?,
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(Value::int(
            eval_supported_constant_index_of_known_string(&val, &args, span)?,
            value_span,
        )),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str index-of` in a compile-time global initializer requires string or list<string> input",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_index_of_known_string(
    input: &str,
    args: &ConstantStrIndexOfArgs,
    span: Span,
) -> Result<i64, LabeledError> {
    let (search_start, search_end) =
        eval_supported_constant_index_of_search_bounds(args.range, input.len());
    if args.use_grapheme_clusters {
        eval_supported_constant_grapheme_index_of_in_byte_range(
            input,
            &args.needle,
            args.search_from_end,
            search_start,
            search_end,
            span,
        )
    } else {
        Ok(eval_supported_constant_byte_index_of_in_range(
            input,
            &args.needle,
            args.search_from_end,
            search_start,
            search_end,
        ))
    }
}

fn eval_supported_constant_index_of_search_bounds(
    range: Option<ConstantMaybeOpenRange>,
    input_len: usize,
) -> (usize, usize) {
    range
        .map(|range| eval_supported_constant_string_range_bounds(range, input_len))
        .unwrap_or((0, input_len))
}

fn eval_supported_constant_byte_index_of_in_range(
    input: &str,
    needle: &str,
    search_from_end: bool,
    search_start: usize,
    search_end: usize,
) -> i64 {
    if needle.is_empty() {
        return if search_from_end {
            search_end as i64
        } else {
            search_start as i64
        };
    }

    if needle.len() > input.len() || search_start.saturating_add(needle.len()) > search_end {
        return -1;
    }

    let last_offset = search_end - needle.len();
    let input = input.as_bytes();
    let needle = needle.as_bytes();
    let mut offsets: Box<dyn Iterator<Item = usize>> = if search_from_end {
        Box::new((search_start..=last_offset).rev())
    } else {
        Box::new(search_start..=last_offset)
    };

    offsets
        .find(|offset| &input[*offset..*offset + needle.len()] == needle)
        .map(|offset| offset as i64)
        .unwrap_or(-1)
}

fn eval_supported_constant_grapheme_index_of_in_byte_range(
    input: &str,
    needle: &str,
    search_from_end: bool,
    search_start: usize,
    search_end: usize,
    span: Span,
) -> Result<i64, LabeledError> {
    let Some(search_input) = input.get(search_start..search_end) else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str index-of --grapheme-clusters --range` bounds must align to UTF-8 character boundaries in compile-time global initializers",
                span,
            ),
        );
    };
    let Some(prefix) = input.get(..search_start) else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str index-of --grapheme-clusters --range` start must align to a UTF-8 character boundary in compile-time global initializers",
                span,
            ),
        );
    };

    let local_index =
        eval_supported_constant_grapheme_index_of(search_input, needle, search_from_end);
    if local_index < 0 {
        return Ok(-1);
    }

    let prefix_graphemes = UnicodeSegmentation::graphemes(prefix, true).count() as i64;
    Ok(prefix_graphemes + local_index)
}

fn eval_supported_constant_grapheme_index_of(
    input: &str,
    needle: &str,
    search_from_end: bool,
) -> i64 {
    let input_graphemes = UnicodeSegmentation::graphemes(input, true).collect::<Vec<_>>();
    let needle_graphemes = UnicodeSegmentation::graphemes(needle, true).collect::<Vec<_>>();

    if needle_graphemes.is_empty() {
        return if search_from_end {
            input_graphemes.len() as i64
        } else {
            0
        };
    }

    if needle_graphemes.len() > input_graphemes.len() {
        return -1;
    }

    let last_offset = input_graphemes.len() - needle_graphemes.len();
    let offsets: Box<dyn Iterator<Item = usize>> = if search_from_end {
        Box::new((0..=last_offset).rev())
    } else {
        Box::new(0..=last_offset)
    };

    offsets
        .filter(|offset| {
            input_graphemes[*offset..*offset + needle_graphemes.len()] == needle_graphemes
        })
        .map(|offset| offset as i64)
        .next()
        .unwrap_or(-1)
}

fn eval_supported_constant_str_distance_call_arg(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<String, LabeledError> {
    let mut compare_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if compare_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str distance` requires exactly one compare-string argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`str distance` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str distance` compare argument cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(compare_expr) = compare_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str distance` requires exactly one compare-string argument in compile-time global initializers",
                span,
            ),
        );
    };
    eval_supported_constant_string_argument(working_set, compare_expr, env, "str distance")
}

fn eval_supported_constant_str_distance_external_arg(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<String, LabeledError> {
    let [compare_arg] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str distance` requires exactly one compare-string argument in compile-time global initializers",
                span,
            ),
        );
    };
    let ExternalArgument::Regular(compare_expr) = compare_arg else {
        return Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                "`str distance` compare argument cannot use spread syntax in compile-time global initializers",
                compare_arg.expr().span,
            ));
    };
    eval_supported_constant_string_argument(working_set, compare_expr, env, "str distance")
}

fn eval_supported_constant_str_distance(
    input: Option<Value>,
    compare: String,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str distance", input, span)?;
    let input = eval_supported_constant_exact_string_value(value, "str distance", span)?;
    Ok(Value::int(
        levenshtein_distance(&input, &compare) as i64,
        span,
    ))
}

fn eval_supported_constant_exact_string_value(
    value: Value,
    cmd_name: &str,
    span: Span,
) -> Result<String, LabeledError> {
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val),
        Value::Binary { val, .. } => String::from_utf8(val).map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires valid UTF-8 binary input in compile-time global initializers"
                ),
                span,
            )
        }),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires string input"),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_str_join_call_separator(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Option<String>, LabeledError> {
    let mut separator_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if separator_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str join` accepts at most one separator argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`str join` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str join` separator cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    separator_expr
        .map(|expr| eval_supported_constant_string_argument(working_set, expr, env, "str join"))
        .transpose()
}

fn eval_supported_constant_str_join_external_separator(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Option<String>, LabeledError> {
    match args {
        [] => Ok(None),
        [ExternalArgument::Regular(expr)] => {
            eval_supported_constant_string_argument(working_set, expr, env, "str join").map(Some)
        }
        [arg] => Err(LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(
                "`str join` separator cannot use spread syntax in compile-time global initializers",
                arg.expr().span,
            )),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str join` accepts at most one separator argument in compile-time global initializers",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_str_join(
    input: Option<Value>,
    separator: Option<String>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str join", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let items = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    eval_supported_constant_str_join_item_value(value, index, span)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let joined = if let Some(separator) = separator {
                items.join(&separator)
            } else {
                items.concat()
            };
            Ok(Value::string(joined, value_span))
        }
        value => {
            let input = eval_supported_constant_exact_string_value(value, "str join", span)?;
            Ok(Value::string(input, value_span))
        }
    }
}

fn eval_supported_constant_str_join_item_value(
    value: Value,
    index: usize,
    span: Span,
) -> Result<String, LabeledError> {
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val),
        Value::Int { val, .. } => Ok(val.to_string()),
        Value::Bool { val, .. } => Ok(val.to_string()),
        Value::Nothing { .. } => Ok(String::new()),
        value @ (Value::Float { .. }
        | Value::Filesize { .. }
        | Value::Duration { .. }
        | Value::Binary { .. }) => Ok(value.to_expanded_string("", &Config::default())),
        value @ (Value::List { .. } | Value::Record { .. }) => {
            Ok(value.to_expanded_string("\n", &Config::default()))
        }
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`str join` supports only string, int, float, filesize, duration, binary, bool, null, list, and record compile-time list items; item {index} has type {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

fn eval_supported_constant_str_stats(
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str stats", input, span)?;
    let value_span = value.span();
    let input = eval_supported_constant_exact_string_value(value, "str stats", span)?;
    let counts = [
        (
            "lines",
            eval_supported_constant_str_stats_line_count(&input) as i64,
        ),
        ("words", input.unicode_words().count() as i64),
        ("bytes", input.len() as i64),
        ("chars", input.chars().count() as i64),
        (
            "graphemes",
            UnicodeSegmentation::graphemes(input.as_str(), true).count() as i64,
        ),
        (
            "unicode-width",
            eval_supported_constant_str_stats_unicode_width(&input) as i64,
        ),
    ];

    let mut record = Record::new();
    for (name, count) in counts {
        record.push(name, Value::int(count, value_span));
    }
    Ok(Value::record(record, value_span))
}

fn eval_supported_constant_str_stats_line_count(input: &str) -> usize {
    if input.is_empty() {
        return 0;
    }

    const LINE_ENDINGS: [&str; 7] = [
        "\r\n", "\n", "\r", "\u{0085}", "\u{000C}", "\u{2028}", "\u{2029}",
    ];

    let mut count = 0;
    let mut index = 0;
    while index < input.len() {
        let rest = &input[index..];
        if rest.starts_with("\r\n") {
            count += 1;
            index += "\r\n".len();
            continue;
        }

        let Some(ch) = rest.chars().next() else {
            break;
        };
        if matches!(
            ch,
            '\n' | '\r' | '\u{0085}' | '\u{000C}' | '\u{2028}' | '\u{2029}'
        ) {
            count += 1;
        }
        index += ch.len_utf8();
    }

    if LINE_ENDINGS.iter().any(|ending| input.ends_with(ending)) {
        count
    } else {
        count + 1
    }
}

fn eval_supported_constant_str_stats_unicode_width(input: &str) -> usize {
    UnicodeSegmentation::graphemes(input, true)
        .map(|grapheme| {
            let width = UnicodeWidthStr::width(grapheme);
            if width == 0
                && grapheme
                    .chars()
                    .any(eval_supported_constant_str_stats_counts_width_one)
            {
                1
            } else {
                width
            }
        })
        .sum()
}

fn eval_supported_constant_str_stats_counts_width_one(ch: char) -> bool {
    ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}')
}

const MAX_CONSTANT_STRING_EXPAND_RESULTS: usize = 60;

fn eval_supported_constant_str_expand_args(
    args: &[nu_protocol::ast::Argument],
) -> Result<bool, LabeledError> {
    let mut use_path = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str expand --path` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                }
                if named.0.item == "path" {
                    use_path = true;
                } else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str expand` supports only --path in compile-time global initializers",
                        arg.span(),
                    ));
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str expand` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str expand` does not accept positional arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }
    Ok(use_path)
}

fn eval_supported_constant_str_expand_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<bool, LabeledError> {
    let mut use_path = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`str expand` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str expand` accepts only string flags in compile-time global initializers",
                        expr.span,
                    ));
            }
        };
        match flag.as_str() {
            "--path" => use_path = true,
            _ if flag.starts_with("--") => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str expand` supports only --path in compile-time global initializers",
                            expr.span,
                        ),
                );
            }
            _ => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str expand` does not accept positional arguments in compile-time global initializers",
                            span,
                        ),
                );
            }
        }
    }
    Ok(use_path)
}

fn eval_supported_constant_str_expand(
    input: Option<Value>,
    use_path: bool,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str expand", input, span)?;
    let value_span = value.span();
    let input = eval_supported_constant_exact_string_value(value, "str expand", span)?;
    let expansion_input = if use_path {
        input.replace('\\', "\\\\")
    } else {
        input
    };
    let outputs = eval_supported_constant_str_expand_pattern(&expansion_input, span)?;
    Ok(Value::list(
        outputs
            .into_iter()
            .map(|output| Value::string(output, value_span))
            .collect(),
        value_span,
    ))
}

fn eval_supported_constant_str_expand_pattern(
    input: &str,
    span: Span,
) -> Result<Vec<String>, LabeledError> {
    let mut saw_braces = false;
    let outputs = eval_supported_constant_str_expand_segment(input, &mut saw_braces, span)?;
    if !saw_braces {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str expand` requires at least one brace expression in compile-time global initializers",
                span,
            ),
        );
    }
    if outputs.len() > MAX_CONSTANT_STRING_EXPAND_RESULTS {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`str expand` produced {} strings; compile-time global initializers support at most {}",
                    outputs.len(),
                    MAX_CONSTANT_STRING_EXPAND_RESULTS
                ),
                span,
            ),
        );
    }
    for output in &outputs {
        if output.len().saturating_add(1) > MAX_STRING_SIZE {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`str expand` output requires {} bytes (limit {}) in compile-time global initializers",
                        output.len() + 1,
                        MAX_STRING_SIZE
                    ),
                    span,
                ),
            );
        }
    }
    Ok(outputs)
}

fn eval_supported_constant_str_expand_segment(
    input: &str,
    saw_braces: &mut bool,
    span: Span,
) -> Result<Vec<String>, LabeledError> {
    let Some(open) = eval_supported_constant_str_expand_find_open_brace(input, span)? else {
        return Ok(vec![eval_supported_constant_str_expand_unescape(input)]);
    };
    *saw_braces = true;
    let close = eval_supported_constant_str_expand_find_matching_brace(input, open, span)?;
    let prefix = eval_supported_constant_str_expand_unescape(&input[..open]);
    let inner = &input[open + '{'.len_utf8()..close];
    let suffix = &input[close + '}'.len_utf8()..];
    let alternatives = eval_supported_constant_str_expand_alternatives(inner, saw_braces, span)?;
    let suffixes = eval_supported_constant_str_expand_segment(suffix, saw_braces, span)?;

    let mut outputs = Vec::new();
    for alternative in alternatives {
        for suffix in &suffixes {
            outputs.push(format!("{prefix}{alternative}{suffix}"));
            if outputs.len() > MAX_CONSTANT_STRING_EXPAND_RESULTS {
                return Ok(outputs);
            }
        }
    }
    Ok(outputs)
}

fn eval_supported_constant_str_expand_alternatives(
    input: &str,
    saw_braces: &mut bool,
    span: Span,
) -> Result<Vec<String>, LabeledError> {
    if let Some(parts) = eval_supported_constant_str_expand_split_commas(input, span)? {
        let mut outputs = Vec::new();
        for part in parts {
            outputs.extend(eval_supported_constant_str_expand_segment(
                part, saw_braces, span,
            )?);
            if outputs.len() > MAX_CONSTANT_STRING_EXPAND_RESULTS {
                return Ok(outputs);
            }
        }
        return Ok(outputs);
    }

    if let Some(range) = eval_supported_constant_str_expand_numeric_range(input, span)? {
        return Ok(range);
    }

    eval_supported_constant_str_expand_segment(input, saw_braces, span)
}

fn eval_supported_constant_str_expand_find_open_brace(
    input: &str,
    span: Span,
) -> Result<Option<usize>, LabeledError> {
    let mut escaped = false;
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => return Ok(Some(index)),
            '}' => {
                return Err(eval_supported_constant_str_expand_balanced_error(span));
            }
            _ => {}
        }
    }
    Ok(None)
}

fn eval_supported_constant_str_expand_find_matching_brace(
    input: &str,
    open: usize,
    span: Span,
) -> Result<usize, LabeledError> {
    let mut escaped = false;
    let mut depth = 1usize;
    for (offset, ch) in input[open + '{'.len_utf8()..].char_indices() {
        let index = open + '{'.len_utf8() + offset;
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {}
        }
    }
    Err(eval_supported_constant_str_expand_balanced_error(span))
}

fn eval_supported_constant_str_expand_split_commas<'a>(
    input: &'a str,
    span: Span,
) -> Result<Option<Vec<&'a str>>, LabeledError> {
    let mut escaped = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => depth = depth.saturating_add(1),
            '}' if depth == 0 => {
                return Err(eval_supported_constant_str_expand_balanced_error(span));
            }
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&input[start..index]);
                start = index + ','.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(eval_supported_constant_str_expand_balanced_error(span));
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        parts.push(&input[start..]);
        Ok(Some(parts))
    }
}

fn eval_supported_constant_str_expand_numeric_range(
    input: &str,
    span: Span,
) -> Result<Option<Vec<String>>, LabeledError> {
    let mut escaped = false;
    let mut ranges = Vec::new();
    let mut iter = input.char_indices().peekable();
    while let Some((index, ch)) = iter.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '.'
            && let Some((_, '.')) = iter.peek().copied()
        {
            ranges.push(index);
            iter.next();
        }
    }

    match ranges.as_slice() {
        [] => Ok(None),
        [_first, _second, ..] => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str expand` numeric ranges must use exactly one '..' operator in compile-time global initializers",
                span,
            ),
        ),
        [range_index] => {
            let start_text = eval_supported_constant_str_expand_unescape(&input[..*range_index]);
            let end_text =
                eval_supported_constant_str_expand_unescape(&input[*range_index + 2..]);
            if start_text.is_empty()
                || end_text.is_empty()
                || !start_text.chars().all(|ch| ch.is_ascii_digit())
                || !end_text.chars().all(|ch| ch.is_ascii_digit())
            {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str expand` numeric ranges must use unsigned integer bounds in compile-time global initializers",
                            span,
                        ),
                );
            }

            let start = start_text.parse::<u64>().map_err(|err| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`str expand` range start is too large in global initializers: {err}"),
                    span,
                )
            })?;
            let end = end_text.parse::<u64>().map_err(|err| {
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`str expand` range end is too large in global initializers: {err}"),
                    span,
                )
            })?;
            if start > end {
                return Ok(Some(Vec::new()));
            }
            let count = end.saturating_sub(start).saturating_add(1);
            if count > MAX_CONSTANT_STRING_EXPAND_RESULTS as u64 {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`str expand` range produces {count} strings; compile-time global initializers support at most {MAX_CONSTANT_STRING_EXPAND_RESULTS}"
                            ),
                            span,
                        ),
                );
            }

            let padded = start_text.starts_with('0') || end_text.starts_with('0');
            let width = if padded {
                start_text.len().max(end_text.len())
            } else {
                0
            };
            Ok(Some(
                (start..=end)
                    .map(|value| {
                        if padded {
                            format!("{value:0width$}")
                        } else {
                            value.to_string()
                        }
                    })
                    .collect(),
            ))
        }
    }
}

fn eval_supported_constant_str_expand_unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\'
            && let Some(next) = chars.next()
        {
            out.push(next);
        } else {
            out.push(ch);
        }
    }
    out
}

fn eval_supported_constant_str_expand_balanced_error(span: Span) -> LabeledError {
    LabeledError::new("Unsupported annotated mutable global initializer").with_label(
        "`str expand` requires balanced brace expressions in compile-time global initializers",
        span,
    )
}

#[derive(Clone, Copy)]
struct ConstantStrTrimArgs {
    trim_char: Option<char>,
    trim_left: bool,
    trim_right: bool,
}

fn eval_supported_constant_str_trim_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantStrTrimArgs, LabeledError> {
    let mut trim_char = None;
    let mut trim_left = false;
    let mut trim_right = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "left" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str trim --left` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    trim_left = true;
                }
                "right" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str trim --right` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    trim_right = true;
                }
                "char" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str trim --char` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    let raw = eval_supported_constant_string_argument(
                        working_set,
                        expr,
                        env,
                        "str trim",
                    )?;
                    if trim_char
                        .replace(eval_supported_constant_str_trim_char_value(
                            &raw, expr.span,
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str trim` accepts only one --char value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`str trim` does not support named argument --{} in compile-time global initializers",
                                named.0.item
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str trim` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str trim` does not support positional arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }
    Ok(ConstantStrTrimArgs {
        trim_char,
        trim_left,
        trim_right,
    })
}

fn eval_supported_constant_str_trim_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrTrimArgs, LabeledError> {
    let mut trim_char = None;
    let mut trim_left = false;
    let mut trim_right = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`str trim` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str trim` accepts only string flags in compile-time global initializers",
                        expr.span,
                    ));
            }
        };
        let Some(flag) = flag.strip_prefix("--") else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`str trim` does not support positional arguments in compile-time global initializers",
                    span,
                ),
            );
        };
        match flag {
            "left" => trim_left = true,
            "right" => trim_right = true,
            "char" => {
                let Some(next_arg) = iter.next() else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str trim --char` requires a value in compile-time global initializers",
                        expr.span,
                    ));
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str trim --char` value cannot use spread syntax in compile-time global initializers",
                        next_arg.expr().span,
                    ));
                };
                let raw = eval_supported_constant_string_argument(
                    working_set,
                    next_expr,
                    env,
                    "str trim",
                )?;
                if trim_char
                    .replace(eval_supported_constant_str_trim_char_value(
                        &raw,
                        next_expr.span,
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str trim` accepts only one --char value in compile-time global initializers",
                        next_expr.span,
                    ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str trim` supports only --left, --right, and --char in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }
    Ok(ConstantStrTrimArgs {
        trim_char,
        trim_left,
        trim_right,
    })
}

fn eval_supported_constant_str_trim_char_value(
    raw: &str,
    span: Span,
) -> Result<char, LabeledError> {
    let mut chars = raw.chars();
    let Some(ch) = chars.next() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str trim --char` requires exactly one character in compile-time global initializers",
                span,
            ),
        );
    };
    if chars.next().is_some() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str trim --char` requires exactly one character in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(ch)
}

fn eval_supported_constant_str_trim(
    input: Option<Value>,
    args: ConstantStrTrimArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str trim", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`str trim` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::string(
                        eval_supported_constant_trim_known_string(input, args),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        value => {
            let input = eval_supported_constant_exact_string_value(value, "str trim", span)?;
            Ok(Value::string(
                eval_supported_constant_trim_known_string(input, args),
                value_span,
            ))
        }
    }
}

fn eval_supported_constant_trim_known_string(input: String, args: ConstantStrTrimArgs) -> String {
    match (args.trim_char, args.trim_left, args.trim_right) {
        (Some(ch), true, false) => input.trim_start_matches(ch).to_string(),
        (Some(ch), false, true) => input.trim_end_matches(ch).to_string(),
        (Some(ch), _, _) => input.trim_matches(ch).to_string(),
        (None, true, false) => input.trim_start().to_string(),
        (None, false, true) => input.trim_end().to_string(),
        (None, _, _) => input.trim().to_string(),
    }
}

#[derive(Clone, Copy)]
struct ConstantMaybeOpenRange {
    start: Option<i64>,
    end: Option<i64>,
    inclusive: bool,
}

#[derive(Clone, Copy)]
struct ConstantStrSubstringArgs {
    range: ConstantMaybeOpenRange,
    use_grapheme_clusters: bool,
}

fn eval_supported_constant_str_substring_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrSubstringArgs, LabeledError> {
    let mut range_expr = None;
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if range_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str substring` requires exactly one explicit range argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str substring` mode flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                }
                match named.0.item.as_str() {
                    "utf-8-bytes" => use_utf8_bytes = true,
                    "grapheme-clusters" => use_grapheme_clusters = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str substring` supports only --utf-8-bytes and --grapheme-clusters flags in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str substring` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(range_expr) = range_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str substring` requires exactly one explicit range argument in compile-time global initializers",
                span,
            ),
        );
    };
    let range =
        eval_supported_constant_range_argument(working_set, range_expr, env, "str substring")?;
    let use_grapheme_clusters = eval_supported_constant_str_substring_validate_modes(
        use_utf8_bytes,
        use_grapheme_clusters,
        span,
    )?;

    Ok(ConstantStrSubstringArgs {
        range,
        use_grapheme_clusters,
    })
}

fn eval_supported_constant_str_substring_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrSubstringArgs, LabeledError> {
    let mut range = None;
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`str substring` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        if let Expr::GlobPattern(token, _) = &expr.expr
            && !token.starts_with("--")
            && let Some(parsed_range) =
                eval_supported_constant_range_token(token, expr.span, "str substring")?
        {
            if range.replace(parsed_range).is_some() {
                return Err(LabeledError::new(
                    "Unsupported annotated mutable global initializer",
                )
                .with_label(
                    "`str substring` requires exactly one explicit range argument in compile-time global initializers",
                    expr.span,
                ));
            }
            continue;
        }
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        match value {
            Value::String { val, .. } | Value::Glob { val, .. } => {
                let Some(flag) = val.strip_prefix("--") else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str substring` requires a compile-time range argument in global initializers",
                        expr.span,
                    ));
                };
                match flag {
                    "utf-8-bytes" => use_utf8_bytes = true,
                    "grapheme-clusters" => use_grapheme_clusters = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str substring` supports only --utf-8-bytes and --grapheme-clusters flags in compile-time global initializers",
                            expr.span,
                        ));
                    }
                }
            }
            value @ Value::Range { .. } => {
                if range
                    .replace(eval_supported_constant_range_value(
                        value,
                        expr.span,
                        "str substring",
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str substring` requires exactly one explicit range argument in compile-time global initializers",
                        expr.span,
                    ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str substring` requires a compile-time range argument in global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(range) = range else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str substring` requires exactly one explicit range argument in compile-time global initializers",
                span,
            ),
        );
    };
    let use_grapheme_clusters = eval_supported_constant_str_substring_validate_modes(
        use_utf8_bytes,
        use_grapheme_clusters,
        span,
    )?;

    Ok(ConstantStrSubstringArgs {
        range,
        use_grapheme_clusters,
    })
}

fn eval_supported_constant_range_argument(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    cmd_name: &str,
) -> Result<ConstantMaybeOpenRange, LabeledError> {
    if let Expr::Range(range) = &expr.expr {
        return eval_supported_constant_ast_range(working_set, range, env, cmd_name);
    }
    if let Expr::GlobPattern(token, _) = &expr.expr
        && let Some(range) = eval_supported_constant_range_token(token, expr.span, cmd_name)?
    {
        return Ok(range);
    }

    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    eval_supported_constant_range_value(value, expr.span, cmd_name)
}

fn eval_supported_constant_ast_range(
    working_set: &StateWorkingSet,
    range: &nu_protocol::ast::Range,
    env: &HashMap<nu_protocol::VarId, Value>,
    cmd_name: &str,
) -> Result<ConstantMaybeOpenRange, LabeledError> {
    let start = range
        .from
        .as_ref()
        .map(|expr| eval_supported_constant_int_range_endpoint(working_set, expr, env, cmd_name))
        .transpose()?;
    let end = range
        .to
        .as_ref()
        .map(|expr| eval_supported_constant_int_range_endpoint(working_set, expr, env, cmd_name))
        .transpose()?;
    if let Some(next_expr) = range.next.as_ref() {
        let next =
            eval_supported_constant_int_range_endpoint(working_set, next_expr, env, cmd_name)?;
        if next == start.unwrap_or(0) {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`{cmd_name}` range step cannot be zero in global initializers"),
                    next_expr.span,
                ),
            );
        }
    }
    Ok(ConstantMaybeOpenRange {
        start,
        end,
        inclusive: range.operator.inclusion == RangeInclusion::Inclusive,
    })
}

fn eval_supported_constant_range_token(
    token: &str,
    span: Span,
    cmd_name: &str,
) -> Result<Option<ConstantMaybeOpenRange>, LabeledError> {
    if token.starts_with("...") || !token.contains("..") {
        return Ok(None);
    }

    let dotdot_pos = token
        .match_indices("..")
        .map(|(pos, _)| pos)
        .collect::<Vec<_>>();
    let (next_op_pos, range_op_pos) = match dotdot_pos.as_slice() {
        [range_op_pos] => (None, *range_op_pos),
        [next_op_pos, range_op_pos] => (Some(*next_op_pos), *range_op_pos),
        _ => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`{cmd_name}` requires an integer range with one range operator in global initializers"),
                    span,
                ),
            );
        }
    };

    let (range_op, inclusive) = if token[range_op_pos..].starts_with("..<") {
        ("..<", false)
    } else if token[range_op_pos..].starts_with("..=") {
        ("..=", true)
    } else {
        ("..", true)
    };
    let range_op_end = range_op_pos + range_op.len();
    if next_op_pos.is_some_and(|pos| pos + 2 > range_op_pos) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` requires a valid integer range in global initializers"),
                span,
            ),
        );
    }

    let start_text = if token.starts_with("..") {
        None
    } else {
        Some(&token[..dotdot_pos[0]])
    };
    let next_text = next_op_pos.map(|pos| &token[pos + 2..range_op_pos]);
    let end_text = if token.len() == range_op_end {
        None
    } else {
        Some(&token[range_op_end..])
    };

    if start_text.is_none() && end_text.is_none() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires at least one integer range bound in global initializers"
                ),
                span,
            ),
        );
    }

    let start = start_text
        .map(|text| eval_supported_constant_parse_int_range_bound(text, span, cmd_name))
        .transpose()?;
    let next = next_text
        .map(|text| eval_supported_constant_parse_int_range_bound(text, span, cmd_name))
        .transpose()?;
    if let (Some(start), Some(next)) = (start, next)
        && start == next
    {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` range step cannot be zero in global initializers"),
                span,
            ),
        );
    }
    let end = end_text
        .map(|text| eval_supported_constant_parse_int_range_bound(text, span, cmd_name))
        .transpose()?;

    Ok(Some(ConstantMaybeOpenRange {
        start,
        end,
        inclusive,
    }))
}

fn eval_supported_constant_parse_int_range_bound(
    text: &str,
    span: Span,
    cmd_name: &str,
) -> Result<i64, LabeledError> {
    text.parse::<i64>().map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{cmd_name}` requires integer range bounds in global initializers"),
            span,
        )
    })
}

fn eval_supported_constant_int_range_endpoint(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    cmd_name: &str,
) -> Result<i64, LabeledError> {
    eval_supported_constant_value_with_env(working_set, expr, env)?
        .as_int()
        .map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` requires integer range bounds in global initializers"),
                expr.span,
            )
        })
}

fn eval_supported_constant_range_value(
    value: Value,
    span: Span,
    cmd_name: &str,
) -> Result<ConstantMaybeOpenRange, LabeledError> {
    let Value::Range { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires a compile-time range argument in global initializers"
                ),
                span,
            ),
        );
    };
    let Range::IntRange(range) = *val else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` requires an integer range in global initializers"),
                span,
            ),
        );
    };
    let (end, inclusive) = match range.end() {
        Bound::Included(end) => (Some(end), true),
        Bound::Excluded(end) => (Some(end), false),
        Bound::Unbounded => (None, false),
    };
    Ok(ConstantMaybeOpenRange {
        start: Some(range.start()),
        end,
        inclusive,
    })
}

fn eval_supported_constant_str_substring_validate_modes(
    use_utf8_bytes: bool,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<bool, LabeledError> {
    if use_utf8_bytes && use_grapheme_clusters {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str substring` accepts either --utf-8-bytes or --grapheme-clusters, not both, in compile-time global initializers",
                span,
            ),
        );
    }
    Ok(use_grapheme_clusters)
}

fn eval_supported_constant_str_substring(
    input: Option<Value>,
    args: ConstantStrSubstringArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str substring", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`str substring` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::string(
                        eval_supported_constant_substring_known_string(
                            input,
                            args.range,
                            args.use_grapheme_clusters,
                            span,
                        )?,
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(Value::string(
            eval_supported_constant_substring_known_string(
                val,
                args.range,
                args.use_grapheme_clusters,
                span,
            )?,
            value_span,
        )),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str substring` in a compile-time global initializer requires string or list<string> input",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_substring_known_string(
    input: String,
    range: ConstantMaybeOpenRange,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<String, LabeledError> {
    if use_grapheme_clusters {
        let graphemes = UnicodeSegmentation::graphemes(input.as_str(), true).collect::<Vec<_>>();
        let (start, end) = eval_supported_constant_string_range_bounds(range, graphemes.len());
        return Ok(graphemes[start..end].concat());
    }

    let (start, end) = eval_supported_constant_string_range_bounds(range, input.len());
    let bytes = input.as_bytes().get(start..end).ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`str substring` produced invalid byte bounds in compile-time global initializers",
            span,
        )
    })?;
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`str substring` byte bounds must preserve valid UTF-8 in compile-time global initializers",
            span,
        )
    })
}

#[derive(Clone)]
struct ConstantStrReplaceArgs {
    find: String,
    replacement: String,
    replace_all: bool,
    use_regex: bool,
    no_expand: bool,
    multiline: bool,
}

fn eval_supported_constant_str_replace_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrReplaceArgs, LabeledError> {
    let mut positional = Vec::new();
    let mut replace_all = false;
    let mut regex = false;
    let mut no_expand = false;
    let mut multiline = false;

    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if positional.len() == 2 {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`str replace` requires exactly two string arguments in compile-time global initializers",
                            arg.span(),
                        ));
                }
                positional.push(expr);
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "all" | "regex" | "no-expand" | "multiline" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                "`str replace` flags cannot receive values in compile-time global initializers",
                                arg.span(),
                            ));
                    }
                    match named.0.item.as_str() {
                        "all" => replace_all = true,
                        "regex" => regex = true,
                        "no-expand" => no_expand = true,
                        "multiline" => multiline = true,
                        _ => unreachable!("validated str replace flag"),
                    }
                }
                _ => {
                    return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`str replace` supports only --all, --regex, --multiline, and --no-expand in compile-time global initializers",
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str replace` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let [find_expr, replacement_expr] = positional.as_slice() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str replace` requires exactly two string arguments in compile-time global initializers",
                span,
            ),
        );
    };
    let find = eval_supported_constant_string_argument(working_set, find_expr, env, "str replace")?;
    let replacement =
        eval_supported_constant_string_argument(working_set, replacement_expr, env, "str replace")?;

    Ok(ConstantStrReplaceArgs {
        find,
        replacement,
        replace_all,
        use_regex: regex || multiline,
        no_expand,
        multiline,
    })
}

fn eval_supported_constant_str_replace_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantStrReplaceArgs, LabeledError> {
    let mut positional = Vec::new();
    let mut replace_all = false;
    let mut regex = false;
    let mut no_expand = false;
    let mut multiline = false;

    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`str replace` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let raw = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str replace` arguments must be compile-time strings in global initializers",
                        expr.span,
                    ));
            }
        };
        match raw.as_str() {
            "--all" => replace_all = true,
            "--regex" => regex = true,
            "--no-expand" => no_expand = true,
            "--multiline" => multiline = true,
            _ if raw.starts_with("--") => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`str replace` supports only --all, --regex, --multiline, and --no-expand in compile-time global initializers",
                        expr.span,
                    ));
            }
            _ => {
                if positional.len() == 2 {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`str replace` requires exactly two string arguments in compile-time global initializers",
                        expr.span,
                    ));
                }
                positional.push(raw);
            }
        }
    }

    if positional.len() != 2 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str replace` requires exactly two string arguments in compile-time global initializers",
                span,
            ),
        );
    }
    let mut positional = positional.into_iter();
    let find = positional
        .next()
        .expect("str replace positional count checked");
    let replacement = positional
        .next()
        .expect("str replace positional count checked");

    Ok(ConstantStrReplaceArgs {
        find,
        replacement,
        replace_all,
        use_regex: regex || multiline,
        no_expand,
        multiline,
    })
}

fn eval_supported_constant_str_replace(
    input: Option<Value>,
    args: ConstantStrReplaceArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("str replace", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`str replace` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::string(
                        eval_supported_constant_replace_known_string(&input, &args, span)?,
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(Value::string(
            eval_supported_constant_replace_known_string(&val, &args, span)?,
            value_span,
        )),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str replace` in a compile-time global initializer requires string or list<string> input",
                span,
            ),
        ),
    }
}

fn eval_supported_constant_replace_known_string(
    input: &str,
    args: &ConstantStrReplaceArgs,
    span: Span,
) -> Result<String, LabeledError> {
    if args.use_regex {
        eval_supported_constant_string_replace_regex(input, args, span)
    } else if args.replace_all {
        Ok(input.replace(&args.find, &args.replacement))
    } else {
        Ok(input.replacen(&args.find, &args.replacement, 1))
    }
}

fn eval_supported_constant_string_replace_regex(
    input: &str,
    args: &ConstantStrReplaceArgs,
    span: Span,
) -> Result<String, LabeledError> {
    let pattern = if args.multiline {
        format!("(?m){}", args.find)
    } else {
        args.find.clone()
    };
    let regex = FancyRegex::new(&pattern).map_err(|err| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`str replace --regex` pattern is invalid in compile-time global initializers: {err}"
            ),
            span,
        )
    })?;
    let limit = if args.replace_all { 0 } else { 1 };
    let output = if args.no_expand {
        regex.try_replacen(input, limit, NoExpand(args.replacement.as_str()))
    } else {
        regex.try_replacen(input, limit, args.replacement.as_str())
    }
    .map_err(|err| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`str replace --regex` failed at compile time in global initializers: {err}"),
            span,
        )
    })?;
    Ok(output.into_owned())
}

fn eval_supported_constant_string_range_bounds(
    range: ConstantMaybeOpenRange,
    len: usize,
) -> (usize, usize) {
    let len = len as i64;
    let start = range
        .start
        .map(|start| eval_supported_constant_substring_start_bound(start, len))
        .unwrap_or(0);
    let end = range
        .end
        .map(|end| eval_supported_constant_substring_end_bound(end, range.inclusive, len))
        .unwrap_or(len)
        .max(start);
    (start as usize, end as usize)
}

fn eval_supported_constant_substring_start_bound(index: i64, len: i64) -> i64 {
    let raw = if index < 0 {
        len.saturating_add(index)
    } else {
        index
    };
    raw.clamp(0, len)
}

fn eval_supported_constant_substring_end_bound(index: i64, inclusive: bool, len: i64) -> i64 {
    let raw = if index < 0 {
        len.saturating_add(index)
    } else {
        index
    };
    let exclusive = if inclusive {
        raw.saturating_add(1)
    } else {
        raw
    };
    exclusive.clamp(0, len)
}

fn eval_supported_constant_str_transform(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input(cmd_name, input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let values = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`{cmd_name}` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::string(
                        eval_supported_constant_known_string_transform(cmd_name, input)?,
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(values, value_span))
        }
        value => {
            let input = eval_supported_constant_exact_string_value(value, cmd_name, span)?;
            Ok(Value::string(
                eval_supported_constant_known_string_transform(cmd_name, input)?,
                value_span,
            ))
        }
    }
}

fn eval_supported_constant_known_string_transform(
    cmd_name: &str,
    input: String,
) -> Result<String, LabeledError> {
    match cmd_name {
        "str downcase" => Ok(input.to_lowercase()),
        "str upcase" => Ok(input.to_uppercase()),
        "str reverse" => Ok(input.chars().rev().collect()),
        "str capitalize" => Ok(eval_supported_constant_capitalize_first_char(&input)),
        "str camel-case" => Ok(input.to_lower_camel_case()),
        "str kebab-case" => Ok(input.to_kebab_case()),
        "str pascal-case" => Ok(input.to_upper_camel_case()),
        "str screaming-snake-case" => Ok(input.to_shouty_snake_case()),
        "str snake-case" => Ok(input.to_snake_case()),
        "str title-case" => Ok(input.to_title_case()),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("unsupported string transform command `{cmd_name}`"),
                Span::unknown(),
            ),
        ),
    }
}

fn eval_supported_constant_capitalize_first_char(input: &str) -> String {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };

    let mut output = first.to_uppercase().collect::<String>();
    output.push_str(chars.as_str());
    output
}

fn eval_supported_constant_split_chars_mode_call(
    args: &[nu_protocol::ast::Argument],
) -> Result<bool, LabeledError> {
    let mut use_code_points = false;
    let mut use_grapheme_clusters = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                if named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`split chars` flags cannot receive values in compile-time global initializers",
                            arg.span(),
                        ));
                }
                match named.0.item.as_str() {
                    "code-points" => use_code_points = true,
                    "grapheme-clusters" => use_grapheme_clusters = true,
                    _ => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split chars` supports only --code-points and --grapheme-clusters in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split chars` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`split chars` does not accept arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }

    eval_supported_constant_split_chars_validate_modes(
        use_code_points,
        use_grapheme_clusters,
        Span::unknown(),
    )
}

fn eval_supported_constant_split_chars_mode_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<bool, LabeledError> {
    let mut use_code_points = false;
    let mut use_grapheme_clusters = false;
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`split chars` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split chars` accepts only string flags in compile-time global initializers",
                        expr.span,
                    ));
            }
        };
        let Some(flag) = flag.strip_prefix("--") else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`split chars` does not accept arguments in compile-time global initializers",
                    span,
                ),
            );
        };
        match flag {
            "code-points" => use_code_points = true,
            "grapheme-clusters" => use_grapheme_clusters = true,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split chars` supports only --code-points and --grapheme-clusters in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_split_chars_validate_modes(use_code_points, use_grapheme_clusters, span)
}

fn eval_supported_constant_split_chars_validate_modes(
    use_code_points: bool,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<bool, LabeledError> {
    if use_code_points && use_grapheme_clusters {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split chars` accepts either --code-points or --grapheme-clusters, not both, in compile-time global initializers",
                span,
            ),
        );
    }

    Ok(use_grapheme_clusters)
}

fn eval_supported_constant_split_chars(
    input: Option<Value>,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("split chars", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let items = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`split chars` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::list(
                        eval_supported_constant_split_chars_known_string(
                            &input,
                            use_grapheme_clusters,
                            value_span,
                        ),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(items, value_span))
        }
        value => {
            let input = eval_supported_constant_exact_string_value(value, "split chars", span)?;
            Ok(Value::list(
                eval_supported_constant_split_chars_known_string(
                    &input,
                    use_grapheme_clusters,
                    value_span,
                ),
                value_span,
            ))
        }
    }
}

fn eval_supported_constant_split_chars_known_string(
    input: &str,
    use_grapheme_clusters: bool,
    span: Span,
) -> Vec<Value> {
    if use_grapheme_clusters {
        UnicodeSegmentation::graphemes(input, true)
            .map(|part| Value::string(part, span))
            .collect()
    } else {
        input
            .chars()
            .map(|ch| Value::string(ch.to_string(), span))
            .collect()
    }
}

#[derive(Clone, Copy)]
enum ConstantSplitListMode {
    On,
    Before,
    After,
}

struct ConstantSplitListArgs {
    separator: Value,
    mode: ConstantSplitListMode,
    use_regex: bool,
}

fn eval_supported_constant_split_list_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantSplitListArgs, LabeledError> {
    let mut separator_expr = None;
    let mut mode = None;
    let mut use_regex = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if separator_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`split list` accepts exactly one separator argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "regex" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split list --regex` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    use_regex = true;
                }
                "split" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split list --split` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    if mode
                        .replace(eval_supported_constant_split_list_mode_argument(
                            working_set,
                            expr,
                            env,
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split list` accepts only one --split value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`split list` does not support named argument --{} in compile-time global initializers",
                                named.0.item
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split list` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(separator_expr) = separator_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split list` requires exactly one separator argument in compile-time global initializers",
                Span::unknown(),
            ),
        );
    };
    Ok(ConstantSplitListArgs {
        separator: eval_supported_constant_value_with_env(working_set, separator_expr, env)?,
        mode: mode.unwrap_or(ConstantSplitListMode::On),
        use_regex,
    })
}

fn eval_supported_constant_split_list_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantSplitListArgs, LabeledError> {
    let mut separator = None;
    let mut mode = None;
    let mut use_regex = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`split list` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match &value {
            Value::String { val, .. } | Value::Glob { val, .. } => val.strip_prefix("--"),
            _ => None,
        };
        let Some(flag) = flag else {
            if separator.replace(value).is_some() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split list` accepts exactly one separator argument in compile-time global initializers",
                        expr.span,
                    ));
            }
            continue;
        };
        match flag {
            "regex" => use_regex = true,
            "split" => {
                let Some(next_arg) = iter.next() else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split list --split` requires a value in compile-time global initializers",
                        expr.span,
                    ));
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split list --split` value cannot use spread syntax in compile-time global initializers",
                        next_arg.expr().span,
                    ));
                };
                if mode
                    .replace(eval_supported_constant_split_list_mode_argument(
                        working_set,
                        next_expr,
                        env,
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split list` accepts only one --split value in compile-time global initializers",
                        next_expr.span,
                    ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split list` supports only --split and --regex in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(separator) = separator else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split list` requires exactly one separator argument in compile-time global initializers",
                span,
            ),
        );
    };
    Ok(ConstantSplitListArgs {
        separator,
        mode: mode.unwrap_or(ConstantSplitListMode::On),
        use_regex,
    })
}

fn eval_supported_constant_split_list_mode_argument(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantSplitListMode, LabeledError> {
    let mode = eval_supported_constant_string_argument(working_set, expr, env, "split list")?;
    match mode.as_str() {
        "on" => Ok(ConstantSplitListMode::On),
        "before" => Ok(ConstantSplitListMode::Before),
        "after" => Ok(ConstantSplitListMode::After),
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`split list --split` must be 'on', 'before', or 'after' in compile-time global initializers, got '{mode}'"
                ),
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_split_list(
    input: Option<Value>,
    args: ConstantSplitListArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("split list", input, span)?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split list` requires a compile-time known list pipeline input in global initializers",
                span,
            ),
        );
    };

    let regex = if args.use_regex {
        Some(eval_supported_constant_split_list_regex(
            &args.separator,
            span,
        )?)
    } else {
        None
    };
    let mut groups = vec![Vec::new()];
    for value in vals {
        let is_separator = if let Some(regex) = regex.as_ref() {
            eval_supported_constant_split_list_regex_matches(&value, regex, span)?
        } else {
            value == args.separator
        };
        if is_separator {
            match args.mode {
                ConstantSplitListMode::On => groups.push(Vec::new()),
                ConstantSplitListMode::Before => groups.push(vec![value]),
                ConstantSplitListMode::After => {
                    groups
                        .last_mut()
                        .expect("split list always has a current group")
                        .push(value);
                    groups.push(Vec::new());
                }
            }
        } else {
            groups
                .last_mut()
                .expect("split list always has a current group")
                .push(value);
        }
    }

    Ok(Value::list(
        groups
            .into_iter()
            .map(|group| Value::list(group, value_span))
            .collect(),
        value_span,
    ))
}

fn eval_supported_constant_split_list_regex(
    separator: &Value,
    span: Span,
) -> Result<FancyRegex, LabeledError> {
    let pattern = match separator {
        Value::String { val, .. } | Value::Glob { val, .. } => val,
        other => {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`split list --regex` separator must be a compile-time string in global initializers; got {}",
                        other.get_type()
                    ),
                    span,
                ),
            );
        }
    };
    FancyRegex::new(pattern).map_err(|err| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`split list --regex` pattern is invalid in global initializers: {err}"),
            span,
        )
    })
}

fn eval_supported_constant_split_list_regex_matches(
    value: &Value,
    regex: &FancyRegex,
    span: Span,
) -> Result<bool, LabeledError> {
    let Some(text) = eval_supported_constant_split_list_regex_item_text(value, span)? else {
        return Ok(false);
    };
    regex.is_match(&text).map_err(|err| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`split list --regex` failed at compile time in global initializers: {err}"),
            span,
        )
    })
}

fn eval_supported_constant_split_list_regex_item_text(
    value: &Value,
    span: Span,
) -> Result<Option<String>, LabeledError> {
    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(Some(val.clone())),
        Value::Int { val, .. } => Ok(Some(val.to_string())),
        Value::Bool { val, .. } => Ok(Some(val.to_string())),
        Value::Nothing { .. } | Value::Filesize { .. } | Value::Duration { .. } => Ok(None),
        other => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`split list --regex` supports only string, int, bool, null, filesize, and duration compile-time list items; got {}",
                    other.get_type()
                ),
                span,
            ),
        ),
    }
}

struct ConstantSplitRowArgs {
    separator: String,
    number: Option<usize>,
    use_regex: bool,
}

fn eval_supported_constant_split_row_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantSplitRowArgs, LabeledError> {
    let mut separator_expr = None;
    let mut number = None;
    let mut use_regex = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if separator_expr.replace(expr).is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`split row` accepts exactly one separator argument in compile-time global initializers",
                            arg.span(),
                        ));
                }
            }
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "regex" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split row --regex` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    use_regex = true;
                }
                "number" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split row --number` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    if number
                        .replace(eval_supported_constant_non_negative_usize_argument(
                            working_set,
                            expr,
                            env,
                            "split row --number",
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split row` accepts only one --number value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`split row` does not support named argument --{} in compile-time global initializers",
                                named.0.item
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split row` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(separator_expr) = separator_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split row` requires exactly one separator argument in compile-time global initializers",
                Span::unknown(),
            ),
        );
    };
    let separator =
        eval_supported_constant_string_argument(working_set, separator_expr, env, "split row")?;
    Ok(ConstantSplitRowArgs {
        separator,
        number,
        use_regex,
    })
}

fn eval_supported_constant_split_row_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantSplitRowArgs, LabeledError> {
    let mut separator = None;
    let mut number = None;
    let mut use_regex = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`split row` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag_or_separator = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split row` separator and flags must be compile-time strings in global initializers",
                        expr.span,
                    ));
            }
        };
        let Some(flag) = flag_or_separator.strip_prefix("--") else {
            if separator.replace(flag_or_separator).is_some() {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split row` accepts exactly one separator argument in compile-time global initializers",
                        expr.span,
                    ));
            }
            continue;
        };
        match flag {
            "regex" => use_regex = true,
            "number" => {
                let Some(next_arg) = iter.next() else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split row --number` requires a value in compile-time global initializers",
                        expr.span,
                    ));
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split row --number` value cannot use spread syntax in compile-time global initializers",
                        next_arg.expr().span,
                    ));
                };
                if number
                    .replace(eval_supported_constant_non_negative_usize_argument(
                        working_set,
                        next_expr,
                        env,
                        "split row --number",
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split row` accepts only one --number value in compile-time global initializers",
                        next_expr.span,
                    ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split row` supports only --number and --regex in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    let Some(separator) = separator else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split row` requires exactly one separator argument in compile-time global initializers",
                span,
            ),
        );
    };
    Ok(ConstantSplitRowArgs {
        separator,
        number,
        use_regex,
    })
}

fn eval_supported_constant_split_row(
    input: Option<Value>,
    args: ConstantSplitRowArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("split row", input, span)?;
    let value_span = value.span();
    let output = match value {
        Value::List { vals, .. } => vals
            .into_iter()
            .enumerate()
            .try_fold(Vec::new(), |mut output, (index, value)| {
                let input = match value {
                    Value::String { val, .. } | Value::Glob { val, .. } => val,
                    other => {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            format!(
                                "`split row` requires string list items in compile-time global initializers; item {index} has type {}",
                                other.get_type()
                            ),
                            span,
                        ));
                    }
                };
                output.extend(eval_supported_constant_split_row_known_string(
                    &input,
                    &args.separator,
                    args.number,
                    args.use_regex,
                    value_span,
                    span,
                )?);
                Ok(output)
            })?,
        value => {
            let input = eval_supported_constant_exact_string_value(value, "split row", span)?;
            eval_supported_constant_split_row_known_string(
                &input,
                &args.separator,
                args.number,
                args.use_regex,
                value_span,
                span,
            )?
        }
    };
    Ok(Value::list(output, value_span))
}

fn eval_supported_constant_split_row_known_string(
    input: &str,
    separator: &str,
    number: Option<usize>,
    use_regex: bool,
    value_span: Span,
    error_span: Span,
) -> Result<Vec<Value>, LabeledError> {
    let parts = if use_regex {
        let regex = FancyRegex::new(separator).map_err(|err| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`split row --regex` pattern is invalid in compile-time global initializers: {err}"),
                error_span,
            )
        })?;
        if let Some(number) = number {
            regex
                .splitn(input, number)
                .map(|part| {
                    part.map(str::to_string).map_err(|err| {
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`split row --regex` failed at compile time in global initializers: {err}"
                                ),
                                error_span,
                            )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            regex
                .split(input)
                .map(|part| {
                    part.map(str::to_string).map_err(|err| {
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`split row --regex` failed at compile time in global initializers: {err}"
                                ),
                                error_span,
                            )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    } else if let Some(number) = number {
        input
            .splitn(number, separator)
            .map(str::to_string)
            .collect()
    } else {
        input.split(separator).map(str::to_string).collect()
    };
    Ok(parts
        .into_iter()
        .map(|part| Value::string(part, value_span))
        .collect())
}

struct ConstantSplitWordsArgs {
    min_word_len: Option<usize>,
    use_grapheme_clusters: bool,
}

fn eval_supported_constant_split_words_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<ConstantSplitWordsArgs, LabeledError> {
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    let mut min_word_len = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => match named.0.item.as_str() {
                "utf-8-bytes" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split words --utf-8-bytes` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    use_utf8_bytes = true;
                }
                "grapheme-clusters" => {
                    if named.2.is_some() {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split words --grapheme-clusters` cannot receive a value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                    use_grapheme_clusters = true;
                }
                "min-word-length" => {
                    let Some(expr) = named.2.as_ref() else {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split words --min-word-length` requires a value in compile-time global initializers",
                            arg.span(),
                        ));
                    };
                    if min_word_len
                        .replace(eval_supported_constant_non_negative_usize_argument(
                            working_set,
                            expr,
                            env,
                            "split words --min-word-length",
                        )?)
                        .is_some()
                    {
                        return Err(LabeledError::new(
                            "Unsupported annotated mutable global initializer",
                        )
                        .with_label(
                            "`split words` accepts only one --min-word-length value in compile-time global initializers",
                            arg.span(),
                        ));
                    }
                }
                _ => {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            format!(
                                "`split words` does not support named argument --{} in compile-time global initializers",
                                named.0.item
                            ),
                            arg.span(),
                        ));
                }
            },
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split words` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`split words` does not accept positional arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
        }
    }

    eval_supported_constant_split_words_validate_args(
        min_word_len,
        use_utf8_bytes,
        use_grapheme_clusters,
        Span::unknown(),
    )
}

fn eval_supported_constant_split_words_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantSplitWordsArgs, LabeledError> {
    let mut use_utf8_bytes = false;
    let mut use_grapheme_clusters = false;
    let mut min_word_len = None;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`split words` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
        let flag = match value {
            Value::String { val, .. } | Value::Glob { val, .. } => val,
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split words` accepts only string flags in compile-time global initializers",
                        expr.span,
                    ));
            }
        };
        let Some(flag) = flag.strip_prefix("--") else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`split words` does not accept positional arguments in compile-time global initializers",
                    span,
                ),
            );
        };
        match flag {
            "utf-8-bytes" => use_utf8_bytes = true,
            "grapheme-clusters" => use_grapheme_clusters = true,
            "min-word-length" => {
                let Some(next_arg) = iter.next() else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split words --min-word-length` requires a value in compile-time global initializers",
                        expr.span,
                    ));
                };
                let ExternalArgument::Regular(next_expr) = next_arg else {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split words --min-word-length` value cannot use spread syntax in compile-time global initializers",
                        next_arg.expr().span,
                    ));
                };
                if min_word_len
                    .replace(eval_supported_constant_non_negative_usize_argument(
                        working_set,
                        next_expr,
                        env,
                        "split words --min-word-length",
                    )?)
                    .is_some()
                {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`split words` accepts only one --min-word-length value in compile-time global initializers",
                        next_expr.span,
                    ));
                }
            }
            _ => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`split words` supports only --min-word-length, --utf-8-bytes, and --grapheme-clusters in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_split_words_validate_args(
        min_word_len,
        use_utf8_bytes,
        use_grapheme_clusters,
        span,
    )
}

fn eval_supported_constant_non_negative_usize_argument(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    context: &str,
) -> Result<usize, LabeledError> {
    let raw = eval_supported_constant_value_with_env(working_set, expr, env)?
        .as_int()
        .map_err(|_| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{context}` requires a compile-time integer in global initializers"),
                expr.span,
            )
        })?;
    if raw < 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{context}` requires a non-negative integer in global initializers"),
                expr.span,
            ),
        );
    }
    usize::try_from(raw).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{context}` is too large for compile-time global initializers"),
            expr.span,
        )
    })
}

fn eval_supported_constant_split_words_validate_args(
    min_word_len: Option<usize>,
    use_utf8_bytes: bool,
    use_grapheme_clusters: bool,
    span: Span,
) -> Result<ConstantSplitWordsArgs, LabeledError> {
    if use_utf8_bytes && use_grapheme_clusters {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split words` accepts either --utf-8-bytes or --grapheme-clusters, not both, in compile-time global initializers",
                span,
            ),
        );
    }
    if min_word_len.is_none() && (use_utf8_bytes || use_grapheme_clusters) {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split words --utf-8-bytes` and `--grapheme-clusters` require `--min-word-length` in compile-time global initializers",
                span,
            ),
        );
    }

    Ok(ConstantSplitWordsArgs {
        min_word_len,
        use_grapheme_clusters,
    })
}

fn eval_supported_constant_split_words(
    input: Option<Value>,
    args: ConstantSplitWordsArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("split words", input, span)?;
    let value_span = value.span();
    match value {
        Value::List { vals, .. } => {
            let items = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let input = match value {
                        Value::String { val, .. } | Value::Glob { val, .. } => val,
                        other => {
                            return Err(LabeledError::new(
                                "Unsupported annotated mutable global initializer",
                            )
                            .with_label(
                                format!(
                                    "`split words` requires string list items in compile-time global initializers; item {index} has type {}",
                                    other.get_type()
                                ),
                                span,
                            ));
                        }
                    };
                    Ok(Value::list(
                        eval_supported_constant_split_words_known_string(
                            &input,
                            args.min_word_len,
                            args.use_grapheme_clusters,
                            value_span,
                        ),
                        value_span,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::list(items, value_span))
        }
        value => {
            let input = eval_supported_constant_exact_string_value(value, "split words", span)?;
            Ok(Value::list(
                eval_supported_constant_split_words_known_string(
                    &input,
                    args.min_word_len,
                    args.use_grapheme_clusters,
                    value_span,
                ),
                value_span,
            ))
        }
    }
}

fn eval_supported_constant_split_words_known_string(
    input: &str,
    min_word_len: Option<usize>,
    use_grapheme_clusters: bool,
    span: Span,
) -> Vec<Value> {
    input
        .unicode_words()
        .filter(|word| {
            min_word_len.is_none_or(|min_word_len| {
                let len = if use_grapheme_clusters {
                    UnicodeSegmentation::graphemes(*word, true).count()
                } else {
                    word.len()
                };
                len >= min_word_len
            })
        })
        .map(|word| Value::string(word.to_string(), span))
        .collect()
}

fn eval_supported_constant_split_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let [subcommand_arg, remaining_args @ ..] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split` requires a supported subcommand in compile-time global initializers",
                span,
            ),
        );
    };

    let ExternalArgument::Regular(subcommand_expr) = subcommand_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`split` subcommand cannot use spread syntax in compile-time global initializers",
                subcommand_arg.expr().span,
            ),
        );
    };
    let subcommand = eval_supported_constant_record_field_name(working_set, subcommand_expr, env)?;

    match subcommand.as_str() {
        "chars" => {
            let use_grapheme_clusters = eval_supported_constant_split_chars_mode_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_split_chars(input, use_grapheme_clusters, span)
        }
        "list" => {
            let args = eval_supported_constant_split_list_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_split_list(input, args, span)
        }
        "row" => {
            let args = eval_supported_constant_split_row_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_split_row(input, args, span)
        }
        "words" => {
            let args = eval_supported_constant_split_words_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_split_words(input, args, span)
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`split {subcommand}` is not supported in compile-time global initializers"
                ),
                subcommand_expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_str_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let [subcommand_arg, remaining_args @ ..] = args else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str` requires a supported subcommand in compile-time global initializers",
                span,
            ),
        );
    };

    let ExternalArgument::Regular(subcommand_expr) = subcommand_arg else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`str` subcommand cannot use spread syntax in compile-time global initializers",
                subcommand_arg.expr().span,
            ),
        );
    };
    let subcommand = eval_supported_constant_record_field_name(working_set, subcommand_expr, env)?;

    match subcommand.as_str() {
        "length" => {
            let mode = eval_supported_constant_str_length_mode_external_args(
                working_set,
                "str length",
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_length(input, mode, span)
        }
        "starts-with" | "ends-with" | "contains" => {
            let cmd_name = format!("str {subcommand}");
            let args = eval_supported_constant_str_predicate_external_args(
                working_set,
                &cmd_name,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_predicate(&cmd_name, input, args, span)
        }
        "index-of" => {
            let args = eval_supported_constant_str_index_of_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_index_of(input, args, span)
        }
        "distance" => {
            let compare = eval_supported_constant_str_distance_external_arg(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_distance(input, compare, span)
        }
        "join" => {
            let separator = eval_supported_constant_str_join_external_separator(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_join(input, separator, span)
        }
        "stats" => {
            eval_supported_constant_no_external_args("str stats", remaining_args, span)?;
            eval_supported_constant_str_stats(input, span)
        }
        "expand" => {
            let use_path = eval_supported_constant_str_expand_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_expand(input, use_path, span)
        }
        "trim" => {
            let args = eval_supported_constant_str_trim_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_trim(input, args, span)
        }
        "substring" => {
            let args = eval_supported_constant_str_substring_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_substring(input, args, span)
        }
        "replace" => {
            let args = eval_supported_constant_str_replace_external_args(
                working_set,
                remaining_args,
                env,
                span,
            )?;
            eval_supported_constant_str_replace(input, args, span)
        }
        "downcase"
        | "upcase"
        | "reverse"
        | "capitalize"
        | "camel-case"
        | "kebab-case"
        | "pascal-case"
        | "screaming-snake-case"
        | "snake-case"
        | "title-case" => {
            let cmd_name = format!("str {subcommand}");
            eval_supported_constant_no_external_args(&cmd_name, remaining_args, span)?;
            eval_supported_constant_str_transform(&cmd_name, input, span)
        }
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`str {subcommand}` is not supported in compile-time global initializers"),
                subcommand_expr.span,
            ),
        ),
    }
}

#[derive(Debug, Clone, Copy)]
struct ConstantFloatSortKey(f64);

impl PartialEq for ConstantFloatSortKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for ConstantFloatSortKey {}

impl PartialOrd for ConstantFloatSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConstantFloatSortKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("constant sort rejects non-finite float keys")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ConstantSortKey {
    Bool(bool),
    Int(i64),
    Float(ConstantFloatSortKey),
    Binary(Vec<u8>),
    String(String),
}

fn eval_supported_constant_list_sort_call(
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    span: Span,
) -> Result<Value, LabeledError> {
    let mut reverse = false;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                if named.0.item != "reverse" || named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`sort` accepts only the --reverse flag in compile-time global initializers",
                            arg.span(),
                        ));
                }
                reverse = true;
            }
            nu_protocol::ast::Argument::Positional(_) | nu_protocol::ast::Argument::Unknown(_) => {
                return Err(
                    LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`sort` does not accept arguments in compile-time global initializers",
                            arg.span(),
                        ),
                );
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`sort` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_list_sort(input, reverse, span)
}

fn eval_supported_constant_list_sort(
    input: Option<Value>,
    reverse: bool,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`sort` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`sort` in a compile-time global initializer requires list input",
                span,
            ),
        );
    };

    let keys = vals
        .iter()
        .map(eval_supported_constant_sort_key)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`sort` supports compile-time lists with boolean, integer, finite float, binary, or string elements",
                span,
            )
        })?;
    if let Some((first, rest)) = keys.split_first()
        && rest
            .iter()
            .any(|key| std::mem::discriminant(key) != std::mem::discriminant(first))
    {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`sort` requires compile-time list elements with one comparable type",
                span,
            ),
        );
    }

    let mut indexed = keys.into_iter().zip(vals).collect::<Vec<_>>();
    indexed.sort_by(|(left_key, _), (right_key, _)| {
        let ord = left_key.cmp(right_key);
        if reverse { ord.reverse() } else { ord }
    });
    let vals = indexed
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    Ok(Value::list(vals, value_span))
}

fn eval_supported_constant_sort_key(value: &Value) -> Option<ConstantSortKey> {
    match value {
        Value::Bool { val, .. } => Some(ConstantSortKey::Bool(*val)),
        Value::Int { val, .. } => Some(ConstantSortKey::Int(*val)),
        Value::Float { val, .. } if val.is_finite() => {
            Some(ConstantSortKey::Float(ConstantFloatSortKey(*val)))
        }
        Value::Binary { val, .. } => Some(ConstantSortKey::Binary(val.clone())),
        Value::String { val, .. } | Value::Glob { val, .. } => {
            Some(ConstantSortKey::String(val.clone()))
        }
        _ => None,
    }
}

fn eval_supported_constant_list_find_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut needle_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if needle_expr.replace(expr).is_some() {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                "`find` requires exactly one search argument in compile-time global initializers",
                                arg.span(),
                            ),
                    );
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`find` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`find` search argument cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }
    let Some(needle_expr) = needle_expr else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`find` requires exactly one search argument in compile-time global initializers",
                span,
            ),
        );
    };

    eval_supported_constant_list_find(working_set, input, needle_expr, env, span)
}

fn eval_supported_constant_list_find(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    needle_expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`find` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`find` in a compile-time global initializer requires list input",
                span,
            ),
        );
    };
    let needle = eval_supported_constant_value_with_env(working_set, needle_expr, env)?;
    let vals = vals
        .into_iter()
        .filter(|value| value == &needle)
        .collect::<Vec<_>>();
    Ok(Value::list(vals, value_span))
}

fn eval_supported_constant_list_take_skip_or_drop_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut count_expr = None;
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if count_expr.replace(expr).is_some() {
                    return Err(
                        LabeledError::new("Unsupported annotated mutable global initializer")
                            .with_label(
                                format!(
                                    "`{cmd_name}` accepts at most one count argument in compile-time global initializers"
                                ),
                                arg.span(),
                            ),
                    );
                }
            }
            nu_protocol::ast::Argument::Named(named) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` does not accept named argument --{} in compile-time global initializers",
                            named.0.item
                        ),
                        arg.span(),
                    ));
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        format!(
                            "`{cmd_name}` count argument cannot use spread syntax in compile-time global initializers"
                        ),
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_list_take_skip_or_drop(
        working_set,
        cmd_name,
        input,
        count_expr,
        env,
        span,
    )
}

fn eval_supported_constant_list_take_skip_or_drop(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    count_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires list input"),
                span,
            ),
        );
    };

    let raw_count = if let Some(count_expr) = count_expr {
        let count_value = eval_supported_constant_value_with_env(working_set, count_expr, env)?;
        let Value::Int { val, .. } = count_value else {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!(
                        "`{cmd_name}` count must be a compile-time integer in global initializers"
                    ),
                    count_expr.span,
                ),
            );
        };
        val
    } else if cmd_name == "take" {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`take` requires exactly one count argument in compile-time global initializers",
                span,
            ),
        );
    } else {
        1
    };
    if raw_count < 0 {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` count must be non-negative in global initializers"),
                count_expr.map(|expr| expr.span).unwrap_or(span),
            ),
        );
    }
    let count = usize::try_from(raw_count).map_err(|_| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!("`{cmd_name}` count is too large for compile-time global initializers"),
            count_expr.map(|expr| expr.span).unwrap_or(span),
        )
    })?;

    let selected = match cmd_name {
        "take" => vals.into_iter().take(count).collect(),
        "skip" => vals.into_iter().skip(count).collect(),
        "drop" => {
            let keep_len = vals.len().saturating_sub(count);
            vals.into_iter().take(keep_len).collect()
        }
        _ => unreachable!("validated list slice command"),
    };

    Ok(Value::list(selected, value_span))
}

fn eval_supported_constant_list_mutation_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    item_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let item_expr = item_expr.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(format!("`{cmd_name}` requires an item argument"), span)
    })?;
    let item = eval_supported_constant_value_with_env(working_set, item_expr, env)?;

    let value_span = value.span();
    let Value::List { vals, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires list input"),
                span,
            ),
        );
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

fn eval_supported_constant_record_merge_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    merge_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let merge_expr = merge_expr.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(format!("`{cmd_name}` requires a record argument"), span)
    })?;
    let merge_value = eval_supported_constant_value_with_env(working_set, merge_expr, env)?;

    let value_span = value.span();
    let Value::Record { val: input, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires record input"),
                span,
            ),
        );
    };
    let Value::Record { val: merge, .. } = merge_value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` in a compile-time global initializer requires a record argument"
                ),
                span,
            ),
        );
    };

    let mut record = input.into_owned();
    for (key, value) in merge.iter() {
        record.insert(key.clone(), value.clone());
    }

    Ok(Value::record(record, value_span))
}

fn eval_supported_constant_record_select_or_reject_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let fields = args
        .iter()
        .map(|arg| match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                eval_supported_constant_record_field_name(working_set, expr, env)
            }
            nu_protocol::ast::Argument::Named(named) => Err(LabeledError::new(
                "Unsupported annotated mutable global initializer",
            )
            .with_label(
                format!(
                    "`{cmd_name}` does not accept named argument --{} in compile-time global initializers",
                    named.0.item
                ),
                arg.span(),
            )),
            nu_protocol::ast::Argument::Spread(expr) => Err(LabeledError::new(
                "Unsupported annotated mutable global initializer",
            )
            .with_label(
                format!(
                    "`{cmd_name}` field arguments cannot use spread syntax in compile-time global initializers"
                ),
                expr.span,
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    eval_supported_constant_record_select_or_reject(cmd_name, input, fields, span)
}

fn eval_supported_constant_record_select_or_reject(
    cmd_name: &str,
    input: Option<Value>,
    fields: Vec<String>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    if fields.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!(
                    "`{cmd_name}` requires at least one record field name in compile-time global initializers"
                ),
                span,
            ),
        );
    }

    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires record input"),
                span,
            ),
        );
    };
    let input = val.into_owned();

    let mut names = Vec::new();
    for field in fields {
        if !names.contains(&field) {
            names.push(field);
        }
    }
    for field in &names {
        if input.get(field).is_none() {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`{cmd_name}` cannot find record field '{field}'"),
                    span,
                ),
            );
        }
    }

    let mut out = Record::new();
    if cmd_name == "select" {
        for field in names {
            let value = input.get(&field).expect("field existence checked");
            out.push(field, value.clone());
        }
    } else {
        for (field, value) in input.iter() {
            if !names.iter().any(|name| name == field) {
                out.push(field, value.clone());
            }
        }
    }

    Ok(Value::record(out, value_span))
}

fn eval_supported_constant_record_field_name(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<String, LabeledError> {
    let value = match &expr.expr {
        Expr::Var(var_id) if env.contains_key(var_id) => {
            env.get(var_id).expect("env key checked").clone()
        }
        _ => eval_supported_constant_value_with_env(working_set, expr, env)?,
    };

    match value {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val),
        Value::CellPath { val, .. } => match val.members.as_slice() {
            [nu_protocol::ast::PathMember::String { val, .. }] => Ok(val.clone()),
            _ => Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "record field arguments must be top-level field names",
                    expr.span,
                ),
            ),
        },
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "record field arguments must be compile-time string or cell-path field names",
                expr.span,
            ),
        ),
    }
}

fn eval_supported_constant_record_rename_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    call: &nu_protocol::ast::Call,
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    for (name, _, _) in call.named_iter() {
        if !matches!(name.item.as_str(), "column" | "c" | "block" | "b") {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    format!(
                        "`rename` does not accept named argument --{} in compile-time global initializers",
                        name.item
                    ),
                    name.span,
                ));
        }
    }

    if call.get_named_arg("block").is_some() || call.get_named_arg("b").is_some() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --block` is not supported in compile-time global initializers",
                span,
            ),
        );
    }

    let column_arg = call
        .get_flag_expr("column")
        .or_else(|| call.get_flag_expr("c"));
    let has_column = call.get_named_arg("column").is_some() || call.get_named_arg("c").is_some();
    if has_column {
        let column_expr = column_arg.ok_or_else(|| {
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --column` requires a record mapping in compile-time global initializers",
                span,
            )
        })?;
        if call.positional_len() != 0 {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`rename --column` cannot be combined with positional field names in compile-time global initializers",
                    span,
                ));
        }
        let pairs =
            eval_supported_constant_record_rename_column_pairs(working_set, column_expr, env)?;
        return eval_supported_constant_record_rename_column(input, pairs, span);
    }

    let positional = call.positional_iter().collect::<Vec<_>>();
    if let Some(first) = positional.first() {
        let first_value = eval_supported_constant_value_with_env(working_set, first, env)?;
        if matches!(
            first_value,
            Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--column" || val == "-c"
        ) {
            let [_, column_expr] = positional.as_slice() else {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`rename --column` requires exactly one record mapping in compile-time global initializers",
                        span,
                    ));
            };
            let pairs =
                eval_supported_constant_record_rename_column_pairs(working_set, column_expr, env)?;
            return eval_supported_constant_record_rename_column(input, pairs, span);
        }
    }
    if positional.len() == 1 {
        let value = eval_supported_constant_value_with_env(working_set, positional[0], env)?;
        if matches!(value, Value::Record { .. }) {
            let pairs = eval_supported_constant_record_rename_column_pairs_from_value(
                value,
                positional[0].span,
            )?;
            return eval_supported_constant_record_rename_column(input, pairs, span);
        }
    }

    let fields = call
        .positional_iter()
        .map(|expr| eval_supported_constant_record_field_name(working_set, expr, env))
        .collect::<Result<Vec<_>, _>>()?;
    eval_supported_constant_record_rename_positional(input, fields, span)
}

fn eval_supported_constant_record_rename_column_pairs(
    working_set: &StateWorkingSet,
    expr: &nu_protocol::ast::Expression,
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<Vec<(String, String)>, LabeledError> {
    let value = eval_supported_constant_value_with_env(working_set, expr, env)?;
    eval_supported_constant_record_rename_column_pairs_from_value(value, expr.span)
}

fn eval_supported_constant_record_rename_column_pairs_from_value(
    value: Value,
    span: Span,
) -> Result<Vec<(String, String)>, LabeledError> {
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --column` requires a compile-time record mapping",
                span,
            ),
        );
    };
    if val.is_empty() {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --column` requires a non-empty record mapping",
                span,
            ),
        );
    }

    val.iter()
        .map(|(source, target)| {
            eval_supported_constant_record_rename_column_target(target)
                .map(|target| (source.to_string(), target))
        })
        .collect()
}

fn eval_supported_constant_record_rename_column_target(
    value: &Value,
) -> Result<String, LabeledError> {
    match value {
        Value::String { val, .. } => Ok(val.clone()),
        Value::CellPath { val, .. } => match val.members.as_slice() {
            [nu_protocol::ast::PathMember::String { val, .. }] => Ok(val.clone()),
            _ => Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    "`rename --column` supports only top-level replacement field names",
                    value.span(),
                ),
            ),
        },
        _ => Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --column` requires compile-time string replacement field names",
                value.span(),
            ),
        ),
    }
}

fn eval_supported_constant_record_rename_positional(
    input: Option<Value>,
    fields: Vec<String>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`rename` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename` in a compile-time global initializer requires record input",
                span,
            ),
        );
    };

    let mut out = Record::new();
    for (idx, (source, value)) in val.iter().enumerate() {
        let target = fields.get(idx).unwrap_or(source).clone();
        out.push(target, value.clone());
    }
    Ok(Value::record(out, value_span))
}

fn eval_supported_constant_record_rename_column(
    input: Option<Value>,
    pairs: Vec<(String, String)>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`rename --column` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`rename --column` in a compile-time global initializer requires record input",
                span,
            ),
        );
    };

    for (source, _) in &pairs {
        if val.get(source).is_none() {
            return Err(
                LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                    format!("`rename --column` cannot find record field '{source}'"),
                    span,
                ),
            );
        }
    }

    let mut out = Record::new();
    for (source, value) in val.iter() {
        let target = pairs
            .iter()
            .find_map(|(from, to)| (from == source).then_some(to.clone()))
            .unwrap_or_else(|| source.to_string());
        out.push(target, value.clone());
    }
    Ok(Value::record(out, value_span))
}

fn eval_supported_constant_record_columns_or_values(
    cmd_name: &str,
    input: Option<Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            format!(
                "`{cmd_name}` in a compile-time global initializer must receive pipeline input"
            ),
            span,
        )
    })?;
    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                format!("`{cmd_name}` in a compile-time global initializer requires record input"),
                span,
            ),
        );
    };

    let vals = if cmd_name == "columns" {
        val.iter()
            .map(|(key, _)| Value::string(key, value_span))
            .collect::<Vec<_>>()
    } else {
        val.iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>()
    };

    Ok(Value::list(vals, value_span))
}

#[derive(Debug, Clone)]
struct ConstantRecordTransposeArgs {
    output_names: [String; 2],
    ignore_titles: bool,
}

fn eval_supported_constant_record_transpose_call_args(
    working_set: &StateWorkingSet,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantRecordTransposeArgs, LabeledError> {
    let mut output_names = ["column0".to_string(), "column1".to_string()];
    let mut output_name_count = 0usize;
    let mut ignore_titles = false;

    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Named(named) => {
                let is_ignore_titles = named.0.item.as_str() == "ignore-titles"
                    || named.0.item.as_str() == "i"
                    || named
                        .1
                        .as_ref()
                        .is_some_and(|short| short.item.as_str() == "i");
                if !is_ignore_titles || named.2.is_some() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`transpose` supports only the --ignore-titles flag in compile-time global initializers",
                        arg.span(),
                    ));
                }
                if ignore_titles {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`transpose` accepts --ignore-titles at most once in compile-time global initializers",
                        arg.span(),
                    ));
                }
                ignore_titles = true;
            }
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => {
                if output_name_count >= output_names.len() {
                    return Err(LabeledError::new(
                        "Unsupported annotated mutable global initializer",
                    )
                    .with_label(
                        "`transpose` accepts at most two output column names in compile-time global initializers",
                        span,
                    ));
                }
                output_names[output_name_count] =
                    eval_supported_constant_string_argument(working_set, expr, env, "transpose")?;
                output_name_count += 1;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`transpose` output column names cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    Ok(ConstantRecordTransposeArgs {
        output_names,
        ignore_titles,
    })
}

fn eval_supported_constant_record_transpose_external_args(
    working_set: &StateWorkingSet,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<ConstantRecordTransposeArgs, LabeledError> {
    let mut output_names = ["column0".to_string(), "column1".to_string()];
    let mut output_name_count = 0usize;
    let mut ignore_titles = false;

    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`transpose` output column names cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };

        let value = eval_supported_constant_string_argument(working_set, expr, env, "transpose")?;
        if value == "--ignore-titles" || value == "-i" {
            if ignore_titles {
                return Err(LabeledError::new(
                    "Unsupported annotated mutable global initializer",
                )
                .with_label(
                    "`transpose` accepts --ignore-titles at most once in compile-time global initializers",
                    expr.span,
                ));
            }
            ignore_titles = true;
            continue;
        }
        if value.starts_with('-') {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`transpose` supports only the --ignore-titles flag in compile-time global initializers",
                    expr.span,
                ));
        }

        if output_name_count >= output_names.len() {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`transpose` accepts at most two output column names in compile-time global initializers",
                    span,
                ));
        }
        output_names[output_name_count] = value;
        output_name_count += 1;
    }

    Ok(ConstantRecordTransposeArgs {
        output_names,
        ignore_titles,
    })
}

fn eval_supported_constant_record_transpose(
    input: Option<Value>,
    args: ConstantRecordTransposeArgs,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = eval_supported_constant_required_pipeline_input("transpose", input, span)?;
    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`transpose` in a compile-time global initializer requires record input",
                span,
            ),
        );
    };

    let mut rows = Vec::with_capacity(val.len());
    for (key, value) in val.iter() {
        let mut row = Record::new();
        if args.ignore_titles {
            row.push(args.output_names[0].clone(), value.clone());
        } else {
            row.push(args.output_names[0].clone(), Value::string(key, value_span));
            row.push(args.output_names[1].clone(), value.clone());
        }
        rows.push(Value::record(row, value_span));
    }

    Ok(Value::list(rows, value_span))
}

fn eval_supported_constant_default_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[nu_protocol::ast::Argument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut replace_empty = false;
    let mut positional = Vec::new();
    for arg in args {
        match arg {
            nu_protocol::ast::Argument::Positional(expr)
            | nu_protocol::ast::Argument::Unknown(expr) => positional.push(expr),
            nu_protocol::ast::Argument::Named(named) => {
                if named.0.item != "empty" || named.2.is_some() {
                    return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                        .with_label(
                            "`default` accepts only the --empty flag in compile-time global initializers",
                            arg.span(),
                        ));
                }
                replace_empty = true;
            }
            nu_protocol::ast::Argument::Spread(expr) => {
                return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                    .with_label(
                        "`default` arguments cannot use spread syntax in compile-time global initializers",
                        expr.span,
                    ));
            }
        }
    }

    eval_supported_constant_default(
        working_set,
        input,
        replace_empty,
        positional.as_slice(),
        env,
        span,
    )
}

fn eval_supported_constant_default_external_call(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    args: &[ExternalArgument],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let mut positional = Vec::new();
    for arg in args {
        let ExternalArgument::Regular(expr) = arg else {
            return Err(LabeledError::new("Unsupported annotated mutable global initializer")
                .with_label(
                    "`default` arguments cannot use spread syntax in compile-time global initializers",
                    arg.expr().span,
                ));
        };
        positional.push(expr);
    }

    let mut replace_empty = false;
    if let Some(first) = positional.first() {
        let first_value = eval_supported_constant_value_with_env(working_set, first, env)?;
        if matches!(
            first_value,
            Value::String { ref val, .. } | Value::Glob { ref val, .. } if val == "--empty"
        ) {
            replace_empty = true;
            positional.remove(0);
        }
    }

    eval_supported_constant_default(
        working_set,
        input,
        replace_empty,
        positional.as_slice(),
        env,
        span,
    )
}

fn eval_supported_constant_default(
    working_set: &StateWorkingSet,
    input: Option<Value>,
    replace_empty: bool,
    positional: &[&nu_protocol::ast::Expression],
    env: &HashMap<nu_protocol::VarId, Value>,
    span: Span,
) -> Result<Value, LabeledError> {
    let value = input.ok_or_else(|| {
        LabeledError::new("Unsupported annotated mutable global initializer").with_label(
            "`default` in a compile-time global initializer must receive pipeline input",
            span,
        )
    })?;
    let Some((default_expr, column_exprs)) = positional.split_first() else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`default` requires a default value in compile-time global initializers",
                span,
            ),
        );
    };

    let default_value = eval_supported_constant_value_with_env(working_set, default_expr, env)?;
    if column_exprs.is_empty() {
        return if eval_supported_constant_default_should_replace_value(&value, replace_empty) {
            Ok(default_value)
        } else {
            Ok(value)
        };
    }

    let value_span = value.span();
    let Value::Record { val, .. } = value else {
        return Err(
            LabeledError::new("Unsupported annotated mutable global initializer").with_label(
                "`default` column fill in a compile-time global initializer requires record input",
                span,
            ),
        );
    };
    let mut record = val.into_owned();
    let mut column_names = Vec::new();
    for expr in column_exprs {
        let name = eval_supported_constant_record_field_name(working_set, expr, env)?;
        if !column_names.contains(&name) {
            column_names.push(name);
        }
    }
    for name in column_names {
        let should_replace = record
            .get(&name)
            .map(|value| eval_supported_constant_default_should_replace_value(value, replace_empty))
            .unwrap_or(true);
        if should_replace {
            record.insert(name, default_value.clone());
        }
    }

    Ok(Value::record(record, value_span))
}

fn eval_supported_constant_default_should_replace_value(
    value: &Value,
    replace_empty: bool,
) -> bool {
    match value {
        Value::Nothing { .. } => true,
        Value::String { val, .. } => replace_empty && val.is_empty(),
        Value::Binary { val, .. } => replace_empty && val.is_empty(),
        Value::List { vals, .. } => replace_empty && vals.is_empty(),
        Value::Record { val, .. } => replace_empty && val.is_empty(),
        _ => false,
    }
}

fn eval_supported_constant_path_mutation_call(
    working_set: &StateWorkingSet,
    cmd_name: &str,
    input: Option<Value>,
    path_expr: Option<&nu_protocol::ast::Expression>,
    new_value_expr: Option<&nu_protocol::ast::Expression>,
    env: &HashMap<nu_protocol::VarId, Value>,
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
    let path = eval_supported_constant_cell_path(working_set, path_expr, env)?;
    let new_value = eval_supported_constant_value_with_env(working_set, new_value_expr, env)?;

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
    env: &HashMap<nu_protocol::VarId, Value>,
) -> Result<String, LabeledError> {
    if let Expr::Var(var_id) = &expr.expr
        && let Some(value) = env.get(var_id)
    {
        return constant_record_key_from_value(value.clone(), expr.span);
    }

    if let Ok(value) = eval_constant(working_set, expr) {
        return constant_record_key_from_value(value, expr.span);
    }

    if let Some(string) = expr.as_string() {
        return Ok(string);
    }
    if let Some((path, _quoted)) = expr.as_filepath() {
        return Ok(path);
    }

    if let Ok(value) = eval_supported_constant_value_with_env(working_set, expr, env) {
        return constant_record_key_from_value(value, expr.span);
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

fn constant_record_key_from_value(value: Value, span: Span) -> Result<String, LabeledError> {
    value.coerce_into_string().map_err(|e| {
        LabeledError::new("Unsupported annotated mutable global initializer")
            .with_label(e.to_string(), span)
    })
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
    let mut constant_env: HashMap<nu_protocol::VarId, Value> = HashMap::new();
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
        let declared_var_id = match &var_expr.expr {
            Expr::VarDecl(var_id) | Expr::Var(var_id) => Some(*var_id),
            _ => None,
        };
        let init_expr = call
            .positional_nth(1)
            .map(|expr| expr.as_keyword().unwrap_or(expr));

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
            if let Some(parse_error) =
                parse_error_in_span(&working_set.parse_errors, first.expr.span)
            {
                return Err(annotated_mut_parse_error(parse_error));
            }
            let init_expr = init_expr.ok_or_else(|| {
                LabeledError::new("Failed to parse annotated mutable declaration")
                    .with_label("Missing initializer", first.expr.span)
            })?;
            Some(eval_supported_constant_value_with_env(
                &working_set,
                init_expr,
                &constant_env,
            )?)
        } else {
            None
        };

        if !mutable
            && let (Some(var_id), Some(init_expr)) = (declared_var_id, init_expr)
            && let Ok(value) =
                eval_supported_constant_value_with_env(&working_set, init_expr, &constant_env)
        {
            constant_env.insert(var_id, value);
        }

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
    if !declarations
        .iter()
        .any(|decl| decl.mutable && decl.declared_type.is_some())
    {
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

struct FetchedIrBlock {
    ir_block: IrBlock,
    decl_names: HashMap<DeclId, String>,
    block_span: Option<Span>,
}

fn parse_view_ir_json(json: &str, span: Span) -> Result<FetchedIrBlock, LabeledError> {
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

    let block_span = value.get("span").and_then(|span_value| {
        serde_json::from_value::<Span>(span_value.clone())
            .ok()
            .filter(|span| span.start <= span.end)
    });

    Ok(FetchedIrBlock {
        ir_block,
        decl_names: extract_decl_names_from_formatted_instructions(&formatted_instructions),
        block_span,
    })
}

fn fetch_view_ir_json(
    engine: &EngineInterface,
    eval: EvaluatedCall,
    span: Span,
) -> Result<FetchedIrBlock, LabeledError> {
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
) -> Result<FetchedIrBlock, LabeledError> {
    let ir_block = engine.get_block_ir(block_id).map_err(|e| {
        LabeledError::new("Failed to fetch compiled IR").with_label(e.to_string(), span)
    })?;

    let mut eval = EvaluatedCall::new(span);
    eval.add_flag("json".into_spanned(span));
    eval.add_positional(Value::int(block_id.get() as i64, span));
    let fetched = fetch_view_ir_json(engine, eval, span).ok();

    Ok(FetchedIrBlock {
        ir_block,
        decl_names: fetched
            .as_ref()
            .map(|fetched| fetched.decl_names.clone())
            .unwrap_or_default(),
        block_span: fetched.and_then(|fetched| fetched.block_span),
    })
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
    let fetched = fetch_view_ir_json(engine, eval, span)?;
    Ok((fetched.ir_block, fetched.decl_names))
}

fn collect_user_function_irs(
    engine: &EngineInterface,
    ir_block: &IrBlock,
    closure_irs: &mut HashMap<BlockId, IrBlock>,
    closure_spans: &mut HashMap<BlockId, Span>,
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

        fetch_closure_irs(engine, &ir, closure_irs, closure_spans, decl_names, span)?;
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

    let FetchedIrBlock {
        ir_block,
        decl_names: mut ir_decl_names,
        ..
    } = fetch_block_ir(engine, closure.item.block_id, closure.span)?;
    let closure_source = fetch_view_source(engine, closure)?;
    let annotated_mut_globals =
        map_leading_annotated_mut_globals(&closure_source, &ir_block, closure.span)?;

    let mut decl_names = build_decl_names(engine)?;
    decl_names.extend(ir_decl_names.drain());

    let mut closure_irs = HashMap::new();
    let mut closure_spans = HashMap::new();
    fetch_closure_irs(
        engine,
        &ir_block,
        &mut closure_irs,
        &mut closure_spans,
        &mut decl_names,
        call_head,
    )?;

    let user_ir_blocks = collect_user_function_irs(
        engine,
        &ir_block,
        &mut closure_irs,
        &mut closure_spans,
        &mut decl_names,
        call_head,
    )?;

    let captures = lower_capture_literals(closure)?;
    let captured_vars: HashSet<_> = captures.iter().map(|(var_id, _)| *var_id).collect();
    let ctx_param = infer_ctx_param_excluding(&ir_block, &captured_vars);
    let closure_param_sources =
        recover_closure_param_sources(&closure_source, closure.span, &closure_spans, &closure_irs);

    let mut hir_program =
        lower_ir_to_hir(ir_block, closure_irs, captures, ctx_param).map_err(|e| {
            LabeledError::new("eBPF compilation failed")
                .with_label(e.to_string(), call_head)
                .with_help("The closure may use unsupported operations")
        })?;
    hir_program.closure_param_sources = closure_param_sources;
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
    let external_map_key_types = pin_group
        .map(|group| {
            state
                .pinned_generic_map_key_types(group)
                .map_err(|e| match e {
                    LoadError::LockPoisoned => LabeledError::new("Failed to attach eBPF probe")
                        .with_label("loader state lock poisoned", call_head),
                    other => LabeledError::new("Failed to attach eBPF probe")
                        .with_label(other.to_string(), call_head),
                })
        })
        .transpose()?;
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
    let external_map_max_entries = pin_group
        .map(|group| {
            state
                .pinned_generic_map_max_entries(group)
                .map_err(|e| match e {
                    LoadError::LockPoisoned => LabeledError::new("Failed to attach eBPF probe")
                        .with_label("loader state lock poisoned", call_head),
                    other => LabeledError::new("Failed to attach eBPF probe")
                        .with_label(other.to_string(), call_head),
                })
        })
        .transpose()?;
    let external_map_inner_templates = pin_group
        .map(|group| {
            state
                .pinned_generic_map_inner_templates(group)
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

    let lower_result = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir_program,
        Some(probe_context),
        &decl_names,
        Some(&hir_types),
        external_map_key_types.as_ref(),
        external_map_max_entries.as_ref(),
        external_map_inner_templates.as_ref(),
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
        generic_map_key_types: _,
        generic_map_value_types,
        generic_map_max_entries: _,
        generic_map_inner_templates: _,
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
                let used_kfuncs = compiled.compile_result.used_kfuncs.clone();
                callback_fields.insert(field_name.to_string());
                callback_kfuncs.insert(field_name.to_string(), used_kfuncs);
                let callback = compiled.compile_result.into_struct_ops_callback(
                    field_name.as_str(),
                    callback_name,
                    compiled.generic_map_value_types,
                    compiled.generic_map_value_semantics,
                );
                callbacks.push(callback);
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
