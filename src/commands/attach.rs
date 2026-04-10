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
    lower_hir_to_mir_with_hints_and_maps, lower_ir_to_hir, passes::optimize_with_ssa_hints,
};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

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

fn struct_ops_value_field_from_value(
    field_name: &str,
    value: &Value,
) -> Result<StructOpsValueField, LabeledError> {
    match value {
        Value::Int { val, .. } => Ok(StructOpsValueField::Int(*val)),
        Value::Bool { val, .. } => Ok(StructOpsValueField::Bool(*val)),
        Value::String { val, .. } => Ok(StructOpsValueField::String(val.clone())),
        Value::Binary { val, .. } => Ok(StructOpsValueField::Bytes(val.clone())),
        Value::List { vals, .. } => {
            let mut items = Vec::with_capacity(vals.len());
            for item in vals {
                match item {
                    Value::Int { val, .. } => items.push(*val),
                    other => {
                        return Err(LabeledError::new("Unsupported struct_ops value field")
                            .with_label(
                                format!(
                                    "Field '{field_name}' uses a list containing unsupported item type {}; only int items are supported in struct_ops constant lists",
                                    other.get_type()
                                ),
                                other.span(),
                            )
                            .with_help(
                                "Use a closure for callback fields, or a constant int/bool/string/binary/int-list value for top-level struct_ops value fields",
                            ));
                    }
                }
            }
            Ok(StructOpsValueField::IntList(items))
        }
        other => Err(LabeledError::new("Unsupported struct_ops value field")
            .with_label(
                format!(
                    "Field '{field_name}' uses unsupported constant type {}; supported top-level struct_ops field values are int, bool, string, binary, and int lists",
                    other.get_type()
                ),
                value.span(),
            )
            .with_help(
                "Use a closure for callback fields, or a constant int/bool/string/binary/int-list value for top-level struct_ops value fields",
            )),
    }
}

fn apply_struct_ops_value_field(
    mut spec: StructOpsObjectSpec,
    field_path: &mut Vec<TrampolineFieldSelector>,
    value: &Value,
) -> Result<StructOpsObjectSpec, LabeledError> {
    let field_path_label = field_path
        .iter()
        .map(|segment| match segment {
            TrampolineFieldSelector::Field(name) => name.clone(),
            TrampolineFieldSelector::Index(index) => index.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".");
    match value {
        Value::Record { val, .. } => {
            for (field_name, nested_value) in val.iter() {
                field_path.push(TrampolineFieldSelector::Field(field_name.to_string()));
                spec = apply_struct_ops_value_field(spec, field_path, nested_value)?;
                field_path.pop();
            }
            Ok(spec)
        }
        Value::List { vals, .. } => {
            for (idx, nested_value) in vals.iter().enumerate() {
                field_path.push(TrampolineFieldSelector::Index(idx));
                spec = apply_struct_ops_value_field(spec, field_path, nested_value)?;
                field_path.pop();
            }
            Ok(spec)
        }
        Value::Closure { .. } => Err(LabeledError::new("Invalid struct_ops object").with_label(
            format!(
                "Nested callback field '{}' is not supported; struct_ops callback closures must be top-level record members",
                field_path_label
            ),
            value.span(),
        )),
        _ => {
            let field_value = struct_ops_value_field_from_value(&field_path_label, value)?;
            spec.with_value_field_path(field_path, field_value)
                .map_err(|e| {
                    LabeledError::new("Failed to initialize struct_ops value field")
                        .with_label(e.to_string(), value.span())
                })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StructOpsTopLevelFieldKind {
    Callback,
    Value,
}

fn struct_ops_live_attach_risk(value_type_name: &str) -> Option<&'static str> {
    match value_type_name {
        "sched_ext_ops" => Some(
            "live sched_ext registration can disrupt host scheduling; prefer --dry-run on the host and use a VM or disposable environment for real loads",
        ),
        _ => None,
    }
}

fn validate_struct_ops_attach_safety(
    value_type_name: &str,
    dry_run: bool,
    allow_unsafe_struct_ops: bool,
    span: Span,
) -> Result<(), LabeledError> {
    if dry_run || allow_unsafe_struct_ops {
        return Ok(());
    }

    let Some(reason) = struct_ops_live_attach_risk(value_type_name) else {
        return Ok(());
    };

    Err(LabeledError::new("Unsafe struct_ops attach requires explicit opt-in")
        .with_label(
            format!(
                "live loading of struct_ops '{}' is disabled by default: {}",
                value_type_name, reason
            ),
            span,
        )
        .with_help(
            "Use --dry-run for host-side validation, or pass --unsafe-struct-ops if you intentionally want a live load",
        ))
}

fn validate_struct_ops_top_level_field_kind(
    value_type_name: &str,
    field_name: &str,
    expected_kind: StructOpsTopLevelFieldKind,
    span: Span,
) -> Result<(), LabeledError> {
    let callback_result =
        KernelBtf::get().struct_ops_callback_ret_type_info(value_type_name, field_name);
    let value_result = KernelBtf::get().kernel_named_type_field_projection(
        value_type_name,
        &[TrampolineFieldSelector::Field(field_name.to_string())],
    );

    match expected_kind {
        StructOpsTopLevelFieldKind::Callback => match callback_result {
            Ok(_) => Ok(()),
            Err(_) if value_result.is_ok() => Err(
                LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        format!(
                            "Field '{}' on struct_ops '{}' is a value member, not a callback slot",
                            field_name, value_type_name
                        ),
                        span,
                    )
                    .with_help(
                        "Use a compile-time constant for value members, and reserve top-level closures for callback slots",
                    ),
            ),
            Err(err) => Err(LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "Field '{}' is not a valid callback member of struct_ops '{}': {}",
                    field_name, value_type_name, err
                ),
                span,
            )),
        },
        StructOpsTopLevelFieldKind::Value => {
            if callback_result.is_ok() {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        format!(
                            "Field '{}' on struct_ops '{}' is a callback slot; provide a closure",
                            field_name, value_type_name
                        ),
                        span,
                    )
                    .with_help(
                        "Use a closure like {|ctx| ... } for callback slots, and constants only for non-callback value members",
                    ));
            }
            value_result.map(|_| ()).map_err(|err| {
                LabeledError::new("Invalid struct_ops object").with_label(
                    format!(
                        "Field '{}' is not a valid value member of struct_ops '{}': {}",
                        field_name, value_type_name, err
                    ),
                    span,
                )
            })
        }
    }
}

fn required_struct_ops_callbacks(value_type_name: &str) -> &'static [&'static str] {
    match value_type_name {
        "tcp_congestion_ops" => &["ssthresh", "cong_avoid", "undo_cwnd"],
        _ => &[],
    }
}

fn validate_required_struct_ops_callbacks(
    value_type_name: &str,
    callback_fields: &HashSet<String>,
    span: Span,
) -> Result<(), LabeledError> {
    let missing: Vec<&'static str> = required_struct_ops_callbacks(value_type_name)
        .iter()
        .copied()
        .filter(|field_name| !callback_fields.contains(*field_name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let help = match value_type_name {
        "tcp_congestion_ops" => {
            "tcp_congestion_ops requires closure members for ssthresh, cong_avoid, and undo_cwnd, for example { ssthresh: {|ctx| 2 }, undo_cwnd: {|ctx| 2 }, cong_avoid: {|ctx| 0 } }"
        }
        _ => "Provide closures for the required struct_ops callback members",
    };
    Err(LabeledError::new("Invalid struct_ops object")
        .with_label(
            format!(
                "struct_ops '{}' is missing required callback closure(s): {}",
                value_type_name,
                missing.join(", ")
            ),
            span,
        )
        .with_help(help))
}

fn resolve_struct_ops_char_array_field_capacity(
    value_type_name: &str,
    field_name: &str,
    span: Span,
) -> Result<usize, LabeledError> {
    KernelBtf::get()
        .kernel_named_type_field_projection(
            value_type_name,
            &[TrampolineFieldSelector::Field(field_name.to_string())],
        )
        .map_err(|e| {
            LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "failed to resolve {}.{} from kernel BTF: {}",
                    value_type_name, field_name, e
                ),
                span,
            )
        })
        .and_then(|projection| match projection.type_info {
            TypeInfo::Array { element, len }
                if matches!(element.as_ref(), TypeInfo::Int { size: 1, .. }) =>
            {
                Ok(len)
            }
            other => Err(LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "{}.{} resolved to unexpected kernel BTF type {:?}",
                    value_type_name, field_name, other
                ),
                span,
            )),
        })
}

fn validate_struct_ops_non_negative_integer_field(
    value_type_name: &str,
    body: &Record,
    field_name: &str,
    span: Span,
) -> Result<(), LabeledError> {
    let Some(field_value) = body.get(field_name) else {
        return Ok(());
    };

    let raw_value = match field_value {
        Value::Int { val, .. } => *val,
        other => {
            return Err(LabeledError::new("Invalid struct_ops object")
                .with_label(
                    format!(
                        "struct_ops '{}' requires '{}' to be a non-negative integer, got {}",
                        value_type_name,
                        field_name,
                        other.get_type()
                    ),
                    other.span(),
                )
                .with_help(format!(
                    "Set '{}' to a non-negative integer that fits the kernel BTF field width",
                    field_name
                )));
        }
    };

    let value = u64::try_from(raw_value).map_err(|_| {
        LabeledError::new("Invalid struct_ops object")
            .with_label(
                format!(
                    "struct_ops '{}' requires '{}' to be a non-negative integer",
                    value_type_name, field_name
                ),
                field_value.span(),
            )
            .with_help(format!(
                "Set '{}' to a non-negative integer that fits the kernel BTF field width",
                field_name
            ))
    })?;

    let field_type = KernelBtf::get()
        .kernel_named_type_field_projection(
            value_type_name,
            &[TrampolineFieldSelector::Field(field_name.to_string())],
        )
        .map_err(|e| {
            LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "failed to resolve {}.{} from kernel BTF: {}",
                    value_type_name, field_name, e
                ),
                span,
            )
        })?;
    let TypeInfo::Int { size, signed } = field_type.type_info else {
        return Err(LabeledError::new("Invalid struct_ops object").with_label(
            format!(
                "{}.{} resolved to unexpected kernel BTF type {:?}",
                value_type_name, field_name, field_type.type_info
            ),
            span,
        ));
    };
    if signed {
        return Err(LabeledError::new("Invalid struct_ops object").with_label(
            format!(
                "{}.{} resolved to a signed integer field in kernel BTF; expected unsigned field",
                value_type_name, field_name
            ),
            span,
        ));
    }

    let max_value = match size {
        1 => u8::MAX as u64,
        2 => u16::MAX as u64,
        4 => u32::MAX as u64,
        8 => u64::MAX,
        other => {
            return Err(LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "{}.{} uses unsupported integer width {} in kernel BTF",
                    value_type_name, field_name, other
                ),
                span,
            ));
        }
    };
    if value > max_value {
        return Err(LabeledError::new("Invalid struct_ops object")
            .with_label(
                format!(
                    "struct_ops '{}.{}' value {} does not fit the kernel BTF field width ({} bytes)",
                    value_type_name, field_name, value, size
                ),
                field_value.span(),
            )
            .with_help(format!(
                "Use a non-negative integer no larger than {} for '{}'",
                max_value, field_name
            )));
    }

    Ok(())
}

fn resolve_sched_ext_allowed_flags_mask(span: Span) -> Result<u64, LabeledError> {
    let enum_info = KernelBtf::get()
        .kernel_named_enum_info("scx_ops_flags")
        .map_err(|e| {
            LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "failed to resolve sched_ext_ops flag definitions from kernel BTF: {}",
                    e
                ),
                span,
            )
        })?;
    if enum_info.is_signed {
        return Err(LabeledError::new("Invalid struct_ops object").with_label(
            "kernel BTF exposed signed sched_ext flag definitions; expected an unsigned bitmask enum",
            span,
        ));
    }

    if let Some((_, value)) = enum_info
        .entries
        .iter()
        .find(|(name, _)| name == "SCX_OPS_ALL_FLAGS")
    {
        return Ok(*value as u64);
    }

    let internal_mask = enum_info
        .entries
        .iter()
        .find(|(name, _)| name == "__SCX_OPS_INTERNAL_MASK")
        .map(|(_, value)| *value as u64)
        .unwrap_or(0);
    let allowed_mask = enum_info
        .entries
        .iter()
        .filter(|(name, _)| name.starts_with("SCX_OPS_") && name != "SCX_OPS_ALL_FLAGS")
        .fold(0u64, |mask, (_, value)| mask | (*value as u64))
        & !internal_mask;
    if allowed_mask == 0 {
        return Err(LabeledError::new("Invalid struct_ops object").with_label(
            "kernel BTF did not expose any usable sched_ext flag bits",
            span,
        ));
    }
    Ok(allowed_mask)
}

fn resolve_sched_ext_flag_bit(flag_name: &str, span: Span) -> Result<u64, LabeledError> {
    let enum_info = KernelBtf::get()
        .kernel_named_enum_info("scx_ops_flags")
        .map_err(|e| {
            LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "failed to resolve sched_ext_ops flag definitions from kernel BTF: {}",
                    e
                ),
                span,
            )
        })?;
    if enum_info.is_signed {
        return Err(LabeledError::new("Invalid struct_ops object").with_label(
            "kernel BTF exposed signed sched_ext flag definitions; expected an unsigned bitmask enum",
            span,
        ));
    }

    enum_info
        .entries
        .iter()
        .find(|(name, _)| name == flag_name)
        .map(|(_, value)| *value as u64)
        .ok_or_else(|| {
            LabeledError::new("Invalid struct_ops object").with_label(
                format!(
                    "kernel BTF did not expose the sched_ext flag '{}' on this system",
                    flag_name
                ),
                span,
            )
        })
}

const SCHED_EXT_MAX_TIMEOUT_MS: i64 = 30_000;
const SCHED_EXT_MAX_DISPATCH_BATCH: i64 = i32::MAX as i64;

fn validate_required_struct_ops_value_fields(
    value_type_name: &str,
    body: &Record,
    span: Span,
) -> Result<(), LabeledError> {
    match value_type_name {
        "tcp_congestion_ops" => {
            let Some(name_value) = body.get("name") else {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        "struct_ops 'tcp_congestion_ops' is missing required value field 'name'",
                        span,
                    )
                    .with_help(
                        "tcp_congestion_ops requires a non-empty 'name' value member, for example { name: 'nu_demo', ssthresh: {|ctx| 2 }, undo_cwnd: {|ctx| 2 }, cong_avoid: {|ctx| 0 } }",
                    ));
            };

            let name_len = match name_value {
                Value::String { val, .. } => val.len(),
                Value::Binary { val, .. } => val.len(),
                other => {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            format!(
                                "struct_ops 'tcp_congestion_ops' requires 'name' to be a string or binary byte buffer, got {}",
                                other.get_type()
                            ),
                            other.span(),
                        )
                        .with_help(
                            "Set 'name' to a short string like 'nu_demo' before registering tcp_congestion_ops",
                        ));
                }
            };
            if name_len == 0 {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        "struct_ops 'tcp_congestion_ops' requires a non-empty 'name' value field",
                        name_value.span(),
                    )
                    .with_help(
                        "Set 'name' to a non-empty string like 'nu_demo' before registering tcp_congestion_ops",
                    ));
            }

            let name_capacity =
                resolve_struct_ops_char_array_field_capacity("tcp_congestion_ops", "name", span)?;
            if name_len >= name_capacity {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        format!(
                            "struct_ops 'tcp_congestion_ops' name is too long: {} bytes for {}-byte field",
                            name_len, name_capacity
                        ),
                        name_value.span(),
                    )
                    .with_help(format!(
                        "Use a tcp_congestion_ops name shorter than {} bytes so it remains NUL-terminated",
                        name_capacity
                    )));
            }

            Ok(())
        }
        "sched_ext_ops" => {
            let Some(name_value) = body.get("name") else {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        "struct_ops 'sched_ext_ops' is missing required value field 'name'",
                        span,
                    )
                    .with_help(
                        "sched_ext_ops requires a non-empty 'name' value member, for example { name: 'nu_demo', select_cpu: {|ctx| 0 } }",
                    ));
            };

            let name = match name_value {
                Value::String { val, .. } => val,
                other => {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            format!(
                                "struct_ops 'sched_ext_ops' requires 'name' to be a string, got {}",
                                other.get_type()
                            ),
                            other.span(),
                        )
                        .with_help(
                            "Set 'name' to a non-empty string like 'nu_demo'; sched_ext_ops names must be valid BPF object names",
                        ));
                }
            };
            if name.is_empty() {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        "struct_ops 'sched_ext_ops' requires a non-empty 'name' value field",
                        name_value.span(),
                    )
                    .with_help(
                        "Set 'name' to a non-empty string like 'nu_demo' before building or registering sched_ext_ops",
                    ));
            }

            let name_capacity =
                resolve_struct_ops_char_array_field_capacity("sched_ext_ops", "name", span)?;
            if name.len() >= name_capacity {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        format!(
                            "struct_ops 'sched_ext_ops' name is too long: {} bytes for {}-byte field",
                            name.len(),
                            name_capacity
                        ),
                        name_value.span(),
                    )
                    .with_help(
                        format!(
                            "Use a sched_ext_ops name shorter than {} bytes so it remains NUL-terminated",
                            name_capacity
                        ),
                    ));
            }

            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
            {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        "struct_ops 'sched_ext_ops' name must be a valid BPF object name using only [A-Za-z0-9_.]",
                        name_value.span(),
                    )
                    .with_help(
                        "Use a name like 'nu_demo' or 'nu.demo_1' without spaces or dashes",
                    ));
            }

            let sched_ext_flags = if let Some(flags_value) = body.get("flags") {
                let flags = match flags_value {
                    Value::Int { val, .. } => u64::try_from(*val).map_err(|_| {
                        LabeledError::new("Invalid struct_ops object")
                            .with_label(
                                "struct_ops 'sched_ext_ops' requires 'flags' to be a non-negative integer bitmask",
                                flags_value.span(),
                            )
                            .with_help(
                                "Use an integer bitmask built from scx_ops_flags bits such as SCX_OPS_SWITCH_PARTIAL",
                            )
                    })?,
                    other => {
                        return Err(LabeledError::new("Invalid struct_ops object")
                            .with_label(
                                format!(
                                    "struct_ops 'sched_ext_ops' requires 'flags' to be a non-negative integer bitmask, got {}",
                                    other.get_type()
                                ),
                                other.span(),
                            )
                            .with_help(
                                "Use an integer bitmask built from scx_ops_flags bits such as SCX_OPS_SWITCH_PARTIAL",
                            ));
                    }
                };
                let allowed_flags = resolve_sched_ext_allowed_flags_mask(flags_value.span())?;
                let unknown_flags = flags & !allowed_flags;
                if unknown_flags != 0 {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            format!(
                                "struct_ops 'sched_ext_ops' flags set unknown or unsupported bits: 0x{unknown_flags:x}",
                            ),
                            flags_value.span(),
                        )
                        .with_help(format!(
                            "Use only kernel-supported scx_ops_flags bits on this system (allowed mask 0x{allowed_flags:x})",
                        )));
                }
                flags
            } else {
                0
            };

            if let Ok(enq_last) = resolve_sched_ext_flag_bit("SCX_OPS_ENQ_LAST", span) {
                if (sched_ext_flags & enq_last) != 0
                    && !matches!(body.get("enqueue"), Some(Value::Closure { .. }))
                {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            "struct_ops 'sched_ext_ops' sets SCX_OPS_ENQ_LAST without implementing 'enqueue'",
                            span,
                        )
                        .with_help(
                            "Add an enqueue callback when using SCX_OPS_ENQ_LAST, or clear the flag to keep the default post-slice behavior",
                        ));
                }
            }

            if matches!(body.get("update_idle"), Some(Value::Closure { .. }))
                && !matches!(body.get("select_cpu"), Some(Value::Closure { .. }))
            {
                let keep_builtin_idle =
                    resolve_sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE", span)?;
                if (sched_ext_flags & keep_builtin_idle) == 0 {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            "struct_ops 'sched_ext_ops' must define 'select_cpu' when 'update_idle' is implemented without SCX_OPS_KEEP_BUILTIN_IDLE",
                            span,
                        )
                        .with_help(
                            "Either add a select_cpu callback or set the SCX_OPS_KEEP_BUILTIN_IDLE flag to keep the built-in idle tracking path",
                        ));
                }
            }

            if let Ok(builtin_idle_per_node) =
                resolve_sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE", span)
            {
                if (sched_ext_flags & builtin_idle_per_node) != 0
                    && matches!(body.get("update_idle"), Some(Value::Closure { .. }))
                {
                    let keep_builtin_idle =
                        resolve_sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE", span)?;
                    if (sched_ext_flags & keep_builtin_idle) == 0 {
                        return Err(LabeledError::new("Invalid struct_ops object")
                            .with_label(
                                "struct_ops 'sched_ext_ops' sets SCX_OPS_BUILTIN_IDLE_PER_NODE without built-in CPU idle selection enabled",
                                span,
                            )
                            .with_help(
                                "Either clear SCX_OPS_BUILTIN_IDLE_PER_NODE, or set SCX_OPS_KEEP_BUILTIN_IDLE when update_idle is implemented",
                            ));
                    }
                }
            }

            validate_struct_ops_non_negative_integer_field(
                "sched_ext_ops",
                body,
                "dispatch_max_batch",
                span,
            )?;
            if let Some(dispatch_max_batch) = body.get("dispatch_max_batch") {
                let Value::Int { val, .. } = dispatch_max_batch else {
                    unreachable!("dispatch_max_batch type was already validated");
                };
                if *val > SCHED_EXT_MAX_DISPATCH_BATCH {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            format!(
                                "struct_ops 'sched_ext_ops' dispatch_max_batch is too large: {} exceeds the kernel INT_MAX limit {}",
                                val, SCHED_EXT_MAX_DISPATCH_BATCH
                            ),
                            dispatch_max_batch.span(),
                        )
                        .with_help(format!(
                            "Set dispatch_max_batch to at most {SCHED_EXT_MAX_DISPATCH_BATCH} to match the kernel sched_ext limit",
                        )));
                }
            }
            validate_struct_ops_non_negative_integer_field(
                "sched_ext_ops",
                body,
                "exit_dump_len",
                span,
            )?;
            validate_struct_ops_non_negative_integer_field(
                "sched_ext_ops",
                body,
                "hotplug_seq",
                span,
            )?;

            if let Some(timeout_value) = body.get("timeout_ms") {
                let timeout_ms = match timeout_value {
                    Value::Int { val, .. } => *val,
                    other => {
                        return Err(LabeledError::new("Invalid struct_ops object")
                            .with_label(
                                format!(
                                    "struct_ops 'sched_ext_ops' requires 'timeout_ms' to be a non-negative integer number of milliseconds, got {}",
                                    other.get_type()
                                ),
                                other.span(),
                            )
                            .with_help(format!(
                                "Use an integer timeout in milliseconds no greater than {SCHED_EXT_MAX_TIMEOUT_MS}",
                            )));
                    }
                };
                if timeout_ms < 0 {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            "struct_ops 'sched_ext_ops' requires 'timeout_ms' to be a non-negative integer number of milliseconds",
                            timeout_value.span(),
                        )
                        .with_help(format!(
                            "Use an integer timeout in milliseconds no greater than {SCHED_EXT_MAX_TIMEOUT_MS}",
                        )));
                }
                if timeout_ms > SCHED_EXT_MAX_TIMEOUT_MS {
                    return Err(LabeledError::new("Invalid struct_ops object")
                        .with_label(
                            format!(
                                "struct_ops 'sched_ext_ops' timeout_ms is too large: {}ms exceeds the documented {}ms maximum",
                                timeout_ms, SCHED_EXT_MAX_TIMEOUT_MS
                            ),
                            timeout_value.span(),
                        )
                        .with_help(format!(
                            "Set timeout_ms to at most {SCHED_EXT_MAX_TIMEOUT_MS} to match the sched_ext limit",
                        )));
                }
            }

            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_sched_ext_callback_kfunc_requirements(
    body: &Record,
    callback_kfuncs: &HashMap<String, HashSet<String>>,
    span: Span,
) -> Result<(), LabeledError> {
    if callback_kfuncs.is_empty() {
        return Ok(());
    }

    let flags = match body.get("flags") {
        Some(Value::Int { val, .. }) => u64::try_from(*val).unwrap_or(0),
        _ => 0,
    };
    let keep_builtin_idle = resolve_sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE", span)?;
    let builtin_idle_per_node = resolve_sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE", span)?;
    let builtin_idle_enabled = !matches!(body.get("update_idle"), Some(Value::Closure { .. }))
        || (flags & keep_builtin_idle) != 0;
    let per_node_idle_enabled = (flags & builtin_idle_per_node) != 0;

    for (callback, used_kfuncs) in callback_kfuncs {
        for kfunc in [
            "scx_bpf_select_cpu_dfl",
            "scx_bpf_select_cpu_and",
            "scx_bpf_test_and_clear_cpu_idle",
            "scx_bpf_pick_idle_cpu",
            "scx_bpf_pick_idle_cpu_node",
        ] {
            if !builtin_idle_enabled && used_kfuncs.contains(kfunc) {
                return Err(LabeledError::new("Invalid struct_ops object")
                    .with_label(
                        format!(
                            "sched_ext_ops.{callback} uses '{kfunc}', but built-in idle tracking is disabled by update_idle",
                        ),
                        span,
                    )
                    .with_help(
                        "Remove update_idle, or set SCX_OPS_KEEP_BUILTIN_IDLE to keep the built-in idle helpers available",
                    ));
            }
        }

        if per_node_idle_enabled && used_kfuncs.contains("scx_bpf_pick_idle_cpu") {
            return Err(LabeledError::new("Invalid struct_ops object")
                .with_label(
                    format!(
                        "sched_ext_ops.{callback} uses 'scx_bpf_pick_idle_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE enables per-node idle masks",
                    ),
                    span,
                )
                .with_help(
                    "Use scx_bpf_pick_idle_cpu_node when SCX_OPS_BUILTIN_IDLE_PER_NODE is set, or clear the flag to keep the flat idle mask helpers",
                ));
        }

        if per_node_idle_enabled && used_kfuncs.contains("scx_bpf_pick_any_cpu") {
            return Err(LabeledError::new("Invalid struct_ops object")
                .with_label(
                    format!(
                        "sched_ext_ops.{callback} uses 'scx_bpf_pick_any_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE requires scx_bpf_pick_idle_cpu_node instead",
                    ),
                    span,
                )
                .with_help(
                    "Use scx_bpf_pick_idle_cpu_node when SCX_OPS_BUILTIN_IDLE_PER_NODE is set, or clear the flag to keep the flat idle mask helpers",
                ));
        }

        if !per_node_idle_enabled && used_kfuncs.contains("scx_bpf_pick_idle_cpu_node") {
            return Err(LabeledError::new("Invalid struct_ops object")
                .with_label(
                    format!(
                        "sched_ext_ops.{callback} uses 'scx_bpf_pick_idle_cpu_node' without SCX_OPS_BUILTIN_IDLE_PER_NODE",
                    ),
                    span,
                )
                .with_help(
                    "Set SCX_OPS_BUILTIN_IDLE_PER_NODE to enable per-node idle mask helpers, or use scx_bpf_pick_idle_cpu instead",
                ));
        }
    }

    Ok(())
}

fn sanitize_struct_ops_component(component: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "struct_ops".to_string()
    } else {
        trimmed.to_string()
    }
}

fn default_struct_ops_object_name(value_type_name: &str) -> String {
    format!("nu_{}", sanitize_struct_ops_component(value_type_name))
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

    let lower_result = lower_hir_to_mir_with_hints_and_maps(
        &hir_program,
        Some(probe_context),
        &decl_names,
        Some(&hir_types),
        external_map_value_types.as_ref(),
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
    example `($ctx.remote_ip6 | get 3)`.

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
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::compiler::hir::{
        HirBlock, HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram, HirStmt,
        HirTerminator,
    };
    use crate::compiler::hir_to_mir::{
        lower_hir_to_mir_with_hints, lower_hir_to_mir_with_hints_and_maps,
    };
    use crate::compiler::mir::{AddressSpace, MapKind, MapRef, StructField};
    use crate::compiler::passes::optimize_with_ssa_hints;
    use crate::compiler::{
        CounterKeySchema, CounterKeySchemaField, EbpfProgramType, MirType, ProbeContext,
        StructOpsObjectSpec, StructOpsValueField, compile_mir_to_ebpf_with_hints,
    };
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
    use nu_protocol::DeclId;
    use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::engine::Closure;
    use nu_protocol::ir::{Instruction, IrBlock};
    use nu_protocol::{BlockId, Record, RegId, Span, Type, Value, VarId};

    #[test]
    fn test_extract_decl_names_from_formatted_instructions_preserves_user_function_names() {
        let decl_names = super::extract_decl_names_from_formatted_instructions(&[
            r#"call                   decl 488 "global-define", %0"#.to_string(),
            r#"call                   decl 489 "project-entry", %1"#.to_string(),
            r#"call                   decl 490 "count", %2"#.to_string(),
            r#"call                   decl 491 "get", %3"#.to_string(),
        ]);

        assert_eq!(
            decl_names,
            HashMap::from([
                (DeclId::new(488), "global-define".to_string()),
                (DeclId::new(489), "project-entry".to_string()),
                (DeclId::new(490), "count".to_string()),
                (DeclId::new(491), "get".to_string()),
            ])
        );
    }

    #[test]
    fn test_parse_inline_user_function_signatures_extracts_closure_local_def() {
        let source = r#"{|ctx|
            def bump [msg] { "ok" }
            let next = (bump "hi")
            $next | count
        }"#;
        let decl_ids = HashSet::from([DeclId::new(515)]);
        let decl_names = HashMap::from([(DeclId::new(515), "bump".to_string())]);

        let sigs = super::parse_inline_user_function_signatures(
            source,
            &decl_ids,
            &decl_names,
            Span::test_data(),
        )
        .expect("inline def signatures should parse");

        assert_eq!(sigs.len(), 1);
        let sig = sigs
            .get(&DeclId::new(515))
            .expect("bump signature should exist");
        assert_eq!(sig.params.len(), 2);
        assert!(matches!(
            sig.params[0],
            crate::compiler::UserParam {
                kind: crate::compiler::UserParamKind::Input,
                ..
            }
        ));
        assert!(matches!(
            sig.params[1],
            crate::compiler::UserParam {
                kind: crate::compiler::UserParamKind::Positional,
                optional: false,
                ..
            }
        ));
        assert_eq!(sig.params[1].name.as_deref(), Some("msg"));
    }

    #[test]
    fn test_parse_inline_user_function_signatures_skips_ambiguous_names() {
        let source = r#"{|ctx| def bump [msg] { "ok" } }"#;
        let decl_ids = HashSet::from([DeclId::new(515), DeclId::new(516)]);
        let decl_names = HashMap::from([
            (DeclId::new(515), "bump".to_string()),
            (DeclId::new(516), "bump".to_string()),
        ]);

        let sigs = super::parse_inline_user_function_signatures(
            source,
            &decl_ids,
            &decl_names,
            Span::test_data(),
        )
        .expect("ambiguous inline defs should not error");

        assert!(sigs.is_empty(), "ambiguous def names should not be guessed");
    }

    #[test]
    fn test_map_leading_annotated_mut_globals_uses_leading_declaration_order() {
        let source =
            "{|| let tmp = 1; mut state: record<pid: int ok: bool> = {pid: 0, ok: false}; $state }";
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(10),
                    src: RegId::new(0),
                },
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(1),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 4],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 4],
            comments: vec!["let".into(), "let".into(), "".into(), "".into()],
            register_count: 2,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .expect("leading annotated mut globals should map cleanly");

        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].var_id, VarId::new(11));
        assert_eq!(
            globals[0].declared_type,
            Type::Record(Box::new([
                ("pid".to_string(), Type::Int),
                ("ok".to_string(), Type::Bool),
            ]))
        );
        match &globals[0].initial_value {
            Value::Record { val, .. } => {
                assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(0));
                assert_eq!(val.get("ok").and_then(|v| v.as_bool().ok()), Some(false));
            }
            other => panic!("expected record initializer, got {other:?}"),
        }
    }

    #[test]
    fn test_map_leading_annotated_mut_globals_rejects_non_leading_annotated_mut() {
        let source = "{|| 1 | count; mut state: int = 0; $state }";
        let ir_block = IrBlock {
            instructions: vec![Instruction::StoreVariable {
                var_id: VarId::new(80),
                src: RegId::new(0),
            }],
            spans: vec![Span::test_data()],
            data: Vec::<u8>::new().into(),
            ast: vec![None],
            comments: vec!["let".into()],
            register_count: 1,
            file_count: 0,
        };

        let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
            .expect_err("non-leading annotated mut declarations should fail clearly");
        assert!(
            err.to_string()
                .contains("Annotated mutable globals must be declared first"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_map_leading_annotated_mut_globals_ignores_non_leading_untyped_mut() {
        let source = "{|| 1 | count; mut state = 0; $state }";
        let ir_block = IrBlock {
            instructions: vec![Instruction::StoreVariable {
                var_id: VarId::new(80),
                src: RegId::new(0),
            }],
            spans: vec![Span::test_data()],
            data: Vec::<u8>::new().into(),
            ast: vec![None],
            comments: vec!["let".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .expect("non-leading untyped mut should remain an ordinary local");

        assert!(globals.is_empty());
    }

    #[test]
    fn test_strip_leading_annotated_mut_initializer_stmts_removes_leading_initializer_code() {
        let mut hir = HirProgram::new(
            HirFunction {
                blocks: vec![HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadValue {
                            dst: RegId::new(0),
                            val: Box::new(Value::int(7, Span::test_data())),
                        },
                        HirStmt::StoreVariable {
                            var_id: VarId::new(10),
                            src: RegId::new(0),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(1),
                            var_id: VarId::new(10),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(1) },
                }],
                entry: HirBlockId(0),
                spans: vec![Span::test_data(); 3],
                ast: vec![None; 3],
                comments: vec![],
                register_count: 2,
                file_count: 0,
            },
            HashMap::new(),
            vec![],
            None,
        );
        hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
            var_id: VarId::new(10),
            declared_type: Type::Int,
            initial_value: Value::int(7, Span::test_data()),
        }];

        super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
            .expect("leading annotated mut initializer should strip cleanly");

        assert_eq!(hir.main.blocks[0].stmts.len(), 1);
        assert!(matches!(
            &hir.main.blocks[0].stmts[0],
            HirStmt::LoadVariable {
                var_id,
                dst: RegId { .. }
            } if *var_id == VarId::new(10)
        ));
    }

    #[test]
    fn test_strip_leading_annotated_mut_initializer_stmts_keeps_following_code() {
        let mut hir = HirProgram::new(
            HirFunction {
                blocks: vec![HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadValue {
                            dst: RegId::new(0),
                            val: Box::new(Value::int(1, Span::test_data())),
                        },
                        HirStmt::StoreVariable {
                            var_id: VarId::new(10),
                            src: RegId::new(0),
                        },
                        HirStmt::LoadValue {
                            dst: RegId::new(1),
                            val: Box::new(Value::int(2, Span::test_data())),
                        },
                        HirStmt::StoreVariable {
                            var_id: VarId::new(11),
                            src: RegId::new(1),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(2),
                            var_id: VarId::new(99),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(2) },
                }],
                entry: HirBlockId(0),
                spans: vec![Span::test_data(); 5],
                ast: vec![None; 5],
                comments: vec![],
                register_count: 3,
                file_count: 0,
            },
            HashMap::new(),
            vec![],
            None,
        );
        hir.annotated_mut_globals = vec![
            crate::compiler::hir::AnnotatedMutGlobal {
                var_id: VarId::new(10),
                declared_type: Type::Int,
                initial_value: Value::int(1, Span::test_data()),
            },
            crate::compiler::hir::AnnotatedMutGlobal {
                var_id: VarId::new(11),
                declared_type: Type::Int,
                initial_value: Value::int(2, Span::test_data()),
            },
        ];

        super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
            .expect("multiple leading annotated mut initializers should strip cleanly");

        assert_eq!(hir.main.blocks[0].stmts.len(), 1);
        assert!(matches!(
            &hir.main.blocks[0].stmts[0],
            HirStmt::LoadVariable { var_id, .. } if *var_id == VarId::new(99)
        ));
    }

    #[test]
    fn test_strip_leading_annotated_mut_initializer_stmts_removes_initializer_cleanup() {
        let mut hir = HirProgram::new(
            HirFunction {
                blocks: vec![HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadValue {
                            dst: RegId::new(0),
                            val: Box::new(Value::int(1, Span::test_data())),
                        },
                        HirStmt::StoreVariable {
                            var_id: VarId::new(10),
                            src: RegId::new(0),
                        },
                        HirStmt::Drain { src: RegId::new(0) },
                        HirStmt::Drop { src: RegId::new(0) },
                        HirStmt::LoadVariable {
                            dst: RegId::new(1),
                            var_id: VarId::new(10),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(1) },
                }],
                entry: HirBlockId(0),
                spans: vec![Span::test_data(); 5],
                ast: vec![None; 5],
                comments: vec![],
                register_count: 2,
                file_count: 0,
            },
            HashMap::new(),
            vec![],
            None,
        );
        hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
            var_id: VarId::new(10),
            declared_type: Type::Int,
            initial_value: Value::int(1, Span::test_data()),
        }];

        super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
            .expect("leading annotated mut cleanup should strip cleanly");

        assert_eq!(hir.main.blocks[0].stmts.len(), 1);
        assert!(matches!(
            &hir.main.blocks[0].stmts[0],
            HirStmt::LoadVariable {
                var_id,
                dst: RegId { .. }
            } if *var_id == VarId::new(10)
        ));
    }

    #[test]
    fn test_value_to_spanned_closure_accepts_closure_value() {
        let closure = Closure {
            block_id: BlockId::new(7),
            captures: vec![],
        };
        let value = Value::closure(closure.clone(), Span::test_data());

        let lowered = super::value_to_spanned_closure(value, Span::test_data())
            .expect("closure should lower");

        assert_eq!(lowered.item.block_id, closure.block_id);
    }

    #[test]
    fn test_struct_ops_value_field_from_value_accepts_binary() {
        let field = super::struct_ops_value_field_from_value(
            "cookie",
            &Value::binary(vec![1, 2, 3], Span::test_data()),
        )
        .expect("binary field should lower");

        assert_eq!(field, StructOpsValueField::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn test_struct_ops_value_field_from_value_accepts_int_list() {
        let field = super::struct_ops_value_field_from_value(
            "cookie",
            &Value::list(
                vec![
                    Value::int(1, Span::test_data()),
                    Value::int(2, Span::test_data()),
                ],
                Span::test_data(),
            ),
        )
        .expect("int-list field should lower");

        assert_eq!(field, StructOpsValueField::IntList(vec![1, 2]));
    }

    #[test]
    fn test_struct_ops_value_field_from_value_rejects_mixed_list() {
        let err = super::struct_ops_value_field_from_value(
            "cookie",
            &Value::list(
                vec![
                    Value::int(1, Span::test_data()),
                    Value::string("oops", Span::test_data()),
                ],
                Span::test_data(),
            ),
        )
        .expect_err("mixed list should be rejected");

        assert!(
            err.to_string()
                .contains("Unsupported struct_ops value field")
        );
    }

    #[test]
    fn test_struct_ops_value_field_from_value_rejects_record() {
        let mut record = Record::new();
        record.push("pid", Value::int(7, Span::test_data()));

        let err = super::struct_ops_value_field_from_value(
            "state",
            &Value::record(record, Span::test_data()),
        )
        .expect_err("record field should be rejected");

        assert!(
            err.to_string()
                .contains("Unsupported struct_ops value field")
        );
    }

    fn find_nested_struct_ops_value_candidate() -> Option<(String, Vec<String>, usize, usize)> {
        for (type_name, path) in [
            ("task_struct", vec!["se", "avg", "util_avg"]),
            ("task_struct", vec!["se", "avg", "load_avg"]),
            ("task_struct", vec!["thread", "pid"]),
        ] {
            let selectors: Vec<_> = path
                .iter()
                .map(|segment| TrampolineFieldSelector::Field((*segment).to_string()))
                .collect();
            let Ok(projection) =
                KernelBtf::get().kernel_named_type_field_projection(type_name, &selectors)
            else {
                continue;
            };
            if projection.path.len() <= 1
                || projection
                    .path
                    .iter()
                    .take(projection.path.len().saturating_sub(1))
                    .any(|segment| matches!(segment.type_info, TypeInfo::Ptr { .. }))
                || !matches!(projection.type_info, TypeInfo::Int { .. })
            {
                continue;
            }
            let Some(offset) = projection
                .path
                .iter()
                .try_fold(0usize, |acc, segment| acc.checked_add(segment.offset_bytes))
            else {
                continue;
            };
            return Some((
                type_name.to_string(),
                path.into_iter().map(str::to_string).collect(),
                offset,
                projection.type_info.size(),
            ));
        }
        None
    }

    fn find_struct_ops_array_record_candidate() -> Option<(String, usize, usize)> {
        for (type_name, path) in [(
            "task_struct",
            vec![
                TrampolineFieldSelector::Field("uclamp_req".to_string()),
                TrampolineFieldSelector::Index(0),
                TrampolineFieldSelector::Field("value".to_string()),
            ],
        )] {
            let Ok(projection) =
                KernelBtf::get().kernel_named_type_field_projection(type_name, &path)
            else {
                continue;
            };
            if projection.path.len() <= 2
                || projection
                    .path
                    .iter()
                    .take(projection.path.len().saturating_sub(1))
                    .any(|segment| matches!(segment.type_info, TypeInfo::Ptr { .. }))
                || !matches!(projection.type_info, TypeInfo::Int { .. })
            {
                continue;
            }
            let Some(offset) = projection
                .path
                .iter()
                .try_fold(0usize, |acc, segment| acc.checked_add(segment.offset_bytes))
            else {
                continue;
            };
            return Some((type_name.to_string(), offset, projection.type_info.size()));
        }
        None
    }

    fn find_struct_ops_callback_member_candidate() -> Option<(String, String)> {
        for (value_type_name, field_name) in [
            ("sched_ext_ops", "select_cpu"),
            ("tcp_congestion_ops", "cong_avoid"),
            ("tcp_congestion_ops", "ssthresh"),
        ] {
            if KernelBtf::get()
                .struct_ops_callback_ret_type_info(value_type_name, field_name)
                .is_ok()
            {
                return Some((value_type_name.to_string(), field_name.to_string()));
            }
        }
        None
    }

    fn find_struct_ops_value_member_candidate() -> Option<(String, String)> {
        for (value_type_name, field_name) in [
            ("tcp_congestion_ops", "name"),
            ("tcp_congestion_ops", "flags"),
            ("sched_ext_ops", "name"),
        ] {
            if KernelBtf::get()
                .struct_ops_callback_ret_type_info(value_type_name, field_name)
                .is_err()
                && KernelBtf::get()
                    .kernel_named_type_field_projection(
                        value_type_name,
                        &[TrampolineFieldSelector::Field(field_name.to_string())],
                    )
                    .is_ok()
            {
                return Some((value_type_name.to_string(), field_name.to_string()));
            }
        }
        None
    }

    #[test]
    fn test_apply_struct_ops_value_field_initializes_nested_record_member() {
        let Some((type_name, path, offset, size)) = find_nested_struct_ops_value_candidate() else {
            return;
        };
        let nested =
            path[1..]
                .iter()
                .rev()
                .fold(Value::int(7, Span::test_data()), |acc, segment| {
                    let mut record = Record::new();
                    record.push(segment.as_str(), acc);
                    Value::record(record, Span::test_data())
                });

        let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", &type_name)
            .expect("expected zeroed spec for nested value-field candidate");
        let mut field_path = vec![TrampolineFieldSelector::Field(path[0].clone())];
        let spec = super::apply_struct_ops_value_field(spec, &mut field_path, &nested)
            .expect("nested struct_ops value field should lower");
        let object = spec
            .to_object()
            .expect("nested struct_ops object should build");

        let bytes = &object.extra_data_symbols[0].data[offset..offset + size];
        let value = match size {
            1 => i8::from_le_bytes([bytes[0]]) as i64,
            2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
            4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
            8 => i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            other => panic!("unexpected integer width {}", other),
        };
        assert_eq!(value, 7);
    }

    #[test]
    fn test_apply_struct_ops_value_field_initializes_array_of_record_member() {
        let Some((type_name, offset, size)) = find_struct_ops_array_record_candidate() else {
            return;
        };
        let mut elem = Record::new();
        elem.push("value", Value::int(17, Span::test_data()));
        let value = Value::list(
            vec![Value::record(elem, Span::test_data())],
            Span::test_data(),
        );

        let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", &type_name)
            .expect("expected zeroed spec for array-of-record candidate");
        let mut field_path = vec![TrampolineFieldSelector::Field("uclamp_req".to_string())];
        let spec = super::apply_struct_ops_value_field(spec, &mut field_path, &value)
            .expect("array-of-record struct_ops value field should lower");
        let object = spec
            .to_object()
            .expect("array-of-record struct_ops object should build");

        let bytes = &object.extra_data_symbols[0].data[offset..offset + size];
        let value = match size {
            1 => i8::from_le_bytes([bytes[0]]) as i64,
            2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
            4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
            8 => i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            other => panic!("unexpected integer width {}", other),
        };
        assert_eq!(value, 17);
    }

    #[test]
    fn test_apply_struct_ops_value_field_rejects_nested_callback() {
        let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
            .expect("expected zeroed task_struct object spec");
        let mut nested = Record::new();
        nested.push(
            "leaf",
            Value::closure(
                Closure {
                    block_id: BlockId::new(0),
                    captures: vec![],
                },
                Span::test_data(),
            ),
        );
        let mut field_path = vec![TrampolineFieldSelector::Field("state".to_string())];
        let err = super::apply_struct_ops_value_field(
            spec,
            &mut field_path,
            &Value::record(nested, Span::test_data()),
        )
        .expect_err("nested callback should be rejected");
        assert!(err.to_string().contains("Invalid struct_ops object"));
    }

    #[test]
    fn test_validate_struct_ops_top_level_field_kind_rejects_closure_on_value_member() {
        let Some((value_type_name, field_name)) = find_struct_ops_value_member_candidate() else {
            return;
        };
        let err = super::validate_struct_ops_top_level_field_kind(
            &value_type_name,
            &field_name,
            super::StructOpsTopLevelFieldKind::Callback,
            Span::test_data(),
        )
        .expect_err("value member used as callback slot should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| label.text.contains("value member, not a callback slot"))
        );
    }

    #[test]
    fn test_validate_struct_ops_top_level_field_kind_rejects_constant_on_callback_member() {
        let Some((value_type_name, field_name)) = find_struct_ops_callback_member_candidate()
        else {
            return;
        };
        let err = super::validate_struct_ops_top_level_field_kind(
            &value_type_name,
            &field_name,
            super::StructOpsTopLevelFieldKind::Value,
            Span::test_data(),
        )
        .expect_err("callback member used as value field should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| label.text.contains("callback slot; provide a closure"))
        );
    }

    #[test]
    fn test_validate_struct_ops_attach_safety_rejects_sched_ext_live_load_by_default() {
        let err = super::validate_struct_ops_attach_safety(
            "sched_ext_ops",
            false,
            false,
            Span::test_data(),
        )
        .expect_err("live sched_ext attach should require explicit opt-in");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("live loading of struct_ops 'sched_ext_ops' is disabled by default")
        }));
    }

    #[test]
    fn test_validate_struct_ops_attach_safety_allows_sched_ext_dry_run() {
        super::validate_struct_ops_attach_safety("sched_ext_ops", true, false, Span::test_data())
            .expect("dry-run sched_ext attach should stay allowed");
    }

    #[test]
    fn test_validate_struct_ops_attach_safety_allows_sched_ext_with_explicit_opt_in() {
        super::validate_struct_ops_attach_safety("sched_ext_ops", false, true, Span::test_data())
            .expect("explicit opt-in should allow live sched_ext attach");
    }

    #[test]
    fn test_validate_struct_ops_attach_safety_allows_lower_risk_families() {
        super::validate_struct_ops_attach_safety(
            "tcp_congestion_ops",
            false,
            false,
            Span::test_data(),
        )
        .expect("lower-risk struct_ops families should not be gated");
    }

    #[test]
    fn test_validate_required_struct_ops_callbacks_rejects_missing_tcp_congestion_callbacks() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        let err = super::validate_required_struct_ops_callbacks(
            "tcp_congestion_ops",
            &HashSet::from(["ssthresh".to_string()]),
            Span::test_data(),
        )
        .expect_err("missing required tcp_congestion_ops callbacks should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("missing required callback closure(s): cong_avoid, undo_cwnd")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_callbacks_allows_complete_tcp_congestion_callbacks() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        super::validate_required_struct_ops_callbacks(
            "tcp_congestion_ops",
            &HashSet::from([
                "ssthresh".to_string(),
                "cong_avoid".to_string(),
                "undo_cwnd".to_string(),
            ]),
            Span::test_data(),
        )
        .expect("complete tcp_congestion_ops callbacks should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_missing_tcp_congestion_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        let err = super::validate_required_struct_ops_value_fields(
            "tcp_congestion_ops",
            &Record::new(),
            Span::test_data(),
        )
        .expect_err("missing tcp_congestion_ops name should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("missing required value field 'name'") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_empty_tcp_congestion_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("", Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "tcp_congestion_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("empty tcp_congestion_ops name should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires a non-empty 'name' value field")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_non_empty_tcp_congestion_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu_demo", Span::test_data()));

        super::validate_required_struct_ops_value_fields(
            "tcp_congestion_ops",
            &body,
            Span::test_data(),
        )
        .expect("non-empty tcp_congestion_ops name should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_non_string_tcp_congestion_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("tcp_congestion_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::int(7, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "tcp_congestion_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("integer tcp_congestion_ops name should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'name' to be a string or binary byte buffer")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_too_long_tcp_congestion_name() {
        let Ok(name_capacity) = super::resolve_struct_ops_char_array_field_capacity(
            "tcp_congestion_ops",
            "name",
            Span::test_data(),
        ) else {
            return;
        };

        let mut body = Record::new();
        body.push(
            "name",
            Value::string("x".repeat(name_capacity), Span::test_data()),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "tcp_congestion_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("overlong tcp_congestion_ops name should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("struct_ops 'tcp_congestion_ops' name is too long")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_missing_sched_ext_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &Record::new(),
            Span::test_data(),
        )
        .expect_err("missing sched_ext_ops name should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("missing required value field 'name'") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_empty_sched_ext_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("", Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("empty sched_ext_ops name should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires a non-empty 'name' value field")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_non_empty_sched_ext_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu_demo", Span::test_data()));

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("non-empty sched_ext_ops name should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_non_string_sched_ext_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::binary(vec![0x6e, 0x75], Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("binary sched_ext_ops name should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("requires 'name' to be a string") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_invalid_sched_ext_name_chars() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu-demo", Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("invalid sched_ext_ops object name chars should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("must be a valid BPF object name using only [A-Za-z0-9_.]")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_too_long_sched_ext_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("x".repeat(128), Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("overlong sched_ext_ops name should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("struct_ops 'sched_ext_ops' name is too long")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_valid_sched_ext_object_name() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("valid sched_ext_ops object names should be allowed");
    }

    fn sched_ext_flag_masks() -> Option<(u64, u64)> {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return None;
        }
        let allowed = super::resolve_sched_ext_allowed_flags_mask(Span::test_data()).ok()?;
        let known = (0..63)
            .map(|bit| 1u64 << bit)
            .find(|bit| (allowed & *bit) != 0)?;
        let unknown = (0..63)
            .map(|bit| 1u64 << bit)
            .find(|bit| (allowed & *bit) == 0)?;
        Some((known, unknown))
    }

    fn sched_ext_flag_bit(flag_name: &str) -> Option<u64> {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return None;
        }
        super::resolve_sched_ext_flag_bit(flag_name, Span::test_data()).ok()
    }

    fn test_closure_value() -> Value {
        Value::closure(
            Closure {
                block_id: BlockId::new(0),
                captures: vec![],
            },
            Span::test_data(),
        )
    }

    fn sched_ext_callback_kfuncs(
        callback: &str,
        kfuncs: &[&str],
    ) -> HashMap<String, HashSet<String>> {
        HashMap::from([(
            callback.to_string(),
            kfuncs.iter().map(|kfunc| (*kfunc).to_string()).collect(),
        )])
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_non_int_sched_ext_flags() {
        if sched_ext_flag_masks().is_none() {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("flags", Value::bool(true, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("non-integer sched_ext_ops flags should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'flags' to be a non-negative integer bitmask")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_negative_sched_ext_flags() {
        if sched_ext_flag_masks().is_none() {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("flags", Value::int(-1, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("negative sched_ext_ops flags should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'flags' to be a non-negative integer bitmask")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_unknown_sched_ext_flags_bits() {
        let Some((_, unknown_flags)) = sched_ext_flag_masks() else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(unknown_flags).expect("unknown flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("unknown sched_ext_ops flag bits should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("flags set unknown or unsupported bits") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_known_sched_ext_flags_bits() {
        let Some((known_flags, _)) = sched_ext_flag_masks() else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(known_flags).expect("known flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("known sched_ext_ops flags should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_enq_last_without_enqueue() {
        let Some(enq_last) = sched_ext_flag_bit("SCX_OPS_ENQ_LAST") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(enq_last).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("SCX_OPS_ENQ_LAST without enqueue should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("sets SCX_OPS_ENQ_LAST without implementing 'enqueue'")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_enq_last_with_enqueue() {
        let Some(enq_last) = sched_ext_flag_bit("SCX_OPS_ENQ_LAST") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(enq_last).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );
        body.push("enqueue", test_closure_value());

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("SCX_OPS_ENQ_LAST with enqueue should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_non_int_sched_ext_timeout() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("timeout_ms", Value::bool(true, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("non-integer sched_ext_ops timeout_ms should be rejected");
        assert!(err.labels.iter().any(|label| {
            label.text.contains(
                "requires 'timeout_ms' to be a non-negative integer number of milliseconds",
            )
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_negative_sched_ext_timeout() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("timeout_ms", Value::int(-1, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("negative sched_ext_ops timeout_ms should be rejected");
        assert!(err.labels.iter().any(|label| {
            label.text.contains(
                "requires 'timeout_ms' to be a non-negative integer number of milliseconds",
            )
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_too_large_sched_ext_timeout() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "timeout_ms",
            Value::int(super::SCHED_EXT_MAX_TIMEOUT_MS + 1, Span::test_data()),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("overlarge sched_ext_ops timeout_ms should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("timeout_ms is too large") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_sched_ext_timeout_within_limit() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "timeout_ms",
            Value::int(super::SCHED_EXT_MAX_TIMEOUT_MS, Span::test_data()),
        );

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("sched_ext_ops timeout_ms within limit should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_update_idle_without_select_cpu() {
        let Some(_keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err(
            "sched_ext_ops update_idle without select_cpu or KEEP_BUILTIN_IDLE should be rejected",
        );
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("must define 'select_cpu' when 'update_idle' is implemented")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_update_idle_with_select_cpu() {
        let Some(_keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push("select_cpu", test_closure_value());

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("sched_ext_ops update_idle with select_cpu should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_update_idle_with_keep_builtin_idle() {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("sched_ext_ops update_idle with KEEP_BUILTIN_IDLE should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_builtin_idle_per_node_without_builtin_idle_enabled()
     {
        let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE")
        else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push("select_cpu", test_closure_value());
        body.push(
            "flags",
            Value::int(
                i64::try_from(builtin_idle_per_node).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("SCX_OPS_BUILTIN_IDLE_PER_NODE without builtin idle should be rejected");
        assert!(err.labels.iter().any(|label| {
            label.text.contains(
                "sets SCX_OPS_BUILTIN_IDLE_PER_NODE without built-in CPU idle selection enabled",
            )
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_builtin_idle_per_node_with_keep_builtin_idle()
     {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };
        let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE")
        else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                    .expect("flag bits should fit in i64"),
                Span::test_data(),
            ),
        );
        body.push("select_cpu", test_closure_value());

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("SCX_OPS_BUILTIN_IDLE_PER_NODE with KEEP_BUILTIN_IDLE should be allowed");
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_rejects_builtin_idle_kfuncs_when_update_idle_disables_builtin_idle()
     {
        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push("select_cpu", test_closure_value());

        for kfunc in [
            "scx_bpf_select_cpu_dfl",
            "scx_bpf_select_cpu_and",
            "scx_bpf_test_and_clear_cpu_idle",
            "scx_bpf_pick_idle_cpu",
            "scx_bpf_pick_idle_cpu_node",
        ] {
            let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &[kfunc]);
            let err =
                super::validate_sched_ext_callback_kfunc_requirements(
                    &body,
                    &callback_kfuncs,
                    Span::test_data(),
                )
                .expect_err("builtin-idle kfunc should be rejected when update_idle disables builtin idle tracking");
            assert!(
                err.labels.iter().any(|label| label.text.contains(kfunc)),
                "unexpected errors for {kfunc}: {:?}",
                err
            );
        }
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_allows_builtin_idle_kfuncs_with_keep_builtin_idle()
     {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("update_idle", test_closure_value());
        body.push("select_cpu", test_closure_value());
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        for kfunc in [
            "scx_bpf_select_cpu_dfl",
            "scx_bpf_select_cpu_and",
            "scx_bpf_test_and_clear_cpu_idle",
            "scx_bpf_pick_idle_cpu",
        ] {
            let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &[kfunc]);
            super::validate_sched_ext_callback_kfunc_requirements(
                &body,
                &callback_kfuncs,
                Span::test_data(),
            )
            .expect("KEEP_BUILTIN_IDLE should preserve builtin-idle kfunc availability");
        }
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_rejects_pick_idle_cpu_node_without_per_node_flag()
     {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
                Span::test_data(),
            ),
        );

        let callback_kfuncs =
            sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu_node"]);
        let err = super::validate_sched_ext_callback_kfunc_requirements(
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect_err("pick_idle_cpu_node should require SCX_OPS_BUILTIN_IDLE_PER_NODE");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("uses 'scx_bpf_pick_idle_cpu_node' without SCX_OPS_BUILTIN_IDLE_PER_NODE")
        }));
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_rejects_pick_idle_cpu_with_per_node_flag()
     {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };
        let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE")
        else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                    .expect("flag bits should fit in i64"),
                Span::test_data(),
            ),
        );

        let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu"]);
        let err = super::validate_sched_ext_callback_kfunc_requirements(
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect_err("pick_idle_cpu should be rejected when per-node idle masks are enabled");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("uses 'scx_bpf_pick_idle_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE enables per-node idle masks")
        }));
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_rejects_pick_any_cpu_with_per_node_flag()
    {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };
        let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE")
        else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                    .expect("flag bits should fit in i64"),
                Span::test_data(),
            ),
        );

        let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_any_cpu"]);
        let err = super::validate_sched_ext_callback_kfunc_requirements(
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect_err("pick_any_cpu should be rejected when per-node idle masks are enabled");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("uses 'scx_bpf_pick_any_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE requires scx_bpf_pick_idle_cpu_node instead")
        }));
    }

    #[test]
    fn test_validate_sched_ext_callback_kfunc_requirements_allows_pick_idle_cpu_node_with_per_node_flag()
     {
        let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
            return;
        };
        let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE")
        else {
            return;
        };

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "flags",
            Value::int(
                i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                    .expect("flag bits should fit in i64"),
                Span::test_data(),
            ),
        );

        let callback_kfuncs =
            sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu_node"]);
        super::validate_sched_ext_callback_kfunc_requirements(
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect(
            "pick_idle_cpu_node should be allowed when per-node builtin idle masks are enabled",
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_non_int_dispatch_max_batch() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("dispatch_max_batch", Value::bool(true, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("non-integer sched_ext_ops dispatch_max_batch should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'dispatch_max_batch' to be a non-negative integer")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_negative_dispatch_max_batch() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("dispatch_max_batch", Value::int(-1, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("negative sched_ext_ops dispatch_max_batch should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'dispatch_max_batch' to be a non-negative integer")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_too_large_dispatch_max_batch() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "dispatch_max_batch",
            Value::int(i64::from(u32::MAX) + 1, Span::test_data()),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("oversized sched_ext_ops dispatch_max_batch should be rejected");
        assert!(err.labels.iter().any(|label| {
            label.text.contains("dispatch_max_batch' value")
                || label.text.contains("dispatch_max_batch")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_dispatch_max_batch_above_int_max() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "dispatch_max_batch",
            Value::int(super::SCHED_EXT_MAX_DISPATCH_BATCH + 1, Span::test_data()),
        );

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("dispatch_max_batch above INT_MAX should be rejected");
        assert!(
            err.labels
                .iter()
                .any(|label| { label.text.contains("dispatch_max_batch is too large") })
        );
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_allows_dispatch_max_batch_int_max() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push(
            "dispatch_max_batch",
            Value::int(super::SCHED_EXT_MAX_DISPATCH_BATCH, Span::test_data()),
        );

        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect("sched_ext_ops dispatch_max_batch at INT_MAX should be allowed");
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_negative_exit_dump_len() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("exit_dump_len", Value::int(-1, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("negative sched_ext_ops exit_dump_len should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'exit_dump_len' to be a non-negative integer")
        }));
    }

    #[test]
    fn test_validate_required_struct_ops_value_fields_rejects_negative_hotplug_seq() {
        if KernelBtf::get()
            .kernel_named_type_size_bytes("sched_ext_ops")
            .is_err()
        {
            return;
        }

        let mut body = Record::new();
        body.push("name", Value::string("nu.demo_1", Span::test_data()));
        body.push("hotplug_seq", Value::int(-1, Span::test_data()));

        let err = super::validate_required_struct_ops_value_fields(
            "sched_ext_ops",
            &body,
            Span::test_data(),
        )
        .expect_err("negative sched_ext_ops hotplug_seq should be rejected");
        assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("requires 'hotplug_seq' to be a non-negative integer")
        }));
    }

    #[test]
    fn test_default_struct_ops_object_name_sanitizes_type_name() {
        assert_eq!(
            super::default_struct_ops_object_name("sched_ext_ops"),
            "nu_sched_ext_ops"
        );
        assert_eq!(
            super::default_struct_ops_object_name("weird-type/name"),
            "nu_weird_type_name"
        );
    }

    fn make_ctx_path_program(cell_path: CellPath) -> HirProgram {
        let ctx_var = VarId::new(0);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(cell_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 4],
            ast: vec![None; 4],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn string_member(name: &str) -> PathMember {
        PathMember::test_string(name.to_string(), false, Casing::Sensitive)
    }

    fn make_ctx_path_call_program(cell_path: CellPath, decl_id: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(cell_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 4],
            ast: vec![None; 4],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_map_put_get_projection_program(
        map_put_decl: DeclId,
        map_get_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("arg0"), string_member("f_path")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(5),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(6),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(6),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("dentry"), string_member("d_flags")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::Call {
                            decl_id: count_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 21],
            ast: vec![None; 21],
            comments: vec![],
            register_count: 7,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_map_get_whole_value_program(map_get_decl: DeclId, terminal_decl: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::Call {
                            decl_id: terminal_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 10],
            ast: vec![None; 10],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_map_get_record_emit_program(map_get_decl: DeclId, emit_decl: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadLiteral {
                            dst: RegId::new(0),
                            lit: HirLiteral::Record { capacity: 1 },
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::String(b"path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(2),
                            var_id: lookup_var,
                        },
                        HirStmt::RecordInsert {
                            src_dst: RegId::new(0),
                            key: RegId::new(1),
                            val: RegId::new(2),
                        },
                        HirStmt::Call {
                            decl_id: emit_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    }],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 16],
            ast: vec![None; 16],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_identity_user_function() -> HirFunction {
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(10),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 2],
            ast: vec![None; 2],
            comments: vec![],
            register_count: 1,
            file_count: 0,
        }
    }

    fn make_project_inode_flags_user_function() -> HirFunction {
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: VarId::new(10),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("f_inode"), string_member("i_flags")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 4],
            ast: vec![None; 4],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        }
    }

    fn make_map_get_user_function_emit_program(
        map_get_decl: DeclId,
        user_decl: DeclId,
        emit_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(1),
                            var_id: lookup_var,
                        },
                        HirStmt::Call {
                            decl_id: user_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(1)],
                                ..Default::default()
                            },
                        },
                        HirStmt::Call {
                            decl_id: emit_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    }],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 14],
            ast: vec![None; 14],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_trampoline_user_function_count_program(
        user_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("arg0")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id: user_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            ..Default::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: count_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 6],
            ast: vec![None; 6],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn cached_path_struct_schema() -> HashMap<MapRef, MirType> {
        HashMap::from([(
            MapRef {
                name: "cached_path".to_string(),
                kind: MapKind::Hash,
            },
            MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "mnt".to_string(),
                        ty: MirType::U64,
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "dentry".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::Struct {
                                name: Some("dentry".to_string()),
                                kernel_btf_type_id: None,
                                fields: vec![StructField {
                                    name: "d_flags".to_string(),
                                    ty: MirType::U32,
                                    offset: 0,
                                    synthetic: false,
                                    bitfield: None,
                                }],
                            }),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            },
        )])
    }

    fn make_map_copy_projection_program(
        map_put_decl: DeclId,
        map_get_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let copied_var = VarId::new(2);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("arg0"), string_member("f_path")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(5),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(6),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(6),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(3),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(7),
                            lit: HirLiteral::String(b"copied_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(7), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(7)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: copied_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(8),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(8),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(2),
                        if_false: HirBlockId(3),
                    },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: copied_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("dentry"), string_member("d_flags")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::Call {
                            decl_id: count_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(3),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 30],
            ast: vec![None; 30],
            comments: vec![],
            register_count: 9,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_path_program(binding: CellPath, access: CellPath) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(2),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 7],
            ast: vec![None; 7],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_get_program(
        binding: CellPath,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 9],
            ast: vec![None; 9],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_runtime_get_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let idx_var = VarId::new(2);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 13],
            ast: vec![None; 13],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_runtime_get_then_call_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let idx_var = VarId::new(1);
        let value_var = VarId::new(2);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id: DeclId::new(42),
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: value_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: value_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 14],
            ast: vec![None; 14],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_runtime_get_path_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let idx_var = VarId::new(2);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 15],
            ast: vec![None; 15],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_branch_refined_bound_ctx_get_program(
        scalar_binding: CellPath,
        pointer_binding: CellPath,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let scalar_var = VarId::new(1);
        let idx_var = VarId::new(2);
        let blocks = vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(scalar_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: scalar_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: scalar_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::GreaterThan),
                        rhs: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: scalar_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Subtract),
                        rhs: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(pointer_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(2),
                        path: RegId::new(3),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(2),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(2),
                        path: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(2) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ];
        let func = HirFunction {
            blocks,
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 19],
            ast: vec![None; 19],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    #[test]
    fn test_recover_optimized_type_hints_for_pointer_hop_trampoline_projection() {
        let hir = make_ctx_path_program(CellPath {
            members: vec![
                string_member("arg0"),
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("pointer-hop field projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized pointer-hop field projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_struct_leaf_counter_schema() {
        let hir = make_ctx_path_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("f_path")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("struct-leaf count should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized struct-leaf count should compile");
        assert_eq!(
            result.bytes_counter_key_schema,
            Some(CounterKeySchema::Record {
                name: Some("path".to_string()),
                fields: vec![
                    CounterKeySchemaField {
                        name: "mnt".to_string(),
                        schema: CounterKeySchema::Int {
                            size: 8,
                            signed: false,
                        },
                        offset: 0,
                        bitfield: None,
                    },
                    CounterKeySchemaField {
                        name: "dentry".to_string(),
                        schema: CounterKeySchema::Int {
                            size: 8,
                            signed: false,
                        },
                        offset: 8,
                        bitfield: None,
                    },
                ],
                total_size: 16,
            })
        );
    }

    #[test]
    fn test_compile_optimized_typed_map_get_projection() {
        let hir =
            make_map_put_get_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "map-put".to_string());
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("typed map put/get projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed map get projection should compile");

        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
        assert!(
            result.maps.iter().any(|map| map.name == "cached_path"),
            "expected generic map definition for cached_path"
        );
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_whole_struct_count() {
        let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("whole-value typed map-get count should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized whole-value typed map-get count should compile");
        let schema = result
            .bytes_counter_key_schema
            .expect("whole-value count should preserve a record key schema");
        assert!(matches!(
            schema,
            CounterKeySchema::Record { ref fields, .. }
                if fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[1].name == "dentry"
        ));
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_whole_struct_emit() {
        let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("whole-value typed map-get emit should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized whole-value typed map-get emit should compile");
        let schema = result
            .event_schema
            .expect("whole-value emit should preserve a structured event schema");
        assert!(
            schema
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .eq(["mnt", "dentry"].into_iter()),
            "whole-value emit should preserve top-level record fields"
        );
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_record_emit() {
        let hir = make_map_get_record_emit_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("record emit around typed map-get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized record emit around typed map-get should compile");
        let schema = result
            .event_schema
            .expect("record emit should preserve a structured event schema");
        assert!(matches!(
            schema.fields.as_slice(),
            [crate::compiler::SchemaField {
                name,
                field_type: crate::compiler::BpfFieldType::Bytes(16),
                value_schema: Some(CounterKeySchema::Record { fields, .. }),
                ..
            }] if name == "path"
                && fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
        ));
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_user_function_emit() {
        let hir = make_map_get_user_function_emit_program(
            DeclId::new(43),
            DeclId::new(90),
            DeclId::new(44),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        decl_names.insert(DeclId::new(90), "project-entry".to_string());
        let external_schema = cached_path_struct_schema();
        let user_functions = HashMap::from([(DeclId::new(90), make_identity_user_function())]);

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &user_functions,
            &HashMap::new(),
        )
        .expect("typed map-get through user function should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        for ((subfn, hints), stack_slots) in lowering
            .program
            .subfunctions
            .iter_mut()
            .zip(lowering.type_hints.subfunctions.iter_mut())
            .zip(lowering.type_hints.subfunction_stack_slots.iter())
        {
            optimize_with_ssa_hints(
                subfn,
                Some(&probe_ctx),
                hints,
                stack_slots,
                &lowering.type_hints.generic_map_value_types,
            );
        }

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed map-get through user function should compile");
        let schema = result
            .event_schema
            .expect("user-function emit should preserve a structured event schema");
        assert!(
            schema
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .eq(["mnt", "dentry"].into_iter()),
            "user-function emit should preserve top-level record fields, got {:?}",
            schema
        );
    }

    #[test]
    fn test_compile_optimized_typed_trampoline_user_function_projection() {
        let hir = make_trampoline_user_function_count_program(DeclId::new(90), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(44), "count".to_string());
        decl_names.insert(DeclId::new(90), "project-inode-flags".to_string());
        let user_functions =
            HashMap::from([(DeclId::new(90), make_project_inode_flags_user_function())]);

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            None,
            &user_functions,
            &HashMap::new(),
        )
        .expect("typed trampoline arg through user function should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        for ((subfn, hints), stack_slots) in lowering
            .program
            .subfunctions
            .iter_mut()
            .zip(lowering.type_hints.subfunctions.iter_mut())
            .zip(lowering.type_hints.subfunction_stack_slots.iter())
        {
            optimize_with_ssa_hints(
                subfn,
                Some(&probe_ctx),
                hints,
                stack_slots,
                &lowering.type_hints.generic_map_value_types,
            );
        }

        compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed trampoline projection through user function should compile");
    }

    #[test]
    fn test_compile_optimized_map_to_map_copy_projection() {
        let hir =
            make_map_copy_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "map-put".to_string());
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("map-to-map copy projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized map-to-map copy projection should compile");

        assert!(
            result.maps.iter().any(|map| map.name == "copied_path"),
            "expected generic map definition for copied_path"
        );
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_direct_pointer_index_projection() {
        let hir = make_ctx_path_program(CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
                PathMember::Int {
                    val: 0,
                    span: Span::test_data(),
                    optional: false,
                },
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("direct pointer-index projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized direct pointer-index projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_bound_pointer_index_projection() {
        let hir = make_bound_ctx_path_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("fd"),
                ],
            },
            CellPath {
                members: vec![
                    PathMember::Int {
                        val: 0,
                        span: Span::test_data(),
                        optional: false,
                    },
                    string_member("f_inode"),
                    string_member("i_ino"),
                ],
            },
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("bound pointer-index projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized bound pointer-index projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_bound_numeric_get_projection() {
        let hir = make_bound_ctx_get_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("fd"),
                ],
            },
            CellPath {
                members: vec![string_member("f_inode"), string_member("i_ino")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("bound numeric get projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized bound numeric get projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_branch_refined_bound_numeric_get_projection() {
        let hir = make_branch_refined_bound_ctx_get_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("max_fds"),
                ],
            },
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("fd"),
                ],
            },
            CellPath {
                members: vec![string_member("f_inode"), string_member("i_ino")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("branch-refined bound numeric get projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized branch-refined bound numeric get projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_array_numeric_get() {
        let hir = make_bound_ctx_runtime_get_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("comm")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed array numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed array numeric get should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_projection_after_numeric_get() {
        let hir = make_bound_ctx_runtime_get_path_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            CellPath {
                members: vec![string_member("bucket_id")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed bitfield projection after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield projection after numeric get should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_count_after_numeric_get()
    {
        let hir = make_bound_ctx_runtime_get_then_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(43),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());
        decl_names.insert(DeclId::new(43), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed bitfield struct count after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield struct count should compile");
        assert!(
            matches!(
                result.bytes_counter_key_schema,
                Some(CounterKeySchema::Record { .. })
            ),
            "bitfield struct count should preserve a record schema"
        );
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_emit_after_numeric_get() {
        let hir = make_bound_ctx_runtime_get_then_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(43),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());
        decl_names.insert(DeclId::new(43), "emit".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed bitfield struct emit after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield struct emit should compile");
        let schema = result
            .event_schema
            .expect("single-value emit should preserve a schema");
        assert!(
            schema.fields.iter().map(|field| field.name.as_str()).eq([
                "value",
                "bucket_id",
                "active",
                "user_defined"
            ]
            .into_iter()),
            "bitfield struct emit should preserve top-level record fields"
        );
        assert!(
            schema.fields[0].bitfield.is_some() && schema.fields[1].bitfield.is_some(),
            "bitfield struct emit should preserve bitfield metadata"
        );
    }
}
