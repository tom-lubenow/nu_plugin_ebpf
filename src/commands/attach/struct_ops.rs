use super::*;

pub(super) fn struct_ops_value_field_from_value(
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

pub(super) fn apply_struct_ops_value_field(
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
pub(super) enum StructOpsTopLevelFieldKind {
    Callback,
    Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StructOpsFamily {
    Generic,
    SchedExt,
    TcpCongestion,
}

impl StructOpsFamily {
    fn from_value_type_name(value_type_name: &str) -> Self {
        match value_type_name {
            "sched_ext_ops" => Self::SchedExt,
            "tcp_congestion_ops" => Self::TcpCongestion,
            _ => Self::Generic,
        }
    }

    fn live_attach_risk(self) -> Option<&'static str> {
        match self {
            Self::SchedExt => Some(
                "live sched_ext registration can disrupt host scheduling; prefer --dry-run on the host and use a VM or disposable environment for real loads",
            ),
            Self::Generic | Self::TcpCongestion => None,
        }
    }

    fn required_callbacks(self) -> &'static [&'static str] {
        match self {
            Self::TcpCongestion => &["ssthresh", "cong_avoid", "undo_cwnd"],
            Self::Generic | Self::SchedExt => &[],
        }
    }

    fn missing_callbacks_help(self) -> &'static str {
        match self {
            Self::TcpCongestion => {
                "tcp_congestion_ops requires closure members for ssthresh, cong_avoid, and undo_cwnd, for example { ssthresh: {|ctx| 2 }, undo_cwnd: {|ctx| 2 }, cong_avoid: {|ctx| 0 } }"
            }
            Self::Generic | Self::SchedExt => {
                "Provide closures for the required struct_ops callback members"
            }
        }
    }
}

fn struct_ops_live_attach_risk(value_type_name: &str) -> Option<&'static str> {
    StructOpsFamily::from_value_type_name(value_type_name).live_attach_risk()
}

pub(super) fn validate_struct_ops_attach_safety(
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

pub(super) fn validate_struct_ops_top_level_field_kind(
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

pub(super) fn validate_required_struct_ops_callbacks(
    value_type_name: &str,
    callback_fields: &HashSet<String>,
    span: Span,
) -> Result<(), LabeledError> {
    let family = StructOpsFamily::from_value_type_name(value_type_name);
    let missing: Vec<&'static str> = family
        .required_callbacks()
        .iter()
        .copied()
        .filter(|field_name| !callback_fields.contains(*field_name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    Err(LabeledError::new("Invalid struct_ops object")
        .with_label(
            format!(
                "struct_ops '{}' is missing required callback closure(s): {}",
                value_type_name,
                missing.join(", ")
            ),
            span,
        )
        .with_help(family.missing_callbacks_help()))
}

pub(super) fn resolve_struct_ops_char_array_field_capacity(
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

pub(super) fn resolve_sched_ext_allowed_flags_mask(span: Span) -> Result<u64, LabeledError> {
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

pub(super) fn resolve_sched_ext_flag_bit(flag_name: &str, span: Span) -> Result<u64, LabeledError> {
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

pub(super) const SCHED_EXT_MAX_TIMEOUT_MS: i64 = 30_000;
pub(super) const SCHED_EXT_MAX_DISPATCH_BATCH: i64 = i32::MAX as i64;

pub(super) fn validate_required_struct_ops_value_fields(
    value_type_name: &str,
    body: &Record,
    span: Span,
) -> Result<(), LabeledError> {
    match StructOpsFamily::from_value_type_name(value_type_name) {
        StructOpsFamily::TcpCongestion => {
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
        StructOpsFamily::SchedExt => {
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
        StructOpsFamily::Generic => Ok(()),
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

pub(super) fn validate_struct_ops_callback_kfunc_requirements(
    value_type_name: &str,
    body: &Record,
    callback_kfuncs: &HashMap<String, HashSet<String>>,
    span: Span,
) -> Result<(), LabeledError> {
    match StructOpsFamily::from_value_type_name(value_type_name) {
        StructOpsFamily::SchedExt => {
            validate_sched_ext_callback_kfunc_requirements(body, callback_kfuncs, span)
        }
        StructOpsFamily::Generic | StructOpsFamily::TcpCongestion => Ok(()),
    }
}

pub(super) fn sanitize_struct_ops_component(component: &str) -> String {
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

pub(super) fn default_struct_ops_object_name(value_type_name: &str) -> String {
    format!("nu_{}", sanitize_struct_ops_component(value_type_name))
}
