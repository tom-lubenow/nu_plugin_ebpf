use super::*;
use crate::compiler::mir::BpfGraphRootKind;

const MAX_NAMED_GLOBAL_NUMERIC_LIST_CAPACITY: usize = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NamedTypeSpecContext {
    Global,
    MapKey,
    MapValue,
    GraphObjectPayload,
}

impl NamedTypeSpecContext {
    fn diagnostic_name(self) -> &'static str {
        match self {
            NamedTypeSpecContext::Global => "global",
            NamedTypeSpecContext::MapKey => "map key",
            NamedTypeSpecContext::MapValue => "map value",
            NamedTypeSpecContext::GraphObjectPayload => "graph object payload",
        }
    }
}

#[derive(Clone, Debug)]
struct ParsedNamedGlobalType {
    ty: MirType,
    list_max_len: Option<usize>,
    string_slot_len: Option<usize>,
    string_content_cap: Option<usize>,
    semantics: Option<AnnotatedValueSemantics>,
    shape: NamedGlobalTypeShape,
}

#[derive(Clone, Debug)]
struct ParsedNamedRecordField {
    name: String,
    offset: usize,
    ty: ParsedNamedGlobalType,
}

#[derive(Clone, Debug)]
struct ParsedGraphRootTypeSpec {
    kind: BpfGraphRootKind,
    value_type: String,
    node_field: String,
    object_ty: Option<MirType>,
}

#[derive(Clone, Debug)]
enum NamedGlobalTypeShape {
    I8,
    I16,
    I32,
    I64,
    Duration,
    Filesize,
    U8,
    U16,
    U32,
    U64,
    Bool,
    Bytes {
        len: usize,
    },
    String {
        content_cap: usize,
        slot_len: usize,
    },
    NumericList {
        max_len: usize,
    },
    BpfTimer,
    BpfSpinLock,
    BpfWq,
    BpfRefcount,
    BpfKptr {
        pointee_name: String,
    },
    BpfGraphRoot {
        kind: BpfGraphRootKind,
        value_type: String,
        node_field: String,
    },
    FixedArray {
        elem: Box<ParsedNamedGlobalType>,
        len: usize,
    },
    Record(Vec<ParsedNamedRecordField>),
}

const NAMED_TYPE_PADDING_FIELD_PREFIX: &str = "__layout_pad";

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        value.saturating_add(align - 1) & !(align - 1)
    }
}

fn named_type_padding_field(offset: usize, size: usize, pad_index: usize) -> Option<StructField> {
    (size > 0).then(|| StructField {
        name: format!("{NAMED_TYPE_PADDING_FIELD_PREFIX}{pad_index}"),
        ty: MirType::Array {
            elem: Box::new(MirType::U8),
            len: size,
        },
        offset,
        synthetic: true,
        bitfield: None,
    })
}

fn split_top_level_fields<'a>(
    body: &'a str,
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> Result<Vec<&'a str>, CompileError> {
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (idx, ch) in body.char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                if depth == 0 {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} has an unmatched '}}'",
                        subject
                    )));
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                fields.push(body[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        let subject = type_spec_subject(spec, context, record_path);
        return Err(CompileError::UnsupportedInstruction(format!(
            "{} has unmatched '{{' braces",
            subject
        )));
    }

    fields.push(body[start..].trim());
    Ok(fields)
}

fn record_field_path(parent_path: Option<&str>, field: &str) -> String {
    match (parent_path, field.trim()) {
        (Some(parent), field) if !field.is_empty() => format!("{parent}.{field}"),
        (Some(parent), _) => parent.to_string(),
        (None, field) => field.to_string(),
    }
}

fn type_spec_subject(
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> String {
    match record_path {
        Some(path) => format!("record field '{path}' type spec '{spec}'"),
        None => format!("{} type spec '{spec}'", context.diagnostic_name()),
    }
}

fn array_type_spec_subject(
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> String {
    match record_path {
        Some(path) => format!("record field '{path}' array type spec '{spec}'"),
        None => format!("array {} type spec '{spec}'", context.diagnostic_name()),
    }
}

fn validate_type_spec_candidate_braces(
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> Result<(), CompileError> {
    if !(spec.starts_with("record{") || spec.starts_with("array{")) {
        return Ok(());
    }

    let mut depth = 0usize;
    for ch in spec.chars() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                if depth == 0 {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} has an unmatched '}}'",
                        subject
                    )));
                }
                depth -= 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        let subject = type_spec_subject(spec, context, record_path);
        return Err(CompileError::UnsupportedInstruction(format!(
            "{} has unmatched '{{' braces",
            subject
        )));
    }

    Ok(())
}

fn split_top_level_field<'a>(
    field: &'a str,
    parent_path: Option<&str>,
) -> Result<(&'a str, &'a str), CompileError> {
    let mut depth = 0usize;

    for (idx, ch) in field.char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                if depth == 0 {
                    let field_path = record_field_path(parent_path, field);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{}' has an unmatched '}}'",
                        field_path
                    )));
                }
                depth -= 1;
            }
            ':' if depth == 0 => {
                let (name, rest) = field.split_at(idx);
                return Ok((name.trim(), rest[1..].trim()));
            }
            _ => {}
        }
    }

    let field_path = record_field_path(parent_path, field);
    Err(CompileError::UnsupportedInstruction(format!(
        "record field '{}' must use name:type syntax",
        field_path
    )))
}

fn split_top_level_type_len<'a>(
    body: &'a str,
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> Result<(&'a str, &'a str), CompileError> {
    let mut depth = 0usize;
    let mut separator = None;

    for (idx, ch) in body.char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                if depth == 0 {
                    let subject = array_type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} has an unmatched '}}'",
                        subject
                    )));
                }
                depth -= 1;
            }
            ':' if depth == 0 => {
                separator = Some(idx);
            }
            _ => {}
        }
    }

    if let Some(idx) = separator {
        let (elem, rest) = body.split_at(idx);
        return Ok((elem.trim(), rest[1..].trim()));
    }

    let subject = array_type_spec_subject(spec, context, record_path);
    Err(CompileError::UnsupportedInstruction(format!(
        "{} must use array{{type:N}} syntax",
        subject
    )))
}

fn split_top_level_colon_parts<'a>(
    body: &'a str,
    spec: &str,
    context: NamedTypeSpecContext,
    record_path: Option<&str>,
) -> Result<Vec<&'a str>, CompileError> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (idx, ch) in body.char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                if depth == 0 {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} has an unmatched '}}'",
                        subject
                    )));
                }
                depth -= 1;
            }
            ':' if depth == 0 => {
                parts.push(body[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        let subject = type_spec_subject(spec, context, record_path);
        return Err(CompileError::UnsupportedInstruction(format!(
            "{} has unmatched '{{' braces",
            subject
        )));
    }

    parts.push(body[start..].trim());
    Ok(parts)
}

fn named_global_numeric_constant_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Int { val, .. } => Some(*val),
        Value::Filesize { val, .. } => Some(val.get()),
        Value::Duration { val, .. } => Some(*val),
        Value::Nothing { .. } => Some(0),
        _ => None,
    }
}

fn named_global_constant_kind(value: &Value) -> &'static str {
    match value {
        Value::Bool { .. } => "bool",
        Value::Int { .. } => "int",
        Value::Float { .. } => "float",
        Value::Filesize { .. } => "filesize",
        Value::Duration { .. } => "duration",
        Value::String { .. } => "string",
        Value::Glob { .. } => "glob",
        Value::Binary { .. } => "binary",
        Value::List { .. } => "list",
        Value::Record { .. } => "record",
        Value::Nothing { .. } => "nothing",
        _ => "unsupported value",
    }
}

impl ParsedNamedGlobalType {
    fn is_fixed_array_element_type(&self) -> bool {
        matches!(
            &self.shape,
            NamedGlobalTypeShape::I8
                | NamedGlobalTypeShape::I16
                | NamedGlobalTypeShape::I32
                | NamedGlobalTypeShape::I64
                | NamedGlobalTypeShape::Duration
                | NamedGlobalTypeShape::Filesize
                | NamedGlobalTypeShape::U8
                | NamedGlobalTypeShape::U16
                | NamedGlobalTypeShape::U32
                | NamedGlobalTypeShape::U64
                | NamedGlobalTypeShape::Bool
                | NamedGlobalTypeShape::Bytes { .. }
                | NamedGlobalTypeShape::String { .. }
                | NamedGlobalTypeShape::NumericList { .. }
                | NamedGlobalTypeShape::BpfTimer
                | NamedGlobalTypeShape::BpfSpinLock
                | NamedGlobalTypeShape::BpfWq
                | NamedGlobalTypeShape::BpfRefcount
                | NamedGlobalTypeShape::FixedArray { .. }
                | NamedGlobalTypeShape::Record(_)
        )
    }

    fn parse(spec: &str) -> Result<Self, CompileError> {
        Self::parse_with_context(spec, NamedTypeSpecContext::Global)
    }

    fn parse_with_context(spec: &str, context: NamedTypeSpecContext) -> Result<Self, CompileError> {
        Self::parse_with_context_at_path(spec, context, None)
    }

    fn parse_with_context_at_path(
        spec: &str,
        context: NamedTypeSpecContext,
        record_path: Option<&str>,
    ) -> Result<Self, CompileError> {
        validate_type_spec_candidate_braces(spec, context, record_path)?;

        let scalar_shape = match spec {
            "i8" => Some((MirType::I8, NamedGlobalTypeShape::I8)),
            "i16" => Some((MirType::I16, NamedGlobalTypeShape::I16)),
            "i32" => Some((MirType::I32, NamedGlobalTypeShape::I32)),
            "i64" | "int" => Some((MirType::I64, NamedGlobalTypeShape::I64)),
            "duration" => Some((MirType::I64, NamedGlobalTypeShape::Duration)),
            "filesize" => Some((MirType::I64, NamedGlobalTypeShape::Filesize)),
            "u8" => Some((MirType::U8, NamedGlobalTypeShape::U8)),
            "u16" => Some((MirType::U16, NamedGlobalTypeShape::U16)),
            "u32" => Some((MirType::U32, NamedGlobalTypeShape::U32)),
            "u64" => Some((MirType::U64, NamedGlobalTypeShape::U64)),
            "bool" => Some((MirType::Bool, NamedGlobalTypeShape::Bool)),
            _ => None,
        };

        if let Some((ty, shape)) = scalar_shape {
            return Ok(Self {
                ty,
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape,
            });
        }

        if context == NamedTypeSpecContext::MapValue && spec == "bpf_timer" {
            return Ok(Self {
                ty: MirType::bpf_timer_struct(),
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfTimer,
            });
        }

        if context == NamedTypeSpecContext::MapValue && spec == "bpf_spin_lock" {
            return Ok(Self {
                ty: MirType::bpf_spin_lock_struct(),
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfSpinLock,
            });
        }

        if context == NamedTypeSpecContext::MapValue && spec == "bpf_wq" {
            return Ok(Self {
                ty: MirType::bpf_wq_struct(),
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfWq,
            });
        }

        if matches!(
            context,
            NamedTypeSpecContext::MapValue | NamedTypeSpecContext::GraphObjectPayload
        ) && spec == "bpf_refcount"
        {
            return Ok(Self {
                ty: MirType::bpf_refcount_struct(),
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfRefcount,
            });
        }

        if context == NamedTypeSpecContext::MapValue
            && let Some(root) = Self::parse_graph_root_type_spec(spec, context, record_path)?
        {
            let ty = match (root.kind, root.object_ty.clone()) {
                (BpfGraphRootKind::ListHead, Some(object_ty)) => {
                    MirType::bpf_list_head_root_struct_with_object(
                        &root.value_type,
                        &root.node_field,
                        object_ty,
                    )
                }
                (BpfGraphRootKind::RbRoot, Some(object_ty)) => {
                    MirType::bpf_rb_root_struct_with_object(
                        &root.value_type,
                        &root.node_field,
                        object_ty,
                    )
                }
                (BpfGraphRootKind::ListHead, None) => {
                    MirType::bpf_list_head_root_struct(&root.value_type, &root.node_field)
                }
                (BpfGraphRootKind::RbRoot, None) => {
                    MirType::bpf_rb_root_struct_with_contains(&root.value_type, &root.node_field)
                }
            };
            return Ok(Self {
                ty,
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfGraphRoot {
                    kind: root.kind,
                    value_type: root.value_type,
                    node_field: root.node_field,
                },
            });
        }

        if context == NamedTypeSpecContext::MapValue && Self::is_dynptr_type_spec_candidate(spec) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value dynptr type spec '{}' is not supported; bpf_dynptr objects are stack-only verifier state for dynptr helpers and cannot be embedded in map-value schemas",
                spec
            )));
        }

        if context == NamedTypeSpecContext::MapValue
            && Self::is_graph_object_type_spec_candidate(spec)
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph type spec '{}' is not supported yet; bpf_list_head/bpf_rb_root roots require a named object type schema so the compiler can emit BTF contains:TYPE:FIELD declaration tags with matching bpf_list_node/bpf_rb_node object fields",
                spec
            )));
        }

        if context == NamedTypeSpecContext::MapValue
            && let Some(pointee_name) = spec.strip_prefix("kptr:")
        {
            if !Self::is_valid_kernel_type_name(pointee_name) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map value kptr type spec '{}' requires a kernel struct type name like kptr:task_struct",
                    spec
                )));
            }
            return Ok(Self {
                ty: MirType::bpf_kptr_slot_struct(pointee_name),
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: None,
                shape: NamedGlobalTypeShape::BpfKptr {
                    pointee_name: pointee_name.to_string(),
                },
            });
        }

        if let Some(body) = spec
            .strip_prefix("record{")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            if body.trim().is_empty() {
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires at least one record field"
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(
                    "record global declarations require at least one field".into(),
                ));
            }

            let mut fields = Vec::new();
            let mut field_specs = Vec::new();
            let mut field_semantics = Vec::new();
            let mut offset = 0usize;
            let mut struct_align = 1usize;
            let mut pad_index = 0usize;

            for field in split_top_level_fields(body, spec, context, record_path)? {
                if field.is_empty() {
                    if context != NamedTypeSpecContext::Global {
                        let subject = type_spec_subject(spec, context, record_path);
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{subject} contains an empty record field"
                        )));
                    }
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global record type spec '{}' contains an empty field",
                        spec
                    )));
                }

                let (name, field_spec) = split_top_level_field(field, record_path)?;
                if name.is_empty() || field_spec.is_empty() {
                    let invalid_field = if name.is_empty() { field } else { name };
                    let field_path = record_field_path(record_path, invalid_field);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{}' must use name:type syntax",
                        field_path
                    )));
                }
                if name.starts_with(NAMED_TYPE_PADDING_FIELD_PREFIX) {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record type specs reserve field names starting with '{}'",
                        NAMED_TYPE_PADDING_FIELD_PREFIX
                    )));
                }

                if fields
                    .iter()
                    .any(|existing: &StructField| existing.name == name)
                {
                    if context != NamedTypeSpecContext::Global {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "record type spec '{}' does not support duplicate field name '{}'",
                            spec, name
                        )));
                    }
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record global declarations do not support duplicate field name '{}'",
                        name
                    )));
                }

                let field_path = record_field_path(record_path, name);
                let parsed_field =
                    Self::parse_with_context_at_path(field_spec, context, Some(&field_path))?;
                if let Some(semantics) = parsed_field.semantics.clone() {
                    field_semantics.push((name.to_string(), semantics));
                }
                let ty = parsed_field.ty.clone();
                let field_align = ty.align().max(1);
                let aligned_offset = align_up(offset, field_align);
                if let Some(padding) = named_type_padding_field(
                    offset,
                    aligned_offset.saturating_sub(offset),
                    pad_index,
                ) {
                    fields.push(padding);
                    pad_index += 1;
                }
                fields.push(StructField {
                    name: name.to_string(),
                    ty: ty.clone(),
                    offset: aligned_offset,
                    synthetic: false,
                    bitfield: None,
                });
                field_specs.push(ParsedNamedRecordField {
                    name: name.to_string(),
                    offset: aligned_offset,
                    ty: parsed_field,
                });
                offset = aligned_offset.saturating_add(ty.size());
                struct_align = struct_align.max(field_align);
            }

            let final_size = align_up(offset, struct_align);
            if let Some(padding) =
                named_type_padding_field(offset, final_size.saturating_sub(offset), pad_index)
            {
                fields.push(padding);
            }

            return Ok(Self {
                ty: MirType::Struct {
                    name: None,
                    kernel_btf_type_id: None,
                    fields,
                },
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: (!field_semantics.is_empty())
                    .then_some(AnnotatedValueSemantics::Record(field_semantics)),
                shape: NamedGlobalTypeShape::Record(field_specs),
            });
        }

        if let Some(body) = spec
            .strip_prefix("array{")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            let (elem_spec, len_spec) = split_top_level_type_len(body, spec, context, record_path)?;
            if elem_spec.is_empty() || len_spec.is_empty() {
                let subject = array_type_spec_subject(spec, context, record_path);
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{} must use array{{type:N}} syntax",
                    subject
                )));
            }

            let len = len_spec.parse::<usize>().map_err(|_| {
                let subject = type_spec_subject(spec, context, record_path);
                CompileError::UnsupportedInstruction(format!(
                    "{subject} has an invalid array length"
                ))
            })?;
            if len == 0 {
                if let Some(path) = record_path {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{path}' type spec '{spec}' requires a positive fixed-array length"
                    )));
                }
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires a positive fixed-array length"
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(
                    "global fixed-array declarations require a positive length".into(),
                ));
            }

            let parsed_elem = Self::parse_with_context_at_path(elem_spec, context, record_path)?;
            if !parsed_elem.is_fixed_array_element_type() {
                if let Some(path) = record_path {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{path}' fixed-array type spec '{spec}' requires elements that can be embedded in fixed arrays, got '{}'",
                        elem_spec
                    )));
                }
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires elements that can be embedded in fixed arrays, got '{}'",
                        elem_spec
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global fixed-array declarations require elements that can be embedded in fixed arrays, got '{}'",
                    elem_spec
                )));
            }
            let elem_ty = parsed_elem.ty.clone();
            let elem_semantics = parsed_elem.semantics.clone();
            return Ok(Self {
                ty: MirType::Array {
                    elem: Box::new(elem_ty),
                    len,
                },
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: elem_semantics.map(|elem| AnnotatedValueSemantics::FixedArray {
                    elem: Box::new(elem),
                    len,
                }),
                shape: NamedGlobalTypeShape::FixedArray {
                    elem: Box::new(parsed_elem),
                    len,
                },
            });
        }

        let byte_len = spec
            .strip_prefix("bytes:")
            .or_else(|| spec.strip_prefix("binary:"))
            .map(|len| {
                len.parse::<usize>().map_err(|_| {
                    let subject = type_spec_subject(spec, context, record_path);
                    CompileError::UnsupportedInstruction(format!(
                        "{subject} has an invalid byte length"
                    ))
                })
            })
            .transpose()?;

        if let Some(len) = byte_len {
            if len == 0 {
                if let Some(path) = record_path {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{path}' type spec '{spec}' requires a positive byte-array length"
                    )));
                }
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires a positive byte-array length"
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(
                    "global byte-array declarations require a positive length".into(),
                ));
            }

            return Ok(Self {
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len,
                },
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
                semantics: Some(AnnotatedValueSemantics::Binary { len }),
                shape: NamedGlobalTypeShape::Bytes { len },
            });
        }

        if let Some(content_cap) = spec
            .strip_prefix("string:")
            .map(|len| {
                len.parse::<usize>().map_err(|_| {
                    let subject = type_spec_subject(spec, context, record_path);
                    CompileError::UnsupportedInstruction(format!(
                        "{subject} has an invalid string capacity"
                    ))
                })
            })
            .transpose()?
        {
            if content_cap == 0 || content_cap >= MAX_STRING_SIZE {
                if let Some(path) = record_path {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{path}' type spec '{spec}' requires a string capacity between 1 and {}",
                        MAX_STRING_SIZE - 1
                    )));
                }
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires a string capacity between 1 and {}",
                        MAX_STRING_SIZE - 1
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global string declarations require a capacity between 1 and {}",
                    MAX_STRING_SIZE - 1
                )));
            }

            let slot_len = align_to_eight(content_cap.saturating_add(1))
                .min(MAX_STRING_SIZE)
                .max(16);
            return Ok(Self {
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 8 + slot_len,
                },
                list_max_len: None,
                string_slot_len: Some(slot_len),
                string_content_cap: Some(content_cap),
                semantics: Some(AnnotatedValueSemantics::String {
                    slot_len,
                    content_cap,
                }),
                shape: NamedGlobalTypeShape::String {
                    content_cap,
                    slot_len,
                },
            });
        }

        if let Some(max_len) = spec
            .strip_prefix("list:int:")
            .or_else(|| spec.strip_prefix("list:i64:"))
            .map(|len| {
                len.parse::<usize>().map_err(|_| {
                    let subject = type_spec_subject(spec, context, record_path);
                    CompileError::UnsupportedInstruction(format!(
                        "{subject} has an invalid list capacity"
                    ))
                })
            })
            .transpose()?
        {
            if max_len > MAX_NAMED_GLOBAL_NUMERIC_LIST_CAPACITY {
                if let Some(path) = record_path {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "record field '{path}' type spec '{spec}' requires a numeric list capacity of at most {}",
                        MAX_NAMED_GLOBAL_NUMERIC_LIST_CAPACITY
                    )));
                }
                if context != NamedTypeSpecContext::Global {
                    let subject = type_spec_subject(spec, context, record_path);
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{subject} requires a numeric list capacity of at most {}",
                        MAX_NAMED_GLOBAL_NUMERIC_LIST_CAPACITY
                    )));
                }
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global numeric list declarations require a capacity of at most {}",
                    MAX_NAMED_GLOBAL_NUMERIC_LIST_CAPACITY
                )));
            }

            return Ok(Self {
                ty: MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: max_len.saturating_add(1),
                },
                list_max_len: Some(max_len),
                string_slot_len: None,
                string_content_cap: None,
                semantics: Some(AnnotatedValueSemantics::NumericList {
                    max_len,
                    known_len: None,
                }),
                shape: NamedGlobalTypeShape::NumericList { max_len },
            });
        }

        let map_suffix = if context == NamedTypeSpecContext::MapValue {
            "; map value schemas also support bpf_timer, bpf_spin_lock, bpf_wq, bpf_refcount, kptr:TYPE, bpf_list_head:TYPE:FIELD[:record{...}], and bpf_rb_root:TYPE:FIELD[:record{...}]"
        } else if context == NamedTypeSpecContext::GraphObjectPayload {
            "; graph object payload schemas also support bpf_refcount"
        } else {
            ""
        };
        let subject = record_path
            .map(|path| format!("record field '{path}' type spec '{spec}'"))
            .unwrap_or_else(|| format!("{} type spec '{spec}'", context.diagnostic_name()));
        Err(CompileError::UnsupportedInstruction(format!(
            "unsupported {subject}; expected one of i8, i16, i32, int/i64, duration, filesize, u8, u16, u32, u64, bool, bytes:N, binary:N, string:N, list:int:N/list:i64:N, array{{type:N}}, or nested record{{field:type,...}}{}",
            map_suffix
        )))
    }

    fn is_valid_kernel_type_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first == '_' || first.is_ascii_alphabetic()) {
            return false;
        }
        chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    }

    fn parse_graph_root_type_spec(
        spec: &str,
        context: NamedTypeSpecContext,
        record_path: Option<&str>,
    ) -> Result<Option<ParsedGraphRootTypeSpec>, CompileError> {
        let Some((kind, rest)) = spec
            .strip_prefix("bpf_list_head:")
            .map(|rest| (BpfGraphRootKind::ListHead, rest))
            .or_else(|| {
                spec.strip_prefix("bpf_rb_root:")
                    .map(|rest| (BpfGraphRootKind::RbRoot, rest))
            })
        else {
            return Ok(None);
        };

        let parts = split_top_level_colon_parts(rest, spec, context, record_path)?;
        if parts.len() < 2 || parts.len() > 3 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph root type spec '{}' must use {}:TYPE:FIELD or {}:TYPE:FIELD:record{{...}} syntax",
                spec,
                kind.root_struct_name(),
                kind.root_struct_name()
            )));
        }
        let value_type = parts[0];
        let node_field = parts[1];
        if !Self::is_valid_kernel_type_name(value_type) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph root type spec '{}' requires a named object type like {}:node_data:node",
                spec,
                kind.root_struct_name()
            )));
        }
        if !Self::is_valid_kernel_type_name(node_field) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph root type spec '{}' requires a valid node field name like {}:node_data:node",
                spec,
                kind.root_struct_name()
            )));
        }

        let object_ty = if let Some(payload_spec) = parts.get(2) {
            if payload_spec.is_empty() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map value graph root type spec '{}' has an empty object payload schema",
                    spec
                )));
            }
            let payload = Self::parse_with_context_at_path(
                payload_spec,
                NamedTypeSpecContext::GraphObjectPayload,
                record_path,
            )?;
            Some(Self::graph_object_type_from_payload(
                kind, value_type, node_field, payload.ty, spec,
            )?)
        } else {
            None
        };

        Ok(Some(ParsedGraphRootTypeSpec {
            kind,
            value_type: value_type.to_string(),
            node_field: node_field.to_string(),
            object_ty,
        }))
    }

    fn graph_node_type(kind: BpfGraphRootKind) -> MirType {
        match kind {
            BpfGraphRootKind::ListHead => MirType::bpf_list_node_struct(),
            BpfGraphRootKind::RbRoot => MirType::bpf_rb_node_struct(),
        }
    }

    fn graph_object_type_from_payload(
        kind: BpfGraphRootKind,
        value_type: &str,
        node_field: &str,
        payload_ty: MirType,
        spec: &str,
    ) -> Result<MirType, CompileError> {
        let MirType::Struct {
            fields: payload_fields,
            ..
        } = payload_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph root type spec '{}' requires the object payload schema to be record{{...}}",
                spec
            )));
        };
        if payload_fields
            .iter()
            .any(|field| !field.synthetic && field.name == node_field)
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map value graph root type spec '{}' object payload duplicates node field '{}'",
                spec, node_field
            )));
        }

        let node_ty = Self::graph_node_type(kind);
        let node_size = node_ty.size();
        let payload_size = payload_fields
            .iter()
            .filter_map(|field| field.offset.checked_add(field.ty.size()))
            .max()
            .unwrap_or(0);
        let payload_align = payload_fields
            .iter()
            .map(|field| field.ty.align())
            .max()
            .unwrap_or(1)
            .max(1);
        let object_align = node_ty.align().max(payload_align).max(1);
        let payload_base = align_up(node_size, payload_align);
        let mut fields = vec![StructField {
            name: node_field.to_string(),
            ty: node_ty,
            offset: 0,
            synthetic: false,
            bitfield: None,
        }];
        let mut pad_index = 0usize;
        if let Some(padding) =
            named_type_padding_field(node_size, payload_base.saturating_sub(node_size), pad_index)
        {
            fields.push(padding);
            pad_index += 1;
        }
        fields.extend(payload_fields.into_iter().map(|mut field| {
            field.offset = payload_base.saturating_add(field.offset);
            field
        }));
        let final_size = align_up(payload_base.saturating_add(payload_size), object_align);
        if let Some(padding) = named_type_padding_field(
            payload_base.saturating_add(payload_size),
            final_size.saturating_sub(payload_base.saturating_add(payload_size)),
            pad_index,
        ) {
            fields.push(padding);
        }

        Ok(MirType::Struct {
            name: Some(value_type.to_string()),
            kernel_btf_type_id: None,
            fields,
        })
    }

    fn is_graph_object_type_spec_candidate(spec: &str) -> bool {
        matches!(
            spec,
            "bpf_list_head" | "bpf_rb_root" | "bpf_list_node" | "bpf_rb_node"
        ) || spec.starts_with("bpf_list_head:")
            || spec.starts_with("bpf_rb_root:")
    }

    fn is_dynptr_type_spec_candidate(spec: &str) -> bool {
        matches!(spec, "bpf_dynptr" | "bpf_dynptr_kern")
    }

    fn layout(&self, symbol: String) -> (MutableCaptureGlobal, Option<AnnotatedValueSemantics>) {
        (
            MutableCaptureGlobal {
                symbol,
                ty: self.ty.clone(),
                list_max_len: self.list_max_len,
                string_slot_len: self.string_slot_len,
                string_content_cap: self.string_content_cap,
            },
            self.semantics.clone(),
        )
    }

    fn initializer_bytes(&self, value: &Value, spec: &str) -> Result<Vec<u8>, CompileError> {
        self.initializer_bytes_with_path(value, spec, None)
    }

    fn zero_initializer_semantics(&self) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        match &self.shape {
            NamedGlobalTypeShape::NumericList { max_len } => {
                Ok(Some(AnnotatedValueSemantics::NumericList {
                    max_len: *max_len,
                    known_len: Some(0),
                }))
            }
            NamedGlobalTypeShape::FixedArray { elem, len } => Ok(elem
                .zero_initializer_semantics()?
                .map(|elem_semantics| AnnotatedValueSemantics::FixedArray {
                    elem: Box::new(elem_semantics),
                    len: *len,
                })),
            NamedGlobalTypeShape::Record(fields) => {
                let mut field_semantics = Vec::new();
                for field in fields {
                    if let Some(semantics) = field.ty.zero_initializer_semantics()? {
                        field_semantics.push((field.name.clone(), semantics));
                    }
                }
                if field_semantics.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(AnnotatedValueSemantics::Record(field_semantics)))
                }
            }
            _ => Ok(self.semantics.clone()),
        }
    }

    fn initializer_semantics(
        &self,
        value: Option<&Value>,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        let Some(value) = value else {
            return self.zero_initializer_semantics();
        };
        if matches!(value, Value::Nothing { .. }) {
            return self.zero_initializer_semantics();
        }

        match &self.shape {
            NamedGlobalTypeShape::NumericList { max_len } => {
                let Value::List { vals, .. } = value else {
                    return Ok(self.semantics.clone());
                };
                Ok(Some(AnnotatedValueSemantics::NumericList {
                    max_len: *max_len,
                    known_len: Some(vals.len()),
                }))
            }
            NamedGlobalTypeShape::FixedArray { elem, len } => {
                let Value::List { vals, .. } = value else {
                    return Ok(self.semantics.clone());
                };
                let mut elem_semantics = None;
                for idx in 0..*len {
                    let item_semantics = elem.initializer_semantics(vals.get(idx))?;
                    match (&elem_semantics, item_semantics) {
                        (None, Some(semantics)) => elem_semantics = Some(semantics),
                        (Some(existing), Some(semantics)) if existing == &semantics => {}
                        (Some(_), Some(_)) => return Ok(self.semantics.clone()),
                        (_, None) => return Ok(None),
                    }
                }
                Ok(
                    elem_semantics.map(|elem_semantics| AnnotatedValueSemantics::FixedArray {
                        elem: Box::new(elem_semantics),
                        len: *len,
                    }),
                )
            }
            NamedGlobalTypeShape::Record(fields) => {
                let Value::Record { val, .. } = value else {
                    return Ok(self.semantics.clone());
                };
                let mut field_semantics = Vec::new();
                for field in fields {
                    if let Some(semantics) = field.ty.initializer_semantics(val.get(&field.name))? {
                        field_semantics.push((field.name.clone(), semantics));
                    }
                }
                if field_semantics.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(AnnotatedValueSemantics::Record(field_semantics)))
                }
            }
            _ => Ok(self.semantics.clone()),
        }
    }

    fn initializer_bytes_with_path(
        &self,
        value: &Value,
        spec: &str,
        path: Option<&str>,
    ) -> Result<Vec<u8>, CompileError> {
        fn initializer_path_suffix(path: Option<&str>) -> String {
            match path {
                Some(path) if path.starts_with('[') => path.to_string(),
                Some(path) => format!(" field '{path}'"),
                None => String::new(),
            }
        }

        let path_suffix = initializer_path_suffix(path);

        if matches!(value, Value::Nothing { .. }) {
            return Ok(vec![0u8; self.ty.size()]);
        }

        let integer_error = |type_name: &str| {
            CompileError::UnsupportedInstruction(format!(
                "global type spec '{}' initializer{} requires a {}-compatible constant",
                spec, path_suffix, type_name
            ))
        };

        let encoded_i64 = |type_name: &str| {
            named_global_numeric_constant_i64(value).ok_or_else(|| integer_error(type_name))
        };

        match &self.shape {
            NamedGlobalTypeShape::I8 => {
                let encoded = i8::try_from(encoded_i64("i8")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in i8",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::I16 => {
                let encoded = i16::try_from(encoded_i64("i16")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in i16",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::I32 => {
                let encoded = i32::try_from(encoded_i64("i32")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in i32",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::I64
            | NamedGlobalTypeShape::Duration
            | NamedGlobalTypeShape::Filesize => Ok(encoded_i64("i64")?.to_le_bytes().to_vec()),
            NamedGlobalTypeShape::U8 => {
                let encoded = u8::try_from(encoded_i64("u8")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in u8",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::U16 => {
                let encoded = u16::try_from(encoded_i64("u16")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in u16",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::U32 => {
                let encoded = u32::try_from(encoded_i64("u32")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in u32",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::U64 => {
                let encoded = u64::try_from(encoded_i64("u64")?).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} does not fit in u64",
                        spec, path_suffix
                    ))
                })?;
                Ok(encoded.to_le_bytes().to_vec())
            }
            NamedGlobalTypeShape::Bool => match value {
                Value::Bool { val, .. } => Ok(vec![u8::from(*val)]),
                _ => Err(CompileError::UnsupportedInstruction(format!(
                    "global type spec '{}' initializer{} requires a bool constant",
                    spec, path_suffix
                ))),
            },
            NamedGlobalTypeShape::Bytes { len } => {
                let Value::Binary { val, .. } = value else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} requires a binary constant",
                        spec, path_suffix
                    )));
                };
                if val.len() > *len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} is {} bytes but capacity is {}",
                        spec,
                        path_suffix,
                        val.len(),
                        len
                    )));
                }
                let mut data = vec![0u8; *len];
                data[..val.len()].copy_from_slice(val);
                Ok(data)
            }
            NamedGlobalTypeShape::String {
                content_cap,
                slot_len,
            } => {
                let bytes = match value {
                    Value::String { val, .. } => val.as_bytes(),
                    Value::Glob { val, .. } => val.as_bytes(),
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global type spec '{}' initializer{} requires a string or glob constant",
                            spec, path_suffix
                        )));
                    }
                };
                if bytes.len() > *content_cap {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} is {} bytes but capacity is {}",
                        spec,
                        path_suffix,
                        bytes.len(),
                        content_cap
                    )));
                }
                let mut data = vec![0u8; 8 + *slot_len];
                data[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
                data[8..8 + bytes.len()].copy_from_slice(bytes);
                Ok(data)
            }
            NamedGlobalTypeShape::NumericList { max_len } => {
                let Value::List { vals, .. } = value else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} requires a numeric constant list",
                        spec, path_suffix
                    )));
                };
                if let Some((idx, item)) = vals
                    .iter()
                    .enumerate()
                    .find(|(_, item)| named_global_numeric_constant_i64(item).is_none())
                {
                    let item_path = path
                        .map(|prefix| format!("{prefix}[{idx}]"))
                        .unwrap_or_else(|| format!("[{idx}]"));
                    let item_path_suffix = initializer_path_suffix(Some(&item_path));
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} requires a numeric constant item, found {}",
                        spec,
                        item_path_suffix,
                        named_global_constant_kind(item)
                    )));
                }
                if vals.len() > *max_len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} has {} items but capacity is {}",
                        spec,
                        path_suffix,
                        vals.len(),
                        max_len
                    )));
                }

                let mut data = vec![0u8; (max_len.saturating_add(1)) * std::mem::size_of::<i64>()];
                data[..8].copy_from_slice(&(vals.len() as u64).to_le_bytes());
                for (idx, item) in vals.iter().enumerate() {
                    let Some(encoded) = named_global_numeric_constant_i64(item) else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "global type spec '{}' initializer{} requires a numeric constant list",
                            spec, path_suffix
                        )));
                    };
                    let start = (idx + 1) * std::mem::size_of::<i64>();
                    data[start..start + std::mem::size_of::<i64>()]
                        .copy_from_slice(&encoded.to_le_bytes());
                }
                Ok(data)
            }
            NamedGlobalTypeShape::BpfTimer => Err(CompileError::UnsupportedInstruction(format!(
                "global type spec '{}' cannot initialize verifier-managed bpf_timer objects",
                spec
            ))),
            NamedGlobalTypeShape::BpfSpinLock => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "global type spec '{}' cannot initialize verifier-managed bpf_spin_lock objects",
                    spec
                )))
            }
            NamedGlobalTypeShape::BpfWq => Err(CompileError::UnsupportedInstruction(format!(
                "global type spec '{}' cannot initialize verifier-managed bpf_wq objects",
                spec
            ))),
            NamedGlobalTypeShape::BpfRefcount => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "global type spec '{}' cannot initialize verifier-managed bpf_refcount objects",
                    spec
                )))
            }
            NamedGlobalTypeShape::BpfKptr { pointee_name } => {
                Err(CompileError::UnsupportedInstruction(format!(
                    "global type spec '{}' cannot initialize verifier-managed kptr slots for {}",
                    spec, pointee_name
                )))
            }
            NamedGlobalTypeShape::BpfGraphRoot {
                kind,
                value_type,
                node_field,
            } => Err(CompileError::UnsupportedInstruction(format!(
                "global type spec '{}' cannot initialize verifier-managed {} roots for object type {}.{}",
                spec,
                kind.root_struct_name(),
                value_type,
                node_field
            ))),
            NamedGlobalTypeShape::FixedArray { elem, len } => {
                let Value::List { vals, .. } = value else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} requires a constant list",
                        spec, path_suffix
                    )));
                };
                if vals.len() > *len {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} has {} items but length is {}",
                        spec,
                        path_suffix,
                        vals.len(),
                        len
                    )));
                }

                let elem_size = elem.ty.size();
                let mut data = vec![0u8; elem_size.saturating_mul(*len)];
                for (idx, item) in vals.iter().enumerate() {
                    let nested_path = path
                        .map(|prefix| format!("{prefix}[{idx}]"))
                        .unwrap_or_else(|| format!("[{idx}]"));
                    let item_data =
                        elem.initializer_bytes_with_path(item, spec, Some(&nested_path))?;
                    let start = idx.saturating_mul(elem_size);
                    data[start..start + elem_size].copy_from_slice(&item_data);
                }
                Ok(data)
            }
            NamedGlobalTypeShape::Record(fields) => {
                let Value::Record { val, .. } = value else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer{} requires a record constant",
                        spec, path_suffix
                    )));
                };

                let mut data = vec![0u8; self.ty.size()];
                for field in fields {
                    if let Some(field_value) = val.get(&field.name) {
                        let nested_path = path
                            .map(|prefix| format!("{prefix}.{}", field.name))
                            .unwrap_or_else(|| field.name.clone());
                        let field_data = field.ty.initializer_bytes_with_path(
                            field_value,
                            spec,
                            Some(&nested_path),
                        )?;
                        let end = field.offset.saturating_add(field.ty.ty.size());
                        data[field.offset..end].copy_from_slice(&field_data);
                    }
                }

                if let Some((extra_name, _)) = val
                    .iter()
                    .find(|(name, _)| !fields.iter().any(|field| field.name == **name))
                {
                    let extra_path = path
                        .map(|prefix| format!("{prefix}.{extra_name}"))
                        .unwrap_or_else(|| extra_name.to_string());
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "global type spec '{}' initializer contains unexpected field '{}'",
                        spec, extra_path
                    )));
                }

                Ok(data)
            }
        }
    }
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn named_program_global_symbol(name: &str) -> String {
        format!("__nu_global_{}", name)
    }

    pub(super) fn named_program_global(&self, name: &str) -> Option<&MutableCaptureGlobal> {
        self.named_program_globals.get(name)
    }

    pub(super) fn named_program_global_semantics(
        &self,
        name: &str,
    ) -> Option<&AnnotatedValueSemantics> {
        self.named_program_global_semantics.get(name)
    }

    fn merge_annotated_value_semantics(
        existing: &AnnotatedValueSemantics,
        incoming: &AnnotatedValueSemantics,
    ) -> Option<AnnotatedValueSemantics> {
        match (existing, incoming) {
            (
                AnnotatedValueSemantics::String {
                    slot_len: existing_slot_len,
                    content_cap: existing_content_cap,
                },
                AnnotatedValueSemantics::String {
                    slot_len: incoming_slot_len,
                    content_cap: incoming_content_cap,
                },
            ) if existing_slot_len == incoming_slot_len
                && existing_content_cap == incoming_content_cap =>
            {
                Some(existing.clone())
            }
            (
                AnnotatedValueSemantics::Binary { len: existing_len },
                AnnotatedValueSemantics::Binary { len: incoming_len },
            ) if existing_len == incoming_len => Some(existing.clone()),
            (
                AnnotatedValueSemantics::NumericList {
                    max_len: existing_max_len,
                    known_len: existing_known_len,
                },
                AnnotatedValueSemantics::NumericList {
                    max_len: incoming_max_len,
                    known_len: incoming_known_len,
                },
            ) if existing_max_len == incoming_max_len => {
                let known_len = match (existing_known_len, incoming_known_len) {
                    (Some(existing), Some(incoming)) if existing == incoming => Some(*existing),
                    (Some(0), Some(incoming)) => Some(*incoming),
                    (Some(existing), Some(0)) => Some(*existing),
                    (Some(_), Some(_)) => return None,
                    (Some(existing), None) => Some(*existing),
                    (None, Some(incoming)) => Some(*incoming),
                    (None, None) => None,
                };
                Some(AnnotatedValueSemantics::NumericList {
                    max_len: *existing_max_len,
                    known_len,
                })
            }
            (
                AnnotatedValueSemantics::FixedArray {
                    elem: existing_elem,
                    len: existing_len,
                },
                AnnotatedValueSemantics::FixedArray {
                    elem: incoming_elem,
                    len: incoming_len,
                },
            ) if existing_len == incoming_len => {
                Self::merge_annotated_value_semantics(existing_elem, incoming_elem).map(
                    |merged_elem| AnnotatedValueSemantics::FixedArray {
                        elem: Box::new(merged_elem),
                        len: *existing_len,
                    },
                )
            }
            (
                AnnotatedValueSemantics::Record(existing_fields),
                AnnotatedValueSemantics::Record(incoming_fields),
            ) if existing_fields.len() == incoming_fields.len() => {
                let mut merged_fields = Vec::with_capacity(existing_fields.len());
                for ((existing_name, existing_semantics), (incoming_name, incoming_semantics)) in
                    existing_fields.iter().zip(incoming_fields)
                {
                    if existing_name != incoming_name {
                        return None;
                    }
                    let merged_semantics = Self::merge_annotated_value_semantics(
                        existing_semantics,
                        incoming_semantics,
                    )?;
                    merged_fields.push((existing_name.clone(), merged_semantics));
                }
                Some(AnnotatedValueSemantics::Record(merged_fields))
            }
            _ => None,
        }
    }

    fn merge_named_program_global_semantics(
        &mut self,
        name: &str,
        semantics: AnnotatedValueSemantics,
    ) -> Result<(), CompileError> {
        let Some(existing_semantics) = self.named_program_global_semantics.get(name).cloned()
        else {
            self.named_program_global_semantics
                .insert(name.to_string(), semantics);
            return Ok(());
        };

        let Some(merged_semantics) =
            Self::merge_annotated_value_semantics(&existing_semantics, &semantics)
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' is used with incompatible value semantics",
                name
            )));
        };

        if merged_semantics != existing_semantics {
            self.named_program_global_semantics
                .insert(name.to_string(), merged_semantics);
        }
        Ok(())
    }

    pub(super) fn tracked_value_semantics(
        &self,
        src: RegId,
        constant_value: Option<&Value>,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        if let Some(value) = constant_value {
            return Self::mutable_global_value_semantics(value);
        }

        let Some(meta) = self.get_metadata(src) else {
            return Ok(None);
        };

        if let Some(semantics) = meta.annotated_semantics.clone() {
            return Ok(Some(semantics));
        }

        if let Some((_, max_len)) = meta.list_buffer {
            return Ok(Some(AnnotatedValueSemantics::NumericList {
                max_len,
                known_len: None,
            }));
        }

        if let Some(slot) = meta.string_slot {
            let slot_len = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during global value semantics inference".into(),
                )
            })?;
            return Ok(Some(AnnotatedValueSemantics::String {
                slot_len,
                content_cap: meta.string_len_bound.unwrap_or(slot_len.saturating_sub(1)),
            }));
        }

        if let Some(record_semantics) = Self::metadata_record_semantics(meta) {
            return Ok(Some(record_semantics));
        }

        Ok(None)
    }

    pub(super) fn parse_named_map_value_type_spec(
        spec: &str,
    ) -> Result<(MirType, Option<AnnotatedValueSemantics>), CompileError> {
        let parsed =
            ParsedNamedGlobalType::parse_with_context(spec, NamedTypeSpecContext::MapValue)?;
        Ok((parsed.ty, parsed.semantics))
    }

    pub(super) fn parse_named_map_key_type_spec(spec: &str) -> Result<MirType, CompileError> {
        let parsed = ParsedNamedGlobalType::parse_with_context(spec, NamedTypeSpecContext::MapKey)?;
        Ok(parsed.ty)
    }

    fn infer_mutable_global_layout(
        &self,
        symbol: String,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        if let Some(meta) = self.get_metadata(src) {
            if let Some((_, max_len)) = meta.list_buffer {
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: max_len.saturating_add(1),
                    },
                    list_max_len: Some(max_len),
                    string_slot_len: None,
                    string_content_cap: None,
                });
            }

            if let Some(slot) = meta.string_slot {
                let slot_len = self.stack_slot_size(slot).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "string slot not found during mutable global layout inference".into(),
                    )
                })?;
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 8 + slot_len,
                    },
                    list_max_len: None,
                    string_slot_len: Some(slot_len),
                    string_content_cap: Some(
                        meta.string_len_bound.unwrap_or(slot_len.saturating_sub(1)),
                    ),
                });
            }

            if let Some(field_ty) = meta.field_type.clone() {
                let stored_ty = self.stored_generic_map_value_type(&field_ty);
                if matches!(
                    stored_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                        | MirType::Array { .. }
                        | MirType::Struct { .. }
                ) {
                    return Ok(MutableCaptureGlobal {
                        symbol,
                        ty: stored_ty,
                        list_max_len: None,
                        string_slot_len: None,
                        string_content_cap: None,
                    });
                }
            }

            if let Some(record_ty) = Self::metadata_record_layout(meta) {
                return Ok(MutableCaptureGlobal {
                    symbol,
                    ty: record_ty,
                    list_max_len: None,
                    string_slot_len: None,
                    string_content_cap: None,
                });
            }
        }

        let fallback_ty = self
            .vreg_type_hints
            .get(&src_vreg)
            .cloned()
            .map(|ty| self.stored_generic_map_value_type(&ty))
            .or_else(|| {
                self.get_metadata(src)
                    .and_then(|m| m.literal_int.map(|_| MirType::I64))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "global-set requires a value with a known fixed layout".into(),
                )
            })?;

        match fallback_ty {
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::Bool
            | MirType::Array { .. }
            | MirType::Struct { .. } => Ok(MutableCaptureGlobal {
                symbol,
                ty: fallback_ty,
                list_max_len: None,
                string_slot_len: None,
                string_content_cap: None,
            }),
            _ => Err(CompileError::UnsupportedInstruction(
                "global-set requires a scalar, string, fixed binary, numeric list, or representable aggregate value".into(),
            )),
        }
    }

    fn ensure_named_program_global_with_mode(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
        initialize_from_constant: bool,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let source_constant_value = self
            .get_metadata(src)
            .and_then(|meta| meta.constant_value.clone());
        let value_semantics = self.tracked_value_semantics(src, source_constant_value.as_ref())?;
        let constant_value = if initialize_from_constant {
            source_constant_value.clone()
        } else {
            None
        };
        let initialized_repr = if let Some(value) = constant_value.as_ref() {
            Self::mutable_capture_global_repr(value)?
        } else {
            None
        };
        let inferred =
            if let Some((ty, _data, list_max_len, string_slot_len)) = initialized_repr.as_ref() {
                MutableCaptureGlobal {
                    symbol: symbol.clone(),
                    ty: ty.clone(),
                    list_max_len: *list_max_len,
                    string_slot_len: *string_slot_len,
                    string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
                }
            } else {
                self.infer_mutable_global_layout(symbol.clone(), src, src_vreg)?
            };

        if let Some(existing) = self.named_program_globals.get(name).cloned() {
            if existing != inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = value_semantics {
                self.merge_named_program_global_semantics(name, semantics)?;
            }
            return Ok(existing);
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        if let Some((_ty, data, _list_max_len, _string_slot_len)) = initialized_repr {
            if data.iter().all(|byte| *byte == 0) {
                self.bss_globals.push(BssGlobal { name: symbol, size });
            } else {
                self.data_globals.push(DataGlobal { name: symbol, data });
            }
        } else {
            self.bss_globals.push(BssGlobal { name: symbol, size });
        }
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = value_semantics {
            self.merge_named_program_global_semantics(name, semantics)?;
        }
        Ok(inferred)
    }

    pub(super) fn ensure_named_program_global(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        self.ensure_named_program_global_with_mode(name, src, src_vreg, true)
    }

    pub(super) fn ensure_zeroed_named_program_global(
        &mut self,
        name: &str,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        self.ensure_named_program_global_with_mode(name, src, src_vreg, false)
    }

    pub(super) fn predeclare_named_program_global_from_value(
        &mut self,
        name: &str,
        value: &Value,
        initialize: bool,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let Some((ty, data, list_max_len, string_slot_len)) =
            Self::mutable_capture_global_repr(value)?
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' requires a compile-time constant with a fixed layout",
                name
            )));
        };

        let inferred = MutableCaptureGlobal {
            symbol: symbol.clone(),
            ty,
            list_max_len,
            string_slot_len,
            string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
        };

        if let Some(existing) = self.named_program_globals.get(name).cloned() {
            if existing != inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = Self::mutable_global_value_semantics(value)? {
                self.merge_named_program_global_semantics(name, semantics)?;
            }
            return Ok(existing);
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        if initialize && data.iter().any(|byte| *byte != 0) {
            self.data_globals.push(DataGlobal { name: symbol, data });
        } else {
            // Forward global-get support from later global-set is layout-only.
            // The later set still performs the real initialization at runtime,
            // so the compile-time global must remain zero-initialized.
            self.bss_globals.push(BssGlobal { name: symbol, size });
        }
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = Self::mutable_global_value_semantics(value)? {
            self.merge_named_program_global_semantics(name, semantics)?;
        }
        Ok(inferred)
    }

    pub(super) fn define_named_program_global_from_type_spec(
        &mut self,
        name: &str,
        spec: &str,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let parsed = ParsedNamedGlobalType::parse(spec)?;
        let (inferred, semantics) = parsed.layout(symbol.clone());
        let semantics = parsed.initializer_semantics(None)?.or(semantics);

        if let Some(existing) = self.named_program_globals.get(name).cloned() {
            if existing != inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = semantics {
                self.merge_named_program_global_semantics(name, semantics)?;
            }
            return Ok(existing);
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        self.bss_globals.push(BssGlobal { name: symbol, size });
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = semantics {
            self.merge_named_program_global_semantics(name, semantics)?;
        }
        Ok(inferred)
    }

    pub(super) fn define_named_program_global_from_type_spec_and_value(
        &mut self,
        name: &str,
        spec: &str,
        value: &Value,
    ) -> Result<MutableCaptureGlobal, CompileError> {
        let symbol = Self::named_program_global_symbol(name);
        let parsed = ParsedNamedGlobalType::parse(spec)?;
        let (inferred, semantics) = parsed.layout(symbol.clone());
        let data = parsed.initializer_bytes(value, spec)?;
        let semantics = parsed.initializer_semantics(Some(value))?.or(semantics);

        if let Some(existing) = self.named_program_globals.get(name).cloned() {
            if existing != inferred {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "global '{}' is used with incompatible layouts",
                    name
                )));
            }
            if let Some(semantics) = semantics {
                self.merge_named_program_global_semantics(name, semantics)?;
            }
            return Ok(existing);
        }

        let size = inferred.ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "global '{}' inferred an empty layout, which is not yet supported",
                name
            )));
        }

        if data.iter().any(|byte| *byte != 0) {
            self.data_globals.push(DataGlobal { name: symbol, data });
        } else {
            self.bss_globals.push(BssGlobal { name: symbol, size });
        }
        self.named_program_globals
            .insert(name.to_string(), inferred.clone());
        if let Some(semantics) = semantics {
            self.merge_named_program_global_semantics(name, semantics)?;
        }
        Ok(inferred)
    }

    pub(super) fn load_mutable_global_value(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        global: &MutableCaptureGlobal,
    ) -> Result<(), CompileError> {
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        let global_ptr_ty = MirType::Ptr {
            pointee: Box::new(global.ty.clone()),
            address_space: crate::compiler::mir::AddressSpace::Map,
        };
        self.vreg_type_hints
            .insert(global_ptr, global_ptr_ty.clone());

        self.reg_metadata.insert(dst.get(), RegMetadata::default());
        self.get_or_create_metadata(dst).mutable_global_runtime = true;

        if let Some(max_len) = global.list_max_len {
            let buffer_size = (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
            let slot = self
                .func
                .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
            self.record_list_buffer_slot_type(slot, max_len);
            self.emit(MirInst::ListNew {
                dst: dst_vreg,
                buffer: slot,
                max_len,
            });
            let stack_list_ptr_ty = MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_list_ptr_ty);
            self.emit_ptr_copy(dst_vreg, global_ptr, global.ty.size())?;
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
            meta.list_buffer = Some((slot, max_len));
        } else if let Some(slot_len) = global.string_slot_len {
            let slot = self
                .func
                .alloc_stack_slot(slot_len, 8, StackSlotKind::StringBuffer);
            self.record_stack_slot_type(
                slot,
                MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                },
            );
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(slot),
            });
            let stack_string_ptr_ty = MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: slot_len,
                }),
                address_space: crate::compiler::mir::AddressSpace::Stack,
            };
            self.vreg_type_hints.insert(dst_vreg, stack_string_ptr_ty);
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Load {
                dst: len_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: MirType::U64,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);
            self.emit_ptr_copy_with_offsets(dst_vreg, 0, global_ptr, 8, slot_len)?;
            let meta = self.get_or_create_metadata(dst);
            meta.string_slot = Some(slot);
            meta.string_len_vreg = Some(len_vreg);
            meta.string_len_bound = Some(
                global
                    .string_content_cap
                    .unwrap_or(slot_len.saturating_sub(1)),
            );
            meta.field_type = Some(MirType::Array {
                elem: Box::new(MirType::U8),
                len: slot_len,
            });
        } else if matches!(global.ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(global_ptr),
            });
            self.vreg_type_hints.insert(dst_vreg, global_ptr_ty);
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        } else {
            self.emit(MirInst::Load {
                dst: dst_vreg,
                ptr: global_ptr,
                offset: 0,
                ty: global.ty.clone(),
            });
            self.vreg_type_hints.insert(dst_vreg, global.ty.clone());
            let meta = self.get_or_create_metadata(dst);
            meta.field_type = Some(global.ty.clone());
        }

        Ok(())
    }

    pub(super) fn store_into_mutable_global(
        &mut self,
        context: &str,
        global: &MutableCaptureGlobal,
        src: RegId,
        src_vreg: VReg,
    ) -> Result<(), CompileError> {
        self.reject_context_pointer_payload(Some(src), context)?;
        let global_ptr = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_ptr,
            symbol: global.symbol.clone(),
            ty: global.ty.clone(),
        });
        self.vreg_type_hints.insert(
            global_ptr,
            MirType::Ptr {
                pointee: Box::new(global.ty.clone()),
                address_space: crate::compiler::mir::AddressSpace::Map,
            },
        );

        if let Some(max_len) = global.list_max_len {
            let Some((slot, src_max_len)) = self.get_metadata(src).and_then(|m| m.list_buffer)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized numeric list value",
                    context
                )));
            };

            if src_max_len != max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing numeric list of capacity {} into {} with capacity {} is not supported",
                    src_max_len, context, max_len
                )));
            }

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(global.ty.clone()),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy(global_ptr, src_ptr, global.ty.size())?;
        } else if let Some(slot_len) = global.string_slot_len {
            let src_meta = self.get_metadata(src).cloned();
            let Some(meta) = src_meta else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(slot) = meta.string_slot else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a materialized string value with tracked length",
                    context
                )));
            };
            let Some(len_vreg) = meta.string_len_vreg else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing into {} requires a tracked string length",
                    context
                )));
            };
            let src_slot_size = self.stack_slot_size(slot).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "string slot not found during mutable global store".into(),
                )
            })?;
            if src_slot_size > slot_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing string buffer of size {} into {} with capacity {} is not supported",
                    src_slot_size, context, slot_len
                )));
            }
            let src_max_len = meta
                .string_len_bound
                .unwrap_or(src_slot_size.saturating_sub(1));
            let dst_max_len = global
                .string_content_cap
                .unwrap_or(slot_len.saturating_sub(1));
            if src_max_len > dst_max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "storing string value with capacity {} into {} with content capacity {} is not supported",
                    src_max_len, context, dst_max_len
                )));
            }

            self.emit(MirInst::Store {
                ptr: global_ptr,
                offset: 0,
                val: MirValue::VReg(len_vreg),
                ty: MirType::U64,
            });

            let src_ptr = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: src_ptr,
                src: MirValue::StackSlot(slot),
            });
            self.vreg_type_hints.insert(
                src_ptr,
                MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: src_slot_size,
                    }),
                    address_space: crate::compiler::mir::AddressSpace::Stack,
                },
            );
            self.emit_ptr_copy_with_offsets(global_ptr, 8, src_ptr, 0, src_slot_size)?;
            if src_slot_size < slot_len {
                self.emit_ptr_zero(global_ptr, 8 + src_slot_size, slot_len - src_slot_size)?;
            }
        } else {
            match &global.ty {
                MirType::Array { .. } | MirType::Struct { .. } => {
                    let aggregate_src_vreg =
                        self.materialized_metadata_aggregate_vreg(src, src_vreg)?;

                    let Some(src_runtime_ty) =
                        self.vreg_type_hints.get(&aggregate_src_vreg).cloned()
                    else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a materialized aggregate pointer value",
                            context
                        )));
                    };

                    let Some(MirType::Ptr {
                        pointee,
                        address_space:
                            crate::compiler::mir::AddressSpace::Stack
                            | crate::compiler::mir::AddressSpace::Map,
                    }) = Some(src_runtime_ty)
                    else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing into {} requires a stack/map aggregate pointer value",
                            context
                        )));
                    };

                    if pointee.as_ref() != &global.ty {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "storing type {:?} into {} of type {:?} is not supported",
                            pointee, context, global.ty
                        )));
                    }

                    self.emit_ptr_copy(global_ptr, aggregate_src_vreg, global.ty.size())?;
                }
                _ => {
                    self.emit(MirInst::Store {
                        ptr: global_ptr,
                        offset: 0,
                        val: MirValue::VReg(src_vreg),
                        ty: global.ty.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}
