//! Output model for `ebpf spec` records.

use nu_protocol::{Span, Value, record};

use crate::compiler::mir::{AddressSpace, MirType};
use crate::compiler::{
    ContextFieldLoadGuard, PacketContextKind, ProbeContext, ProgramValueAccess,
    SockOpsCallbackGuard,
};
use crate::kernel_btf::{TrampolineValueKind, TypeInfo};

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextField {
    field: String,
    names: Vec<&'static str>,
    semantic_type: Option<String>,
    runtime_type: Option<String>,
    kernel_btf_runtime_type: Option<&'static str>,
    load_guard: Option<&'static str>,
    load_guard_witness: Option<String>,
    load_guard_description: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextWrite {
    field: &'static str,
    kind: &'static str,
    indexed: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextArg {
    name: String,
    index: Option<usize>,
    named_alias: Option<String>,
    source: &'static str,
    kind: &'static str,
    ty: Option<String>,
    supported: bool,
    note: Option<String>,
    unsupported_reason: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextRetval {
    name: &'static str,
    source: &'static str,
    kind: &'static str,
    ty: Option<String>,
    supported: bool,
    note: Option<String>,
    unsupported_reason: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecTracepointField {
    name: String,
    ty: String,
    offset: usize,
    size: usize,
    bit_offset: Option<u32>,
    bit_size: Option<u32>,
}

#[cfg(target_os = "linux")]
fn address_space_label(address_space: AddressSpace) -> &'static str {
    match address_space {
        AddressSpace::Stack => "stack",
        AddressSpace::Kernel => "kernel",
        AddressSpace::User => "user",
        AddressSpace::Packet => "packet",
        AddressSpace::Map => "map",
    }
}

#[cfg(target_os = "linux")]
fn mir_type_label(ty: &MirType) -> String {
    match ty {
        MirType::I8 => "i8".to_string(),
        MirType::I16 => "i16".to_string(),
        MirType::I32 => "i32".to_string(),
        MirType::I64 => "i64".to_string(),
        MirType::U8 => "u8".to_string(),
        MirType::U16 => "u16".to_string(),
        MirType::U32 => "u32".to_string(),
        MirType::U64 => "u64".to_string(),
        MirType::Bool => "bool".to_string(),
        MirType::Ptr {
            pointee,
            address_space,
        } => format!(
            "ptr<{}, {}>",
            address_space_label(*address_space),
            mir_type_label(pointee)
        ),
        MirType::Array { elem, len } => format!("array<{}; {}>", mir_type_label(elem), len),
        MirType::Struct {
            name: Some(name), ..
        } => format!("struct<{name}>"),
        MirType::Struct { fields, .. } => {
            let fields = fields
                .iter()
                .filter(|field| !field.synthetic)
                .map(|field| format!("{}:{}", field.name, mir_type_label(&field.ty)))
                .collect::<Vec<_>>()
                .join(",");
            format!("record<{fields}>")
        }
        MirType::MapRef { key_ty, val_ty } => {
            format!(
                "map<{}, {}>",
                mir_type_label(key_ty),
                mir_type_label(val_ty)
            )
        }
        MirType::Subprogram { args, ret } => {
            let args = args
                .iter()
                .map(mir_type_label)
                .collect::<Vec<_>>()
                .join(",");
            format!("subprogram<({args}) -> {}>", mir_type_label(ret))
        }
        MirType::Unknown => "unknown".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn type_info_label(ty: &TypeInfo) -> String {
    match ty {
        TypeInfo::Int { size, signed } => match (*size, *signed) {
            (1, true) => "i8".to_string(),
            (2, true) => "i16".to_string(),
            (4, true) => "i32".to_string(),
            (8, true) => "i64".to_string(),
            (1, false) => "u8".to_string(),
            (2, false) => "u16".to_string(),
            (4, false) => "u32".to_string(),
            (8, false) => "u64".to_string(),
            (size, true) => format!("int<{size}>"),
            (size, false) => format!("uint<{size}>"),
        },
        TypeInfo::Ptr { target, is_user } => {
            let address_space = if *is_user { "user" } else { "kernel" };
            format!("ptr<{address_space}, {}>", type_info_label(target))
        }
        TypeInfo::Struct { name, .. } if !name.is_empty() => format!("struct<{name}>"),
        TypeInfo::Struct { size, .. } => format!("struct<{size}>"),
        TypeInfo::Array { element, len } => format!("array<{}; {}>", type_info_label(element), len),
        TypeInfo::Void => "void".to_string(),
        TypeInfo::Unknown => "unknown".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn trampoline_value_kind_label(kind: TrampolineValueKind) -> &'static str {
    match kind {
        TrampolineValueKind::Scalar => "scalar",
        TrampolineValueKind::Pointer { .. } => "pointer",
        TrampolineValueKind::Aggregate { .. } => "aggregate",
    }
}

#[cfg(target_os = "linux")]
fn packet_context_kind_label(kind: PacketContextKind) -> &'static str {
    match kind {
        PacketContextKind::XdpMd => "xdp_md",
        PacketContextKind::SkBuff => "sk_buff",
        PacketContextKind::SkReuseport => "sk_reuseport_md",
        PacketContextKind::SkMsg => "sk_msg_md",
        PacketContextKind::SockOps => "bpf_sock_ops",
    }
}

#[cfg(target_os = "linux")]
fn context_field_load_guard_label(guard: ContextFieldLoadGuard) -> &'static str {
    match guard {
        ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::PacketData) => {
            "sock-ops-packet-data"
        }
        ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::PacketMetadata) => {
            "sock-ops-packet-metadata"
        }
        ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::TcpFlags) => {
            "sock-ops-tcp-flags"
        }
        ContextFieldLoadGuard::SockOpsCallback(SockOpsCallbackGuard::Hwtstamp) => {
            "sock-ops-hwtstamp"
        }
    }
}

#[cfg(target_os = "linux")]
fn optional_packet_context_kind(value: Option<PacketContextKind>, span: Span) -> Value {
    value
        .map(|value| Value::string(packet_context_kind_label(value), span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn optional_string(value: Option<String>, span: Span) -> Value {
    value
        .map(|value| Value::string(value, span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn optional_static_str(value: Option<&'static str>, span: Span) -> Value {
    value
        .map(|value| Value::string(value, span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn optional_usize(value: Option<usize>, span: Span) -> Value {
    value
        .and_then(|value| i64::try_from(value).ok())
        .map(|value| Value::int(value, span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn optional_u32(value: Option<u32>, span: Span) -> Value {
    value
        .map(|value| Value::int(i64::from(value), span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn spec_context_fields(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextField> {
    let mut fields: Vec<(crate::compiler::mir::CtxField, SpecContextField)> = Vec::new();

    for entry in spec.program_type().ctx_field_name_entries() {
        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        if let Some((_, field)) = fields.iter_mut().find(|(field, _)| field == &entry.field) {
            field.names.push(entry.name);
        } else {
            let type_spec = spec.ctx_field_type_spec(&entry.field);
            let load_guard = spec.ctx_field_load_guard(&entry.field);
            fields.push((
                entry.field.clone(),
                SpecContextField {
                    field: entry.field.display_name(),
                    names: vec![entry.name],
                    semantic_type: type_spec
                        .as_ref()
                        .map(|type_spec| mir_type_label(&type_spec.semantic_ty)),
                    runtime_type: type_spec
                        .as_ref()
                        .map(|type_spec| mir_type_label(&type_spec.runtime_ty)),
                    kernel_btf_runtime_type: type_spec
                        .as_ref()
                        .and_then(|type_spec| type_spec.kernel_btf_runtime_type_name),
                    load_guard: load_guard.map(context_field_load_guard_label),
                    load_guard_witness: load_guard
                        .map(ContextFieldLoadGuard::witness_field)
                        .map(|field| field.display_name()),
                    load_guard_description: load_guard.map(|guard| guard.error(&entry.field)),
                },
            ));
        }
    }

    fields.into_iter().map(|(_, field)| field).collect()
}

#[cfg(target_os = "linux")]
fn context_field_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_context_fields(spec)
        .into_iter()
        .map(|field| {
            let names = field
                .names
                .into_iter()
                .map(|name| Value::string(name, span))
                .collect();
            Value::record(
                record! {
                    "field" => Value::string(field.field, span),
                    "names" => Value::list(names, span),
                    "semantic_type" => optional_string(field.semantic_type, span),
                    "runtime_type" => optional_string(field.runtime_type, span),
                    "kernel_btf_runtime_type" => optional_static_str(field.kernel_btf_runtime_type, span),
                    "load_guard" => optional_static_str(field.load_guard, span),
                    "load_guard_witness" => optional_string(field.load_guard_witness, span),
                    "load_guard_description" => optional_string(field.load_guard_description, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_tracepoint_fields(
    spec: &crate::program_spec::ProgramSpec,
    resolve_dynamic_fields: bool,
) -> (Vec<SpecTracepointField>, Option<String>) {
    if !resolve_dynamic_fields || spec.tracepoint_parts().is_none() {
        return (Vec::new(), None);
    }

    let ctx = ProbeContext::from_program_spec(spec.clone());
    match ctx.tracepoint_context() {
        Ok(Some(tracepoint)) => (
            tracepoint
                .fields
                .into_iter()
                .map(|field| SpecTracepointField {
                    name: field.name,
                    ty: type_info_label(&field.type_info),
                    offset: field.offset,
                    size: field.size,
                    bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
                    bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
                })
                .collect(),
            None,
        ),
        Ok(None) => (Vec::new(), None),
        Err(err) => (Vec::new(), Some(err)),
    }
}

#[cfg(target_os = "linux")]
fn tracepoint_field_records(fields: Vec<SpecTracepointField>, span: Span) -> Vec<Value> {
    fields
        .into_iter()
        .map(|field| {
            Value::record(
                record! {
                    "name" => Value::string(field.name, span),
                    "type" => Value::string(field.ty, span),
                    "offset" => optional_usize(Some(field.offset), span),
                    "size" => optional_usize(Some(field.size), span),
                    "bit_offset" => optional_u32(field.bit_offset, span),
                    "bit_size" => optional_u32(field.bit_size, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_context_args(
    spec: &crate::program_spec::ProgramSpec,
    resolve_dynamic_args: bool,
) -> (Vec<SpecContextArg>, Option<String>) {
    match spec.program_type().arg_access() {
        ProgramValueAccess::None => (Vec::new(), None),
        ProgramValueAccess::PtRegs => (
            (0..6)
                .map(|index| SpecContextArg {
                    name: format!("arg{index}"),
                    index: Some(index),
                    named_alias: None,
                    source: "pt_regs",
                    kind: "scalar",
                    ty: Some("u64".to_string()),
                    supported: true,
                    note: None,
                    unsupported_reason: None,
                })
                .collect(),
            None,
        ),
        ProgramValueAccess::RawTracepoint => (
            vec![SpecContextArg {
                name: "argN".to_string(),
                index: None,
                named_alias: None,
                source: "raw_tracepoint",
                kind: "scalar",
                ty: Some("u64".to_string()),
                supported: true,
                note: Some(
                    "raw tracepoint argument count and meanings are target-specific".to_string(),
                ),
                unsupported_reason: None,
            }],
            None,
        ),
        ProgramValueAccess::Trampoline if !resolve_dynamic_args => (Vec::new(), None),
        ProgramValueAccess::Trampoline => {
            let ctx = ProbeContext::from_program_spec(spec.clone());
            match ctx.btf_arg_infos() {
                Ok(infos) => (
                    infos
                        .into_iter()
                        .map(|info| {
                            let kind = info
                                .value
                                .map(|value| trampoline_value_kind_label(value.kind))
                                .unwrap_or("unsupported");
                            SpecContextArg {
                                name: format!("arg{}", info.index),
                                index: Some(info.index),
                                named_alias: info.name,
                                source: "btf_trampoline",
                                kind,
                                ty: Some(type_info_label(&info.type_info)),
                                supported: info.value.is_some(),
                                note: None,
                                unsupported_reason: info.unsupported_reason,
                            }
                        })
                        .collect(),
                    None,
                ),
                Err(err) => (Vec::new(), Some(err)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn context_arg_records(args: Vec<SpecContextArg>, span: Span) -> Vec<Value> {
    args.into_iter()
        .map(|arg| {
            Value::record(
                record! {
                    "name" => Value::string(arg.name, span),
                    "index" => optional_usize(arg.index, span),
                    "named_alias" => optional_string(arg.named_alias, span),
                    "source" => Value::string(arg.source, span),
                    "kind" => Value::string(arg.kind, span),
                    "type" => optional_string(arg.ty, span),
                    "supported" => Value::bool(arg.supported, span),
                    "note" => optional_string(arg.note, span),
                    "unsupported_reason" => optional_string(arg.unsupported_reason, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_context_retval(
    spec: &crate::program_spec::ProgramSpec,
    resolve_dynamic_args: bool,
) -> (Option<SpecContextRetval>, Option<String>) {
    match spec.program_type().retval_access() {
        ProgramValueAccess::None => (None, None),
        ProgramValueAccess::PtRegs => (
            Some(SpecContextRetval {
                name: "retval",
                source: "pt_regs",
                kind: "scalar",
                ty: Some("u64".to_string()),
                supported: true,
                note: None,
                unsupported_reason: None,
            }),
            None,
        ),
        ProgramValueAccess::RawTracepoint => (None, None),
        ProgramValueAccess::Trampoline if !resolve_dynamic_args => (None, None),
        ProgramValueAccess::Trampoline => {
            let ctx = ProbeContext::from_program_spec(spec.clone());
            let type_info = match ctx.btf_ret_type_info() {
                Ok(Some(type_info)) => type_info,
                Ok(None) => return (None, None),
                Err(err) => return (None, Some(err)),
            };
            match ctx.btf_ret_spec() {
                Ok(Some(value)) => (
                    Some(SpecContextRetval {
                        name: "retval",
                        source: "btf_trampoline",
                        kind: trampoline_value_kind_label(value.kind),
                        ty: Some(type_info_label(&type_info)),
                        supported: true,
                        note: None,
                        unsupported_reason: None,
                    }),
                    None,
                ),
                Ok(None) => (None, None),
                Err(err) => (
                    Some(SpecContextRetval {
                        name: "retval",
                        source: "btf_trampoline",
                        kind: "unsupported",
                        ty: Some(type_info_label(&type_info)),
                        supported: false,
                        note: None,
                        unsupported_reason: Some(err),
                    }),
                    None,
                ),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn context_retval_record(retval: Option<SpecContextRetval>, span: Span) -> Value {
    let Some(retval) = retval else {
        return Value::nothing(span);
    };
    Value::record(
        record! {
            "name" => Value::string(retval.name, span),
            "source" => Value::string(retval.source, span),
            "kind" => Value::string(retval.kind, span),
            "type" => optional_string(retval.ty, span),
            "supported" => Value::bool(retval.supported, span),
            "note" => optional_string(retval.note, span),
            "unsupported_reason" => optional_string(retval.unsupported_reason, span),
        },
        span,
    )
}

#[cfg(target_os = "linux")]
fn spec_context_writes(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextWrite> {
    spec.ctx_write_surfaces_for_spec()
        .into_iter()
        .map(|surface| SpecContextWrite {
            field: surface.field_name,
            kind: surface.kind,
            indexed: surface.indexed,
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn context_write_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_context_writes(spec)
        .into_iter()
        .map(|surface| {
            Value::record(
                record! {
                    "field" => Value::string(surface.field, span),
                    "kind" => Value::string(surface.kind, span),
                    "indexed" => Value::bool(surface.indexed, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(super) fn spec_record(
    probe: String,
    spec: crate::program_spec::ProgramSpec,
    span: Span,
    resolve_dynamic_args: bool,
) -> Value {
    let program_type = spec.program_type();
    let attach_kind = program_type.attach_kind();
    let live_attach_policy = spec.live_attach_policy();
    let live_attach_note = live_attach_policy.note.unwrap_or("");
    let context_fields = context_field_records(&spec, span);
    let (tracepoint_fields, tracepoint_field_error) =
        spec_tracepoint_fields(&spec, resolve_dynamic_args);
    let tracepoint_fields = tracepoint_field_records(tracepoint_fields, span);
    let (context_args, context_arg_error) = spec_context_args(&spec, resolve_dynamic_args);
    let context_args = context_arg_records(context_args, span);
    let (context_retval, context_retval_error) = spec_context_retval(&spec, resolve_dynamic_args);
    let context_retval = context_retval_record(context_retval, span);
    let context_writes = context_write_records(&spec, span);
    let capabilities = program_type
        .supported_capabilities()
        .iter()
        .map(|capability| {
            Value::record(
                record! {
                    "key" => Value::string(capability.key(), span),
                    "description" => Value::string(capability.description(), span),
                },
                span,
            )
        })
        .collect();
    let requirements = spec
        .compatibility_requirements()
        .into_iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "key" => Value::string(requirement.key(), span),
                    "description" => Value::string(requirement.description(), span),
                },
                span,
            )
        })
        .collect();
    let return_aliases = program_type
        .return_action_alias_pairs()
        .into_iter()
        .map(|(alias, value)| {
            let const_value = value
                .const_value()
                .map(|value| Value::int(value, span))
                .unwrap_or_else(|| Value::nothing(span));
            Value::record(
                record! {
                    "alias" => Value::string(alias, span),
                    "kind" => Value::string(value.key(), span),
                    "const_value" => const_value,
                },
                span,
            )
        })
        .collect();

    Value::record(
        record! {
            "probe" => Value::string(probe, span),
            "program_type" => Value::string(program_type.canonical_prefix(), span),
            "kernel_program_type" => Value::string(program_type.kernel_prog_type(), span),
            "context_family" => Value::string(program_type.context_family().key(), span),
            "packet_context_kind" => optional_packet_context_kind(spec.packet_context_kind(), span),
            "data_meta_context_kind" => optional_packet_context_kind(spec.data_meta_context_kind(), span),
            "direct_packet_writes" => Value::bool(spec.supports_direct_packet_writes(), span),
            "target" => Value::string(spec.target_string(), span),
            "section" => Value::string(spec.section_name(), span),
            "attach_kind" => Value::string(attach_kind.key(), span),
            "target_kind" => Value::string(program_type.target_kind().key(), span),
            "arg_access" => Value::string(program_type.arg_access().key(), span),
            "retval_access" => Value::string(program_type.retval_access().key(), span),
            "live_attach_supported" => Value::bool(live_attach_policy.loader_supported, span),
            "live_attach_default_allowed" => Value::bool(live_attach_policy.default_allowed, span),
            "live_attach_requires_opt_in" => Value::bool(live_attach_policy.requires_opt_in, span),
            "live_attach_note" => Value::string(live_attach_note, span),
            "context_fields" => Value::list(context_fields, span),
            "tracepoint_fields" => Value::list(tracepoint_fields, span),
            "tracepoint_field_error" => optional_string(tracepoint_field_error, span),
            "context_args" => Value::list(context_args, span),
            "context_arg_error" => optional_string(context_arg_error, span),
            "context_retval" => context_retval,
            "context_retval_error" => optional_string(context_retval_error, span),
            "context_writes" => Value::list(context_writes, span),
            "capabilities" => Value::list(capabilities, span),
            "compatibility_requirements" => Value::list(requirements, span),
            "return_aliases" => Value::list(return_aliases, span),
        },
        span,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::program_spec::ProgramSpec;

    fn field<'a>(fields: &'a [SpecContextField], field_name: &str) -> &'a SpecContextField {
        fields
            .iter()
            .find(|field| field.field == field_name)
            .unwrap_or_else(|| panic!("expected ctx.{field_name} in spec context fields"))
    }

    #[test]
    fn test_spec_context_fields_include_program_specific_aliases() {
        let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        let fields = spec_context_fields(&spec);

        assert!(field(&fields, "ingress_ifindex").names.contains(&"ifindex"));
        let packet_len = field(&fields, "packet_len");
        assert!(packet_len.names.contains(&"packet_len"));
        assert_eq!(packet_len.semantic_type.as_deref(), Some("u32"));
        assert_eq!(packet_len.runtime_type.as_deref(), Some("u32"));
    }

    #[test]
    fn test_spec_context_fields_include_kernel_btf_runtime_type_labels() {
        let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
        let fields = spec_context_fields(&spec);

        let task = field(&fields, "task");
        assert!(task.names.contains(&"current_task"));
        assert_eq!(
            task.semantic_type.as_deref(),
            Some("ptr<kernel, struct<task_struct>>")
        );
        assert_eq!(
            task.runtime_type.as_deref(),
            Some("ptr<kernel, struct<task_struct>>")
        );
        assert_eq!(task.kernel_btf_runtime_type, Some("task_struct"));
    }

    #[test]
    fn test_spec_context_fields_include_load_guards() {
        let spec =
            ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
        let fields = spec_context_fields(&spec);

        let data = field(&fields, "data");
        assert_eq!(data.load_guard, Some("sock-ops-packet-data"));
        assert_eq!(data.load_guard_witness.as_deref(), Some("op"));
        assert!(
            data.load_guard_description
                .as_deref()
                .is_some_and(|description| description.contains("packet-aware ctx.op"))
        );

        let skb_len = field(&fields, "skb_len");
        assert_eq!(skb_len.load_guard, Some("sock-ops-packet-metadata"));
    }

    #[test]
    fn test_spec_record_includes_packet_context_metadata() {
        let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
            .into_record()
            .expect("spec output should be a record");

        assert_eq!(
            record
                .get("packet_context_kind")
                .expect("packet context kind should be present")
                .as_str()
                .expect("packet context kind should be a string"),
            "xdp_md"
        );
        assert_eq!(
            record
                .get("data_meta_context_kind")
                .expect("data_meta context kind should be present")
                .as_str()
                .expect("data_meta context kind should be a string"),
            "xdp_md"
        );
        assert!(
            record
                .get("direct_packet_writes")
                .expect("direct packet writes should be present")
                .as_bool()
                .expect("direct packet writes should be a bool")
        );

        let kprobe = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
        let record = spec_record(
            "kprobe:sys_read".to_string(),
            kprobe,
            Span::test_data(),
            false,
        )
        .into_record()
        .expect("spec output should be a record");
        assert!(
            record
                .get("packet_context_kind")
                .expect("packet context kind should be present")
                .is_nothing()
        );
        assert!(
            !record
                .get("direct_packet_writes")
                .expect("direct packet writes should be present")
                .as_bool()
                .expect("direct packet writes should be a bool")
        );
    }

    #[test]
    fn test_spec_context_fields_preserve_tracepoint_payload_names() {
        let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
            .expect("tracepoint spec should parse");
        let fields = spec_context_fields(&spec);

        assert!(field(&fields, "cgroup").names.contains(&"current_cgroup"));
        assert!(
            !fields.iter().any(|field| field.names.contains(&"cgroup")),
            "ctx.cgroup is a tracepoint payload field name, so it must not be advertised as a builtin"
        );
    }

    fn tracepoint_field<'a>(
        fields: &'a [SpecTracepointField],
        field_name: &str,
    ) -> Option<&'a SpecTracepointField> {
        fields.iter().find(|field| field.name == field_name)
    }

    #[test]
    fn test_spec_tracepoint_fields_include_payload_fields_when_available() {
        let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
            .expect("tracepoint spec should parse");
        let (fields, err) = spec_tracepoint_fields(&spec, true);

        if fields.is_empty() {
            assert!(err.is_some(), "expected tracepoint fields or an error");
            return;
        }

        assert!(
            tracepoint_field(&fields, "filename").is_some()
                || tracepoint_field(&fields, "args").is_some(),
            "expected tracefs syscall fields or the well-known syscall fallback"
        );
        assert!(fields.iter().all(|field| !field.ty.is_empty()));
    }

    #[test]
    fn test_spec_tracepoint_fields_are_absent_for_non_tracepoints() {
        let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        let (fields, err) = spec_tracepoint_fields(&spec, true);

        assert!(fields.is_empty());
        assert!(err.is_none());
    }

    fn arg<'a>(args: &'a [SpecContextArg], arg_name: &str) -> &'a SpecContextArg {
        args.iter()
            .find(|arg| arg.name == arg_name)
            .unwrap_or_else(|| panic!("expected {arg_name} in spec context args"))
    }

    #[test]
    fn test_spec_context_args_include_pt_regs_slots() {
        let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
        let (args, err) = spec_context_args(&spec, true);

        assert!(err.is_none());
        assert_eq!(args.len(), 6);
        let arg0 = arg(&args, "arg0");
        assert_eq!(arg0.index, Some(0));
        assert_eq!(arg0.source, "pt_regs");
        assert_eq!(arg0.kind, "scalar");
        assert_eq!(arg0.ty.as_deref(), Some("u64"));
        assert!(arg0.supported);
    }

    #[test]
    fn test_spec_context_args_describe_raw_tracepoint_symbolic_args() {
        let spec = ProgramSpec::parse("raw_tracepoint:sys_enter")
            .expect("raw tracepoint spec should parse");
        let (args, err) = spec_context_args(&spec, true);

        assert!(err.is_none());
        let argn = arg(&args, "argN");
        assert_eq!(argn.index, None);
        assert_eq!(argn.source, "raw_tracepoint");
        assert_eq!(argn.ty.as_deref(), Some("u64"));
        assert!(argn.note.is_some());
        assert!(argn.unsupported_reason.is_none());
    }

    #[test]
    fn test_spec_context_args_include_btf_trampoline_metadata_when_available() {
        let spec =
            ProgramSpec::parse("fentry:security_file_open").expect("fentry spec should parse");
        let (args, err) = spec_context_args(&spec, true);

        let Some(file_arg) = args
            .iter()
            .find(|arg| arg.named_alias.as_deref() == Some("file"))
        else {
            assert!(
                err.is_some() || args.is_empty(),
                "expected named file arg metadata or an unavailable-BTF skip"
            );
            return;
        };

        assert_eq!(file_arg.name, "arg0");
        assert_eq!(file_arg.index, Some(0));
        assert_eq!(file_arg.source, "btf_trampoline");
        assert!(file_arg.supported);
        assert!(file_arg.ty.as_deref().is_some_and(|ty| ty.contains("file")));
    }

    #[test]
    fn test_spec_context_retval_includes_pt_regs_surface() {
        let spec = ProgramSpec::parse("kretprobe:sys_read").expect("kretprobe spec should parse");
        let (retval, err) = spec_context_retval(&spec, true);
        let retval = retval.expect("kretprobe should expose ctx.retval");

        assert!(err.is_none());
        assert_eq!(retval.name, "retval");
        assert_eq!(retval.source, "pt_regs");
        assert_eq!(retval.kind, "scalar");
        assert_eq!(retval.ty.as_deref(), Some("u64"));
        assert!(retval.supported);
    }

    #[test]
    fn test_spec_context_retval_is_absent_on_entry_probe() {
        let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
        let (retval, err) = spec_context_retval(&spec, true);

        assert!(retval.is_none());
        assert!(err.is_none());
    }

    #[test]
    fn test_spec_context_retval_includes_btf_trampoline_metadata_when_available() {
        let spec = ProgramSpec::parse("fexit:security_file_open").expect("fexit spec should parse");
        let (retval, err) = spec_context_retval(&spec, true);

        let Some(retval) = retval else {
            assert!(
                err.is_some(),
                "expected BTF retval metadata or an unavailable-BTF skip"
            );
            return;
        };

        assert_eq!(retval.name, "retval");
        assert_eq!(retval.source, "btf_trampoline");
        assert!(retval.supported);
        assert!(retval.ty.is_some());
    }

    #[test]
    fn test_context_write_records_filter_target_specific_writes() {
        let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
        let tc_ingress_writes = spec_context_writes(&tc_ingress);
        assert!(tc_ingress_writes.iter().any(|surface| {
            surface.field == "sk" && surface.kind == "assign-socket" && !surface.indexed
        }));

        let tc_egress = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
        let tc_egress_writes = spec_context_writes(&tc_egress);
        assert!(
            !tc_egress_writes.iter().any(|surface| surface.field == "sk"),
            "ctx.sk assignment should not be advertised on tc egress"
        );
    }
}
