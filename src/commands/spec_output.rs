//! Output model for `ebpf spec` records.

use nu_protocol::{Span, Value, record};

use crate::compiler::mir::{AddressSpace, CtxField, MirType};
use crate::compiler::{
    BpfHelper, ContextFieldCompatibilityRequirement, ContextFieldLoadGuard,
    KfuncCompatibilityRequirement, PacketContextKind, ProbeContext,
    ProgramCompatibilityRequirement, ProgramIntrinsic, ProgramValueAccess, SockOpsCallbackGuard,
    ctx_field_backing_helper, ctx_field_for_bpf_sock_projection_member, synthetic_bpf_sock_type,
    synthetic_bpf_tcp_sock_type,
};
use crate::kernel_btf::{TrampolineValueKind, TypeInfo};
use crate::program_spec::ProgramAttachShape;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextField {
    field: String,
    names: Vec<&'static str>,
    semantic_type: Option<String>,
    runtime_type: Option<String>,
    kernel_btf_runtime_type: Option<&'static str>,
    raw_context_pointer: bool,
    pointer_non_null: bool,
    trusted_btf_kernel_pointer: bool,
    backing_helper: Option<&'static str>,
    backing_helper_minimum_kernel: Option<&'static str>,
    backing_helper_minimum_kernel_source: Option<&'static str>,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
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
    helper: Option<&'static str>,
    helper_minimum_kernel: Option<&'static str>,
    helper_minimum_kernel_source: Option<&'static str>,
    kfunc: Option<&'static str>,
    kfunc_minimum_kernel: Option<&'static str>,
    kfunc_minimum_kernel_source: Option<&'static str>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextProjection {
    root: String,
    name: String,
    path: String,
    source: &'static str,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
    helper: Option<&'static str>,
    helper_minimum_kernel: Option<&'static str>,
    helper_minimum_kernel_source: Option<&'static str>,
    ty: String,
    offset: usize,
    bit_offset: Option<u32>,
    bit_size: Option<u32>,
    supported: bool,
    unsupported_reason: Option<String>,
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
    source: &'static str,
    source_path: Option<String>,
    context_struct: String,
    context_size: usize,
}

#[cfg(target_os = "linux")]
fn address_space_label(address_space: AddressSpace) -> &'static str {
    match address_space {
        AddressSpace::Stack => "stack",
        AddressSpace::Kernel => "kernel",
        AddressSpace::User => "user",
        AddressSpace::Packet => "packet",
        AddressSpace::Context => "context",
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
fn u64_value(value: u64, span: Span) -> Value {
    i64::try_from(value)
        .map(|value| Value::int(value, span))
        .unwrap_or_else(|_| Value::string(value.to_string(), span))
}

#[cfg(target_os = "linux")]
fn string_list(values: &[&'static str], span: Span) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::string(*value, span))
        .collect()
}

#[cfg(target_os = "linux")]
fn attach_shape_record(spec: &crate::program_spec::ProgramSpec, span: Span) -> Value {
    match spec.attach_shape() {
        ProgramAttachShape::Generic => Value::record(
            record! {
                "kind" => Value::string("generic", span),
            },
            span,
        ),
        ProgramAttachShape::Syscall => Value::record(
            record! {
                "kind" => Value::string("syscall", span),
            },
            span,
        ),
        ProgramAttachShape::Iter => Value::record(
            record! {
                "kind" => Value::string("iterator", span),
            },
            span,
        ),
        ProgramAttachShape::Xdp { mode, frags } => Value::record(
            record! {
                "kind" => Value::string("xdp", span),
                "mode" => Value::string(mode.key(), span),
                "frags" => Value::bool(frags, span),
            },
            span,
        ),
        ProgramAttachShape::PerfEvent {
            event,
            cpu,
            pid,
            sample_policy,
        } => Value::record(
            record! {
                "kind" => Value::string("perf-event", span),
                "source" => Value::string(event.source_name(), span),
                "event" => Value::string(event.event_name(), span),
                "cpu" => optional_u32(cpu, span),
                "pid" => optional_u32(pid, span),
                "sample_policy" => Value::string(sample_policy.key(), span),
                "sample_value" => u64_value(sample_policy.value(), span),
                "default_sample" => Value::bool(sample_policy.is_default(), span),
            },
            span,
        ),
        ProgramAttachShape::SocketFilter { socket_kind } => Value::record(
            record! {
                "kind" => Value::string("socket-filter", span),
                "socket_kind" => Value::string(socket_kind.name(), span),
                "transport" => Value::string(socket_kind.transport_key(), span),
                "family" => Value::string(socket_kind.address_family().key(), span),
            },
            span,
        ),
        ProgramAttachShape::SkLookup => Value::record(
            record! {
                "kind" => Value::string("sk-lookup", span),
                "scope" => Value::string("netns", span),
            },
            span,
        ),
        ProgramAttachShape::FlowDissector => Value::record(
            record! {
                "kind" => Value::string("flow-dissector", span),
                "scope" => Value::string("netns", span),
            },
            span,
        ),
        ProgramAttachShape::SkMsg => Value::record(
            record! {
                "kind" => Value::string("sk-msg", span),
                "resource" => Value::string("socket-map", span),
            },
            span,
        ),
        ProgramAttachShape::SkSkb { parser } => Value::record(
            record! {
                "kind" => Value::string("sk-skb", span),
                "hook" => Value::string(if parser { "parser" } else { "verdict" }, span),
                "parser" => Value::bool(parser, span),
                "resource" => Value::string("socket-map", span),
            },
            span,
        ),
        ProgramAttachShape::Netkit { endpoint } => Value::record(
            record! {
                "kind" => Value::string("netkit", span),
                "endpoint" => Value::string(endpoint.key(), span),
                "primary" => Value::bool(matches!(endpoint, crate::program_spec::NetkitAttachType::Primary), span),
            },
            span,
        ),
        ProgramAttachShape::TcAction => Value::record(
            record! {
                "kind" => Value::string("tc-action", span),
            },
            span,
        ),
        ProgramAttachShape::SkReuseport { mode } => Value::record(
            record! {
                "kind" => Value::string("sk-reuseport", span),
                "mode" => Value::string(mode.target_name(), span),
            },
            span,
        ),
        ProgramAttachShape::Lwt { hook } => Value::record(
            record! {
                "kind" => Value::string("lwt", span),
                "hook" => Value::string(hook.key(), span),
            },
            span,
        ),
        ProgramAttachShape::Netfilter {
            family,
            hook,
            priority,
            defrag,
        } => Value::record(
            record! {
                "kind" => Value::string("netfilter", span),
                "family" => Value::string(family.target_name(), span),
                "hook" => Value::string(hook.target_name(), span),
                "priority" => Value::int(i64::from(priority), span),
                "defrag" => Value::bool(defrag, span),
            },
            span,
        ),
        ProgramAttachShape::Tc { ingress } => Value::record(
            record! {
                "kind" => Value::string("tc", span),
                "direction" => Value::string(if ingress { "ingress" } else { "egress" }, span),
                "ingress" => Value::bool(ingress, span),
            },
            span,
        ),
        ProgramAttachShape::CgroupSkb { ingress } => Value::record(
            record! {
                "kind" => Value::string("cgroup-skb", span),
                "direction" => Value::string(if ingress { "ingress" } else { "egress" }, span),
                "ingress" => Value::bool(ingress, span),
            },
            span,
        ),
        ProgramAttachShape::CgroupDevice => Value::record(
            record! {
                "kind" => Value::string("cgroup-device", span),
                "resource" => Value::string("cgroup", span),
            },
            span,
        ),
        ProgramAttachShape::CgroupSysctl => Value::record(
            record! {
                "kind" => Value::string("cgroup-sysctl", span),
                "resource" => Value::string("cgroup", span),
            },
            span,
        ),
        ProgramAttachShape::SockOps => Value::record(
            record! {
                "kind" => Value::string("sock-ops", span),
                "resource" => Value::string("cgroup", span),
            },
            span,
        ),
        ProgramAttachShape::CgroupSock { post_bind, family } => Value::record(
            record! {
                "kind" => Value::string("cgroup-sock", span),
                "phase" => Value::string(if post_bind { "post-bind" } else { "create-release" }, span),
                "post_bind" => Value::bool(post_bind, span),
                "family" => optional_static_str(family.map(|family| family.key()), span),
            },
            span,
        ),
        ProgramAttachShape::CgroupSockopt { get } => Value::record(
            record! {
                "kind" => Value::string("cgroup-sockopt", span),
                "operation" => Value::string(if get { "get" } else { "set" }, span),
            },
            span,
        ),
        ProgramAttachShape::CgroupSockAddr { family, hook } => Value::record(
            record! {
                "kind" => Value::string("cgroup-sock-addr", span),
                "family" => Value::string(family.key(), span),
                "hook" => Value::string(hook.key(), span),
            },
            span,
        ),
        ProgramAttachShape::LircMode2 => Value::record(
            record! {
                "kind" => Value::string("lirc-mode2", span),
                "resource" => Value::string("lirc-device", span),
            },
            span,
        ),
        ProgramAttachShape::StructOps { family } => Value::record(
            record! {
                "kind" => Value::string("struct-ops", span),
                "family" => Value::string(family.key(), span),
            },
            span,
        ),
        ProgramAttachShape::StructOpsCallback { family, sleepable } => Value::record(
            record! {
                "kind" => Value::string("struct-ops-callback", span),
                "family" => Value::string(family.key(), span),
                "sleepable" => Value::bool(sleepable, span),
            },
            span,
        ),
    }
}

#[cfg(target_os = "linux")]
fn dynamic_context_field_type_labels(
    spec: &crate::program_spec::ProgramSpec,
    field: &CtxField,
    resolve_dynamic_fields: bool,
) -> Option<(String, String)> {
    match field {
        CtxField::RetVal => match spec.program_type().retval_access() {
            ProgramValueAccess::PtRegs => Some(("u64".to_string(), "u64".to_string())),
            ProgramValueAccess::Trampoline if resolve_dynamic_fields => {
                let ctx = ProbeContext::from_program_spec(spec.clone());
                let type_info = ctx.btf_ret_type_info().ok().flatten()?;
                let value = ctx.btf_ret_spec().ok().flatten()?;
                let semantic_type = type_info_label(&type_info);
                let runtime_type = match value.kind {
                    TrampolineValueKind::Aggregate { .. } => {
                        format!("ptr<stack, {semantic_type}>")
                    }
                    TrampolineValueKind::Scalar | TrampolineValueKind::Pointer { .. } => {
                        semantic_type.clone()
                    }
                };
                Some((semantic_type, runtime_type))
            }
            _ => None,
        },
        CtxField::KStack | CtxField::UStack => Some(("i64".to_string(), "i64".to_string())),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn spec_context_fields(
    spec: &crate::program_spec::ProgramSpec,
    resolve_dynamic_fields: bool,
) -> Vec<SpecContextField> {
    let mut fields: Vec<(crate::compiler::mir::CtxField, SpecContextField)> = Vec::new();
    let target = spec.target_string();

    for entry in spec.program_type().ctx_field_name_entries() {
        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        if let Some((_, field)) = fields.iter_mut().find(|(field, _)| field == &entry.field) {
            field.names.push(entry.name);
        } else {
            let type_spec = spec.ctx_field_type_spec(&entry.field);
            let dynamic_type_labels =
                dynamic_context_field_type_labels(spec, &entry.field, resolve_dynamic_fields);
            let load_guard = spec.ctx_field_load_guard(&entry.field);
            let backing_helper = ctx_field_backing_helper(&entry.field);
            let compatibility_requirement =
                ContextFieldCompatibilityRequirement::for_field_on_program_target(
                    &entry.field,
                    Some(spec.program_type()),
                    Some(target.as_str()),
                );
            fields.push((
                entry.field.clone(),
                SpecContextField {
                    field: entry.field.display_name(),
                    names: vec![entry.name],
                    semantic_type: type_spec
                        .as_ref()
                        .map(|type_spec| mir_type_label(&type_spec.semantic_ty))
                        .or_else(|| dynamic_type_labels.as_ref().map(|(ty, _)| ty.clone())),
                    runtime_type: type_spec
                        .as_ref()
                        .map(|type_spec| mir_type_label(&type_spec.runtime_ty))
                        .or_else(|| dynamic_type_labels.as_ref().map(|(_, ty)| ty.clone())),
                    kernel_btf_runtime_type: type_spec
                        .as_ref()
                        .and_then(|type_spec| type_spec.kernel_btf_runtime_type_name),
                    raw_context_pointer: spec.ctx_field_is_raw_context_pointer(&entry.field),
                    pointer_non_null: spec.ctx_field_pointer_is_non_null(&entry.field),
                    trusted_btf_kernel_pointer: spec
                        .ctx_field_is_trusted_btf_kernel_pointer(&entry.field),
                    backing_helper: backing_helper.map(BpfHelper::name),
                    backing_helper_minimum_kernel: backing_helper
                        .and_then(BpfHelper::minimum_kernel),
                    backing_helper_minimum_kernel_source: backing_helper
                        .and_then(BpfHelper::minimum_kernel_source),
                    minimum_kernel: compatibility_requirement
                        .as_ref()
                        .map(ContextFieldCompatibilityRequirement::minimum_kernel),
                    minimum_kernel_source: compatibility_requirement
                        .as_ref()
                        .map(ContextFieldCompatibilityRequirement::minimum_kernel_source),
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
fn context_field_records(
    spec: &crate::program_spec::ProgramSpec,
    span: Span,
    resolve_dynamic_fields: bool,
) -> Vec<Value> {
    spec_context_fields(spec, resolve_dynamic_fields)
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
                    "raw_context_pointer" => Value::bool(field.raw_context_pointer, span),
                    "pointer_non_null" => Value::bool(field.pointer_non_null, span),
                    "trusted_btf_kernel_pointer" => Value::bool(field.trusted_btf_kernel_pointer, span),
                    "backing_helper" => optional_static_str(field.backing_helper, span),
                    "backing_helper_minimum_kernel" => optional_static_str(field.backing_helper_minimum_kernel, span),
                    "backing_helper_minimum_kernel_source" => optional_static_str(field.backing_helper_minimum_kernel_source, span),
                    "minimum_kernel" => optional_static_str(field.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(field.minimum_kernel_source, span),
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
fn spec_context_projections(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextProjection> {
    let mut projections = Vec::new();
    let mut seen_roots = Vec::new();
    let target = spec.target_string();

    for entry in spec.program_type().ctx_field_name_entries() {
        if spec.ctx_field_access_error(&entry.field).is_some() || seen_roots.contains(&entry.field)
        {
            continue;
        }
        seen_roots.push(entry.field.clone());

        let Some(type_spec) = spec.ctx_field_type_spec(&entry.field) else {
            continue;
        };
        let MirType::Ptr { pointee, .. } = type_spec.semantic_ty else {
            continue;
        };
        let MirType::Struct { fields, .. } = *pointee else {
            continue;
        };

        let root = entry.field.display_name();
        for field in fields.into_iter().filter(|field| !field.synthetic) {
            let unsupported_reason = match entry.field {
                CtxField::Socket => spec.socket_projection_access_error(&field.name),
                _ => None,
            };
            if unsupported_reason.is_some() {
                continue;
            }
            let compatibility_requirement = context_projection_compatibility_requirement(
                spec,
                &target,
                &entry.field,
                &field.name,
            );
            projections.push(SpecContextProjection {
                root: root.clone(),
                path: format!("{root}.{}", field.name),
                name: field.name,
                source: "context_field",
                minimum_kernel: compatibility_requirement
                    .as_ref()
                    .map(ContextFieldCompatibilityRequirement::minimum_kernel),
                minimum_kernel_source: compatibility_requirement
                    .as_ref()
                    .map(ContextFieldCompatibilityRequirement::minimum_kernel_source),
                helper: None,
                helper_minimum_kernel: None,
                helper_minimum_kernel_source: None,
                ty: mir_type_label(&field.ty),
                offset: field.offset,
                bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
                bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
                supported: true,
                unsupported_reason: None,
            });
        }

        if matches!(entry.field, CtxField::Socket) {
            push_helper_backed_socket_projections(spec, &mut projections);
        }
    }

    projections
}

#[cfg(target_os = "linux")]
fn context_projection_compatibility_requirement(
    spec: &crate::program_spec::ProgramSpec,
    target: &str,
    root_field: &CtxField,
    member: &str,
) -> Option<ContextFieldCompatibilityRequirement> {
    let mut effective = ContextFieldCompatibilityRequirement::for_field_on_program_target(
        root_field,
        Some(spec.program_type()),
        Some(target),
    );

    if matches!(root_field, CtxField::Socket | CtxField::MigratingSocket) {
        if let Some(member_field) = ctx_field_for_bpf_sock_projection_member(member) {
            let member_requirement =
                ContextFieldCompatibilityRequirement::for_field_on_program_target(
                    &member_field,
                    Some(spec.program_type()),
                    Some(target),
                );
            if let Some(member_requirement) = member_requirement {
                let should_replace = match effective.as_ref() {
                    Some(current) => ContextFieldCompatibilityRequirement::kernel_version_at_least(
                        member_requirement.minimum_kernel(),
                        current.minimum_kernel(),
                    ),
                    None => true,
                };
                if should_replace {
                    effective = Some(member_requirement);
                }
            }
        }
    }

    effective
}

#[cfg(target_os = "linux")]
fn push_struct_field_projections(
    projections: &mut Vec<SpecContextProjection>,
    root: &str,
    source: &'static str,
    helper: Option<BpfHelper>,
    ty: MirType,
    unsupported_reason: Option<String>,
) {
    let MirType::Struct { fields, .. } = ty else {
        return;
    };
    if unsupported_reason.is_some() {
        return;
    }
    let helper_name = helper.map(BpfHelper::name);
    let helper_minimum_kernel = helper.and_then(BpfHelper::minimum_kernel);
    let helper_minimum_kernel_source = helper.and_then(BpfHelper::minimum_kernel_source);

    for field in fields.into_iter().filter(|field| !field.synthetic) {
        projections.push(SpecContextProjection {
            root: root.to_string(),
            path: format!("{root}.{}", field.name),
            name: field.name,
            source,
            minimum_kernel: None,
            minimum_kernel_source: None,
            helper: helper_name,
            helper_minimum_kernel,
            helper_minimum_kernel_source,
            ty: mir_type_label(&field.ty),
            offset: field.offset,
            bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
            bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
            supported: true,
            unsupported_reason: None,
        });
    }
}

#[cfg(target_os = "linux")]
fn push_helper_backed_socket_projections(
    spec: &crate::program_spec::ProgramSpec,
    projections: &mut Vec<SpecContextProjection>,
) {
    for (root, helper, ty) in [
        ("sk.tcp", BpfHelper::TcpSock, synthetic_bpf_tcp_sock_type()),
        ("sk.full", BpfHelper::SkFullsock, synthetic_bpf_sock_type()),
        (
            "sk.listener",
            BpfHelper::GetListenerSock,
            synthetic_bpf_sock_type(),
        ),
    ] {
        push_struct_field_projections(
            projections,
            root,
            "helper_return",
            Some(helper),
            ty,
            spec.helper_call_error(helper),
        );
    }
}

#[cfg(target_os = "linux")]
fn context_projection_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_context_projections(spec)
        .into_iter()
        .map(|projection| {
            Value::record(
                record! {
                    "root" => Value::string(projection.root, span),
                    "name" => Value::string(projection.name, span),
                    "path" => Value::string(projection.path, span),
                    "source" => Value::string(projection.source, span),
                    "minimum_kernel" => optional_static_str(projection.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(projection.minimum_kernel_source, span),
                    "helper" => optional_static_str(projection.helper, span),
                    "helper_minimum_kernel" => optional_static_str(projection.helper_minimum_kernel, span),
                    "helper_minimum_kernel_source" => optional_static_str(projection.helper_minimum_kernel_source, span),
                    "type" => Value::string(projection.ty, span),
                    "offset" => optional_usize(Some(projection.offset), span),
                    "bit_offset" => optional_u32(projection.bit_offset, span),
                    "bit_size" => optional_u32(projection.bit_size, span),
                    "supported" => Value::bool(projection.supported, span),
                    "unsupported_reason" => optional_string(projection.unsupported_reason, span),
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
        Ok(Some(tracepoint)) => {
            let source = tracepoint.source.label();
            let source_path = tracepoint.source_path.clone();
            let context_struct = tracepoint.struct_name.clone();
            let context_size = tracepoint.size;
            (
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
                        source,
                        source_path: source_path.clone(),
                        context_struct: context_struct.clone(),
                        context_size,
                    })
                    .collect(),
                None,
            )
        }
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
                    "source" => Value::string(field.source, span),
                    "source_path" => optional_string(field.source_path, span),
                    "context_struct" => Value::string(field.context_struct, span),
                    "context_size" => optional_usize(Some(field.context_size), span),
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
        .map(|surface| {
            let kfunc_requirement = surface
                .kfunc
                .and_then(KfuncCompatibilityRequirement::for_name);
            SpecContextWrite {
                field: surface.field_name,
                kind: surface.kind,
                indexed: surface.indexed,
                helper: surface.helper.map(BpfHelper::name),
                helper_minimum_kernel: surface.helper.and_then(BpfHelper::minimum_kernel),
                helper_minimum_kernel_source: surface
                    .helper
                    .and_then(BpfHelper::minimum_kernel_source),
                kfunc: surface.kfunc,
                kfunc_minimum_kernel: kfunc_requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel()),
                kfunc_minimum_kernel_source: kfunc_requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel_source()),
            }
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
                    "helper" => optional_static_str(surface.helper, span),
                    "helper_minimum_kernel" => optional_static_str(surface.helper_minimum_kernel, span),
                    "helper_minimum_kernel_source" => optional_static_str(surface.helper_minimum_kernel_source, span),
                    "kfunc" => optional_static_str(surface.kfunc, span),
                    "kfunc_minimum_kernel" => optional_static_str(surface.kfunc_minimum_kernel, span),
                    "kfunc_minimum_kernel_source" => optional_static_str(surface.kfunc_minimum_kernel_source, span),
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
    let kernel_target_validation = program_type
        .kernel_target_validation()
        .map(|validation| validation.key());
    let btf_callable_surface = program_type
        .btf_callable_surface()
        .map(|surface| surface.key());
    let context_fields = context_field_records(&spec, span, resolve_dynamic_args);
    let (tracepoint_fields, tracepoint_field_error) =
        spec_tracepoint_fields(&spec, resolve_dynamic_args);
    let tracepoint_fields = tracepoint_field_records(tracepoint_fields, span);
    let (context_args, context_arg_error) = spec_context_args(&spec, resolve_dynamic_args);
    let context_args = context_arg_records(context_args, span);
    let (context_retval, context_retval_error) = spec_context_retval(&spec, resolve_dynamic_args);
    let context_retval = context_retval_record(context_retval, span);
    let context_writes = context_write_records(&spec, span);
    let context_projections = context_projection_records(&spec, span);
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
    let intrinsics = ProgramIntrinsic::all()
        .iter()
        .filter(|intrinsic| program_type.supports_intrinsic(**intrinsic))
        .map(|intrinsic| {
            let capability = intrinsic.required_capability();
            Value::record(
                record! {
                    "command" => Value::string(intrinsic.command_name(), span),
                    "capability" => Value::string(capability.key(), span),
                    "capability_description" => Value::string(capability.description(), span),
                },
                span,
            )
        })
        .collect();
    let compatibility_requirements = spec.compatibility_requirements();
    let compatibility_minimum_kernel =
        ProgramCompatibilityRequirement::effective_minimum_kernel(&compatibility_requirements);
    let requirements = compatibility_requirements
        .iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "key" => Value::string(requirement.key(), span),
                    "description" => Value::string(requirement.description(), span),
                    "category" => Value::string(requirement.category(), span),
                    "default_test_lane" => Value::string(requirement.default_test_lane(), span),
                    "minimum_kernel" => optional_static_str(requirement.minimum_kernel(), span),
                    "minimum_kernel_source" => optional_static_str(requirement.minimum_kernel_source(), span),
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
            "spec_aliases" => Value::list(string_list(program_type.spec_aliases(), span), span),
            "kernel_program_type" => Value::string(program_type.kernel_prog_type(), span),
            "context_family" => Value::string(program_type.context_family().key(), span),
            "packet_context_kind" => optional_packet_context_kind(spec.packet_context_kind(), span),
            "data_meta_context_kind" => optional_packet_context_kind(spec.data_meta_context_kind(), span),
            "direct_packet_writes" => Value::bool(spec.supports_direct_packet_writes(), span),
            "target" => Value::string(spec.target_string(), span),
            "section" => Value::string(spec.section_name(), span),
            "section_prefix" => Value::string(program_type.section_prefix(), span),
            "section_uses_target" => Value::bool(program_type.section_uses_target(), span),
            "attach_kind" => Value::string(attach_kind.key(), span),
            "attach_shape" => attach_shape_record(&spec, span),
            "target_kind" => Value::string(program_type.target_kind().key(), span),
            "kernel_target_validation" => optional_static_str(kernel_target_validation, span),
            "btf_callable_surface" => optional_static_str(btf_callable_surface, span),
            "sleepable" => Value::bool(spec.sleepable(), span),
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
            "context_projections" => Value::list(context_projections, span),
            "capabilities" => Value::list(capabilities, span),
            "intrinsics" => Value::list(intrinsics, span),
            "compatibility_requirements" => Value::list(requirements, span),
            "compatibility_minimum_kernel" => optional_static_str(compatibility_minimum_kernel, span),
            "return_aliases" => Value::list(return_aliases, span),
        },
        span,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
