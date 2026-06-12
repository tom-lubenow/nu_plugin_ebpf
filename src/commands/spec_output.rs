//! Output model for `ebpf spec` records.

use nu_protocol::{Span, Value, record};

use crate::compiler::instruction::{
    KfuncArgKind, KfuncRetKind, KfuncSignature, kfunc_acquire_ref_kind, kfunc_pointer_arg_ref_kind,
    kfunc_release_ref_arg_index, kfunc_release_ref_kind, kfunc_semantics,
};
use crate::compiler::mir::{AddressSpace, CtxField, MirType, StructField};
use crate::compiler::packet_layout::PacketHeaderKind;
use crate::compiler::{
    BpfHelper, ContextFieldCompatibilityRequirement, ContextFieldDirectLoadWidth,
    ContextFieldLoadGuard, ContextFieldReadTransform, HelperCompatibilityRequirement, MapKind,
    PacketContextKind, ProbeContext, ProgramCompatibilityRequirement, ProgramIntrinsic,
    ProgramValueAccess, SockOpsCallbackGuard, bpf_flow_keys_projection_member_aliases,
    bpf_sock_projection_member_aliases, ctx_field_backing_helper,
    ctx_field_for_bpf_sock_projection_member, synthetic_bpf_sock_type, synthetic_bpf_tcp_sock_type,
};
use crate::kernel_btf::{
    TracepointContext, TracepointContextSource, TrampolineValueKind, TypeInfo,
};
use crate::program_spec::{ProgramAttachShape, ProgramSpec};

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextField {
    field: String,
    names: Vec<&'static str>,
    abi_field: Option<String>,
    semantic_type: Option<String>,
    runtime_type: Option<String>,
    kernel_btf_runtime_type: Option<&'static str>,
    raw_context_pointer: bool,
    pointer_non_null: bool,
    trusted_btf_kernel_pointer: bool,
    compatibility_minimum_kernel: Option<&'static str>,
    compatibility_minimum_kernel_source: Option<&'static str>,
    backing_helper: Option<&'static str>,
    backing_helper_requirement_key: Option<String>,
    backing_helper_minimum_kernel: Option<&'static str>,
    backing_helper_minimum_kernel_source: Option<&'static str>,
    requirement_key: Option<String>,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
    load_guard: Option<&'static str>,
    load_guard_witness: Option<String>,
    load_guard_description: Option<String>,
    load_kind: Option<&'static str>,
    direct_load_width: Option<&'static str>,
    direct_load_offset: Option<i16>,
    direct_load_transform: Option<&'static str>,
    array_load_base_offset: Option<i16>,
    array_load_count: Option<usize>,
    array_load_normalize_big_endian: Option<bool>,
    array_load_transform: Option<&'static str>,
    nested_load_pointer_offset: Option<i16>,
    nested_load_width: Option<&'static str>,
    nested_load_field_offset: Option<i16>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextWrite {
    field: &'static str,
    kind: &'static str,
    indexed: bool,
    abi_field: Option<String>,
    direct_store_offset: Option<i16>,
    indexed_store_base_offset: Option<i16>,
    indexed_store_count: Option<usize>,
    indexed_store_convert_to_big_endian: Option<bool>,
    transformed_store_offset: Option<i16>,
    transformed_store_transform: Option<&'static str>,
    compatibility_minimum_kernel: Option<&'static str>,
    compatibility_minimum_kernel_source: Option<&'static str>,
    context_field_requirement_key: Option<String>,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
    helper: Option<&'static str>,
    helper_requirement_key: Option<String>,
    helper_minimum_kernel: Option<&'static str>,
    helper_minimum_kernel_source: Option<&'static str>,
    kfunc: Option<&'static str>,
    kfunc_requirement_key: Option<String>,
    kfunc_minimum_kernel: Option<&'static str>,
    kfunc_minimum_kernel_source: Option<&'static str>,
    kfunc_maximum_kernel_exclusive: Option<&'static str>,
    kfunc_maximum_kernel_exclusive_source: Option<&'static str>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecKfuncCall {
    kfunc: &'static str,
    policy: &'static str,
    note: &'static str,
    min_args: Option<usize>,
    max_args: Option<usize>,
    arg_kinds: Vec<&'static str>,
    return_kind: Option<&'static str>,
    requirement_key: Option<String>,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
    maximum_kernel_exclusive: Option<&'static str>,
    maximum_kernel_exclusive_source: Option<&'static str>,
    acquire_ref_kind: Option<&'static str>,
    release_ref_kind: Option<&'static str>,
    release_arg_idx: Option<usize>,
    pointer_arg_ref_kinds: Vec<SpecKfuncArgRefKind>,
    pointer_arg_rules: Vec<SpecKfuncPtrArgRule>,
    positive_size_args: Vec<usize>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecKfuncArgRefKind {
    arg_idx: usize,
    ref_kind: &'static str,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecKfuncPtrArgRule {
    arg_idx: usize,
    op: &'static str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    fixed_size: Option<usize>,
    size_from_arg: Option<usize>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextProjection {
    root: String,
    name: String,
    path: String,
    source: &'static str,
    compatibility_minimum_kernel: Option<&'static str>,
    compatibility_minimum_kernel_source: Option<&'static str>,
    context_field_requirement_key: Option<String>,
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
    helper: Option<&'static str>,
    helper_requirement_key: Option<String>,
    helper_minimum_kernel: Option<&'static str>,
    helper_minimum_kernel_source: Option<&'static str>,
    read_helper: Option<&'static str>,
    read_helper_requirement_key: Option<String>,
    read_helper_minimum_kernel: Option<&'static str>,
    read_helper_minimum_kernel_source: Option<&'static str>,
    ty: String,
    offset: Option<usize>,
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
    minimum_kernel: Option<&'static str>,
    minimum_kernel_source: Option<&'static str>,
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
fn context_field_direct_load_width_label(width: ContextFieldDirectLoadWidth) -> &'static str {
    match width {
        ContextFieldDirectLoadWidth::U8 => "u8",
        ContextFieldDirectLoadWidth::U16 => "u16",
        ContextFieldDirectLoadWidth::U32 => "u32",
        ContextFieldDirectLoadWidth::U64 => "u64",
    }
}

#[cfg(target_os = "linux")]
fn context_field_read_transform_label(transform: ContextFieldReadTransform) -> &'static str {
    match transform {
        ContextFieldReadTransform::BigEndianU16ToHost => "big-endian-u16-to-host",
        ContextFieldReadTransform::BigEndianU32ToHost => "big-endian-u32-to-host",
        ContextFieldReadTransform::BigEndianU32WordsToHost => "big-endian-u32-words-to-host",
        ContextFieldReadTransform::BigEndianU32PortToHost => "big-endian-u32-port-to-host",
        ContextFieldReadTransform::LircValueMask => "low-24-bits",
        ContextFieldReadTransform::LircModeMask => "high-byte-mask",
        ContextFieldReadTransform::CgroupDeviceAccessShift => "access-type-high-16-bits",
        ContextFieldReadTransform::CgroupDeviceTypeMask => "access-type-low-16-bits",
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
fn optional_bool(value: Option<bool>, span: Span) -> Value {
    value
        .map(|value| Value::bool(value, span))
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
fn optional_i16(value: Option<i16>, span: Span) -> Value {
    value
        .map(|value| Value::int(i64::from(value), span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn optional_u32(value: Option<u32>, span: Span) -> Value {
    value
        .map(|value| Value::int(i64::from(value), span))
        .unwrap_or_else(|| Value::nothing(span))
}

#[cfg(target_os = "linux")]
fn helper_requirement_key(helper: BpfHelper) -> Option<String> {
    HelperCompatibilityRequirement::for_helper(helper).map(HelperCompatibilityRequirement::key)
}

#[cfg(target_os = "linux")]
fn kfunc_arg_kind_label(kind: KfuncArgKind) -> &'static str {
    match kind {
        KfuncArgKind::Scalar => "scalar",
        KfuncArgKind::Pointer => "pointer",
        KfuncArgKind::Subprogram => "subprogram",
    }
}

#[cfg(target_os = "linux")]
fn kfunc_ret_kind_label(kind: KfuncRetKind) -> &'static str {
    match kind {
        KfuncRetKind::Scalar => "scalar",
        KfuncRetKind::PointerMaybeNull => "pointer-maybe-null",
        KfuncRetKind::Void => "void",
    }
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
fn packet_header_field_records(header: PacketHeaderKind, span: Span) -> Vec<Value> {
    header
        .fields()
        .iter()
        .copied()
        .map(|field| {
            let bitfield = field.bitfield;
            Value::record(
                record! {
                    "name" => Value::string(field.name, span),
                    "names" => Value::list({
                        let mut names = Vec::with_capacity(1 + field.aliases.len());
                        names.push(Value::string(field.name, span));
                        names.extend(field.aliases.iter().map(|alias| Value::string(*alias, span)));
                        names
                    }, span),
                    "semantic_type" => Value::string(mir_type_label(&field.ty.mir_type()), span),
                    "offset" => optional_usize(Some(field.offset), span),
                    "packet_big_endian" => Value::bool(field.big_endian, span),
                    "bit_offset" => optional_u32(bitfield.map(|bitfield| bitfield.bit_offset), span),
                    "bit_size" => optional_u32(bitfield.map(|bitfield| bitfield.bit_size), span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn packet_header_protocol_view_records(header: PacketHeaderKind, span: Span) -> Vec<Value> {
    header
        .protocol_views()
        .map(|view| {
            Value::record(
                record! {
                    "header" => Value::string(view.to.key(), span),
                    "type_name" => Value::string(view.to.type_name(), span),
                    "names" => Value::list(string_list(view.to.aliases(), span), span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn packet_header_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    if spec.packet_context_kind().is_none() {
        return Vec::new();
    }

    PacketHeaderKind::all()
        .iter()
        .copied()
        .map(|header| {
            Value::record(
                record! {
                    "header" => Value::string(header.key(), span),
                    "type_name" => Value::string(header.type_name(), span),
                    "names" => Value::list(string_list(header.aliases(), span), span),
                    "payload_step" => Value::bool(header.supports_payload_step(), span),
                    "protocol_views" => Value::list(packet_header_protocol_view_records(header, span), span),
                    "fields" => Value::list(packet_header_field_records(header, span), span),
                },
                span,
            )
        })
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
        ProgramAttachShape::Iter { target_kind } => Value::record(
            record! {
                "kind" => Value::string("iterator", span),
                "target_kind" => optional_static_str(target_kind.map(|kind| kind.key()), span),
            },
            span,
        ),
        ProgramAttachShape::Xdp {
            target_kind,
            mode,
            frags,
        } => Value::record(
            record! {
                "kind" => Value::string("xdp", span),
                "target_kind" => Value::string(target_kind.key(), span),
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
        ProgramAttachShape::Lsm {
            sleepable,
            sleepable_hook,
        } => Value::record(
            record! {
                "kind" => Value::string("lsm", span),
                "hook" => Value::string(spec.target_string(), span),
                "sleepable" => Value::bool(sleepable, span),
                "sleepable_hook" => Value::bool(sleepable_hook, span),
            },
            span,
        ),
        ProgramAttachShape::LsmCgroup { sleepable_hook } => {
            let hook = match spec {
                ProgramSpec::LsmCgroup { target } => target.hook.clone(),
                _ => spec.target_string(),
            };
            Value::record(
                record! {
                    "kind" => Value::string("lsm-cgroup", span),
                    "hook" => Value::string(hook, span),
                    "sleepable" => Value::bool(false, span),
                    "sleepable_hook" => Value::bool(sleepable_hook, span),
                },
                span,
            )
        }
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
                "value_type" => Value::string(spec.struct_ops_value_type_name().unwrap_or(""), span),
            },
            span,
        ),
        ProgramAttachShape::StructOpsCallback { family, sleepable } => Value::record(
            record! {
                "kind" => Value::string("struct-ops-callback", span),
                "family" => Value::string(family.key(), span),
                "value_type" => Value::string(spec.struct_ops_value_type_name().unwrap_or(""), span),
                "callback" => Value::string(spec.struct_ops_callback_name().unwrap_or(""), span),
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
        CtxField::RetVal => match spec.retval_access() {
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
                ContextFieldCompatibilityRequirement::for_field_on_program_spec(&entry.field, spec);
            let compatibility_floor = context_surface_compatibility_floor(
                compatibility_requirement.as_ref(),
                backing_helper,
            );
            let direct_load = spec.ctx_field_direct_load(&entry.field);
            let direct_load_transform =
                direct_load.and_then(|_| spec.ctx_field_direct_load_transform(&entry.field));
            let array_load = spec.ctx_field_array_load(&entry.field);
            let array_load_transform =
                array_load.and_then(|_| spec.ctx_field_array_load_transform(&entry.field));
            let nested_load = spec.ctx_field_nested_load(&entry.field);
            let load_kind = if direct_load.is_some() {
                Some("direct")
            } else if array_load.is_some() {
                Some("array")
            } else if nested_load.is_some() {
                Some("nested")
            } else {
                None
            };
            let abi_field = load_kind.and_then(|_| {
                spec.ctx_field_abi_field(&entry.field)
                    .map(|field| field.display_name())
            });
            fields.push((
                entry.field.clone(),
                SpecContextField {
                    field: entry.field.display_name(),
                    names: vec![entry.name],
                    abi_field,
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
                    compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
                    compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
                    backing_helper: backing_helper.map(BpfHelper::name),
                    backing_helper_requirement_key: backing_helper.and_then(helper_requirement_key),
                    backing_helper_minimum_kernel: backing_helper
                        .and_then(BpfHelper::minimum_kernel),
                    backing_helper_minimum_kernel_source: backing_helper
                        .and_then(BpfHelper::minimum_kernel_source),
                    requirement_key: compatibility_requirement
                        .as_ref()
                        .map(ContextFieldCompatibilityRequirement::key),
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
                    load_kind,
                    direct_load_width: direct_load
                        .map(|load| context_field_direct_load_width_label(load.width)),
                    direct_load_offset: direct_load.map(|load| load.offset),
                    direct_load_transform: direct_load_transform
                        .map(context_field_read_transform_label),
                    array_load_base_offset: array_load.map(|load| load.base_offset),
                    array_load_count: array_load.map(|load| load.count),
                    array_load_normalize_big_endian: array_load
                        .map(|load| load.normalize_big_endian),
                    array_load_transform: array_load_transform
                        .map(context_field_read_transform_label),
                    nested_load_pointer_offset: nested_load.map(|load| load.pointer_offset),
                    nested_load_width: nested_load
                        .map(|load| context_field_direct_load_width_label(load.field_load.width)),
                    nested_load_field_offset: nested_load.map(|load| load.field_load.offset),
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
                    "abi_field" => optional_string(field.abi_field, span),
                    "semantic_type" => optional_string(field.semantic_type, span),
                    "runtime_type" => optional_string(field.runtime_type, span),
                    "kernel_btf_runtime_type" => optional_static_str(field.kernel_btf_runtime_type, span),
                    "raw_context_pointer" => Value::bool(field.raw_context_pointer, span),
                    "pointer_non_null" => Value::bool(field.pointer_non_null, span),
                    "trusted_btf_kernel_pointer" => Value::bool(field.trusted_btf_kernel_pointer, span),
                    "compatibility_minimum_kernel" => optional_static_str(field.compatibility_minimum_kernel, span),
                    "compatibility_minimum_kernel_source" => optional_static_str(field.compatibility_minimum_kernel_source, span),
                    "backing_helper" => optional_static_str(field.backing_helper, span),
                    "backing_helper_requirement_key" => optional_string(field.backing_helper_requirement_key, span),
                    "backing_helper_minimum_kernel" => optional_static_str(field.backing_helper_minimum_kernel, span),
                    "backing_helper_minimum_kernel_source" => optional_static_str(field.backing_helper_minimum_kernel_source, span),
                    "requirement_key" => optional_string(field.requirement_key, span),
                    "minimum_kernel" => optional_static_str(field.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(field.minimum_kernel_source, span),
                    "load_guard" => optional_static_str(field.load_guard, span),
                    "load_guard_witness" => optional_string(field.load_guard_witness, span),
                    "load_guard_description" => optional_string(field.load_guard_description, span),
                    "load_kind" => optional_static_str(field.load_kind, span),
                    "direct_load_width" => optional_static_str(field.direct_load_width, span),
                    "direct_load_offset" => optional_i16(field.direct_load_offset, span),
                    "direct_load_transform" => optional_static_str(field.direct_load_transform, span),
                    "array_load_base_offset" => optional_i16(field.array_load_base_offset, span),
                    "array_load_count" => optional_usize(field.array_load_count, span),
                    "array_load_normalize_big_endian" => optional_bool(field.array_load_normalize_big_endian, span),
                    "array_load_transform" => optional_static_str(field.array_load_transform, span),
                    "nested_load_pointer_offset" => optional_i16(field.nested_load_pointer_offset, span),
                    "nested_load_width" => optional_static_str(field.nested_load_width, span),
                    "nested_load_field_offset" => optional_i16(field.nested_load_field_offset, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_context_projections(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextProjection> {
    let mut projections = Vec::new();

    for entry in spec.program_type().ctx_field_name_entries() {
        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        let Some(type_spec) = spec.ctx_field_type_spec(&entry.field) else {
            continue;
        };
        let read_helper =
            context_projection_read_helper(spec, &entry.field, &type_spec.semantic_ty);
        let MirType::Ptr { pointee, .. } = type_spec.semantic_ty else {
            continue;
        };
        let MirType::Struct { fields, .. } = *pointee else {
            continue;
        };

        let root = entry.name;
        let projection_source = if root == entry.field.display_name() {
            "context_field"
        } else {
            "context_field_root_alias"
        };
        for field in fields.into_iter().filter(|field| !field.synthetic) {
            let unsupported_reason = match entry.field {
                CtxField::Socket => spec.socket_projection_access_error(&field.name),
                _ => None,
            };
            if unsupported_reason.is_some() {
                continue;
            }
            let compatibility_requirement =
                context_projection_compatibility_requirement(spec, &entry.field, &field.name);
            push_context_field_projection(
                &mut projections,
                root,
                &field.name,
                projection_source,
                &field,
                compatibility_requirement,
                read_helper,
            );

            if matches!(entry.field, CtxField::Socket | CtxField::MigratingSocket) {
                for alias in bpf_sock_projection_member_aliases(&field.name) {
                    let unsupported_reason = match entry.field {
                        CtxField::Socket => spec.socket_projection_access_error(alias),
                        _ => None,
                    };
                    if unsupported_reason.is_some() {
                        continue;
                    }
                    let compatibility_requirement =
                        context_projection_compatibility_requirement(spec, &entry.field, alias);
                    push_context_field_projection(
                        &mut projections,
                        root,
                        alias,
                        "context_field_alias",
                        &field,
                        compatibility_requirement,
                        read_helper,
                    );
                }
            }

            if matches!(entry.field, CtxField::FlowKeys) {
                for alias in bpf_flow_keys_projection_member_aliases(&field.name) {
                    let compatibility_requirement =
                        context_projection_compatibility_requirement(spec, &entry.field, alias);
                    push_context_field_projection(
                        &mut projections,
                        root,
                        alias,
                        "context_field_alias",
                        &field,
                        compatibility_requirement,
                        read_helper,
                    );
                }
            }
        }

        if matches!(entry.field, CtxField::Socket) {
            push_helper_backed_socket_projections(spec, root, &mut projections);
        }
    }

    push_parameterized_context_projections(spec, &mut projections);

    projections
}

#[cfg(target_os = "linux")]
fn context_projection_compatibility_requirement(
    spec: &crate::program_spec::ProgramSpec,
    root_field: &CtxField,
    member: &str,
) -> Option<ContextFieldCompatibilityRequirement> {
    let mut effective =
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(root_field, spec);

    if matches!(root_field, CtxField::Socket | CtxField::MigratingSocket) {
        if let Some(member_field) = ctx_field_for_bpf_sock_projection_member(member) {
            let member_requirement =
                ContextFieldCompatibilityRequirement::for_field_on_program_spec(
                    &member_field,
                    spec,
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
fn context_projection_read_helper(
    spec: &crate::program_spec::ProgramSpec,
    root_field: &CtxField,
    semantic_ty: &MirType,
) -> Option<BpfHelper> {
    match semantic_ty {
        MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        } if !spec.ctx_field_is_trusted_btf_kernel_pointer(root_field) => {
            Some(BpfHelper::ProbeReadKernel)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn push_context_field_projection(
    projections: &mut Vec<SpecContextProjection>,
    root: &str,
    name: &str,
    source: &'static str,
    field: &StructField,
    compatibility_requirement: Option<ContextFieldCompatibilityRequirement>,
    read_helper: Option<BpfHelper>,
) {
    let compatibility_floor = context_projection_compatibility_floor(
        compatibility_requirement.as_ref(),
        None,
        read_helper,
    );
    projections.push(SpecContextProjection {
        root: root.to_string(),
        path: format!("{root}.{name}"),
        name: name.to_string(),
        source,
        compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
        compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
        context_field_requirement_key: compatibility_requirement
            .as_ref()
            .map(ContextFieldCompatibilityRequirement::key),
        minimum_kernel: compatibility_requirement
            .as_ref()
            .map(ContextFieldCompatibilityRequirement::minimum_kernel),
        minimum_kernel_source: compatibility_requirement
            .as_ref()
            .map(ContextFieldCompatibilityRequirement::minimum_kernel_source),
        helper: None,
        helper_requirement_key: None,
        helper_minimum_kernel: None,
        helper_minimum_kernel_source: None,
        read_helper: read_helper.map(BpfHelper::name),
        read_helper_requirement_key: read_helper.and_then(helper_requirement_key),
        read_helper_minimum_kernel: read_helper.and_then(BpfHelper::minimum_kernel),
        read_helper_minimum_kernel_source: read_helper.and_then(BpfHelper::minimum_kernel_source),
        ty: mir_type_label(&field.ty),
        offset: Some(field.offset),
        bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
        bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
        supported: true,
        unsupported_reason: None,
    });
}

#[cfg(target_os = "linux")]
fn push_struct_field_projections(
    projections: &mut Vec<SpecContextProjection>,
    root: &str,
    source: &'static str,
    helper: Option<BpfHelper>,
    read_helper: Option<BpfHelper>,
    ty: MirType,
    unsupported_reason: Option<String>,
) {
    let MirType::Struct { name, fields, .. } = ty else {
        return;
    };
    if unsupported_reason.is_some() {
        return;
    }
    let helper_name = helper.map(BpfHelper::name);
    let helper_requirement_feature_key = helper.and_then(helper_requirement_key);
    let helper_minimum_kernel = helper.and_then(BpfHelper::minimum_kernel);
    let helper_minimum_kernel_source = helper.and_then(BpfHelper::minimum_kernel_source);
    let read_helper_name = read_helper.map(BpfHelper::name);
    let read_helper_requirement_feature_key = read_helper.and_then(helper_requirement_key);
    let read_helper_minimum_kernel = read_helper.and_then(BpfHelper::minimum_kernel);
    let read_helper_minimum_kernel_source = read_helper.and_then(BpfHelper::minimum_kernel_source);
    let compatibility_floor = context_projection_compatibility_floor(None, helper, read_helper);
    let include_bpf_sock_aliases = name.as_deref() == Some("bpf_sock");

    for field in fields.into_iter().filter(|field| !field.synthetic) {
        projections.push(SpecContextProjection {
            root: root.to_string(),
            path: format!("{root}.{}", field.name),
            name: field.name.clone(),
            source,
            compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
            compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
            context_field_requirement_key: None,
            minimum_kernel: None,
            minimum_kernel_source: None,
            helper: helper_name,
            helper_requirement_key: helper_requirement_feature_key.clone(),
            helper_minimum_kernel,
            helper_minimum_kernel_source,
            read_helper: read_helper_name,
            read_helper_requirement_key: read_helper_requirement_feature_key.clone(),
            read_helper_minimum_kernel,
            read_helper_minimum_kernel_source,
            ty: mir_type_label(&field.ty),
            offset: Some(field.offset),
            bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
            bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
            supported: true,
            unsupported_reason: None,
        });
        if include_bpf_sock_aliases {
            for alias in bpf_sock_projection_member_aliases(&field.name) {
                projections.push(SpecContextProjection {
                    root: root.to_string(),
                    path: format!("{root}.{alias}"),
                    name: (*alias).to_string(),
                    source: "helper_return_alias",
                    compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
                    compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
                    context_field_requirement_key: None,
                    minimum_kernel: None,
                    minimum_kernel_source: None,
                    helper: helper_name,
                    helper_requirement_key: helper_requirement_feature_key.clone(),
                    helper_minimum_kernel,
                    helper_minimum_kernel_source,
                    read_helper: read_helper_name,
                    read_helper_requirement_key: read_helper_requirement_feature_key.clone(),
                    read_helper_minimum_kernel,
                    read_helper_minimum_kernel_source,
                    ty: mir_type_label(&field.ty),
                    offset: Some(field.offset),
                    bit_offset: field.bitfield.map(|bitfield| bitfield.bit_offset),
                    bit_size: field.bitfield.map(|bitfield| bitfield.bit_size),
                    supported: true,
                    unsupported_reason: None,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn push_helper_call_projection(
    projections: &mut Vec<SpecContextProjection>,
    root: &str,
    name: &str,
    path: &str,
    helper: BpfHelper,
    ty: MirType,
    unsupported_reason: Option<String>,
) {
    if unsupported_reason.is_some() {
        return;
    }
    let compatibility_floor = context_surface_compatibility_floor(None, Some(helper));

    projections.push(SpecContextProjection {
        root: root.to_string(),
        name: name.to_string(),
        path: path.to_string(),
        source: "helper_call",
        compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
        compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
        context_field_requirement_key: None,
        minimum_kernel: None,
        minimum_kernel_source: None,
        helper: Some(helper.name()),
        helper_requirement_key: helper_requirement_key(helper),
        helper_minimum_kernel: helper.minimum_kernel(),
        helper_minimum_kernel_source: helper.minimum_kernel_source(),
        read_helper: None,
        read_helper_requirement_key: None,
        read_helper_minimum_kernel: None,
        read_helper_minimum_kernel_source: None,
        ty: mir_type_label(&ty),
        offset: None,
        bit_offset: None,
        bit_size: None,
        supported: true,
        unsupported_reason: None,
    });
}

#[cfg(target_os = "linux")]
fn push_parameterized_context_projections(
    spec: &crate::program_spec::ProgramSpec,
    projections: &mut Vec<SpecContextProjection>,
) {
    if spec.ctx_field_access_error(&CtxField::CgroupId).is_none() {
        push_helper_call_projection(
            projections,
            "ancestor_cgroup_id",
            "N",
            "ancestor_cgroup_id.N",
            BpfHelper::GetCurrentAncestorCgroupId,
            MirType::U64,
            None,
        );
    }

    push_helper_call_projection(
        projections,
        "skb_ancestor_cgroup_id",
        "N",
        "skb_ancestor_cgroup_id.N",
        BpfHelper::SkbAncestorCgroupId,
        MirType::U64,
        spec.helper_call_error(BpfHelper::SkbAncestorCgroupId),
    );

    for entry in spec
        .program_type()
        .ctx_field_name_entries()
        .into_iter()
        .filter(|entry| entry.field == CtxField::Socket)
    {
        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        push_helper_call_projection(
            projections,
            entry.name,
            "cgroup_id",
            &format!("{}.cgroup_id", entry.name),
            BpfHelper::SkCgroupId,
            MirType::U64,
            spec.helper_call_error(BpfHelper::SkCgroupId),
        );

        push_helper_call_projection(
            projections,
            entry.name,
            "ancestor_cgroup_id.N",
            &format!("{}.ancestor_cgroup_id.N", entry.name),
            BpfHelper::SkAncestorCgroupId,
            MirType::U64,
            spec.helper_call_error(BpfHelper::SkAncestorCgroupId),
        );
    }

    if spec.ctx_field_access_error(&CtxField::Task).is_none()
        && spec.helper_call_error(BpfHelper::TaskPtRegs).is_none()
    {
        for register in ["arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "retval"] {
            push_helper_call_projection(
                projections,
                "task",
                &format!("pt_regs.{register}"),
                &format!("task.pt_regs.{register}"),
                BpfHelper::TaskPtRegs,
                MirType::U64,
                None,
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn push_helper_backed_socket_projections(
    spec: &crate::program_spec::ProgramSpec,
    socket_root: &str,
    projections: &mut Vec<SpecContextProjection>,
) {
    for (member, helper, ty) in [
        ("tcp", BpfHelper::TcpSock, synthetic_bpf_tcp_sock_type()),
        ("full", BpfHelper::SkFullsock, synthetic_bpf_sock_type()),
        (
            "listener",
            BpfHelper::GetListenerSock,
            synthetic_bpf_sock_type(),
        ),
    ] {
        push_struct_field_projections(
            projections,
            &format!("{socket_root}.{member}"),
            "helper_return",
            Some(helper),
            Some(BpfHelper::ProbeReadKernel),
            ty,
            spec.helper_call_error(helper),
        );
    }
}

#[cfg(target_os = "linux")]
fn context_surface_compatibility_floor(
    context_requirement: Option<&ContextFieldCompatibilityRequirement>,
    helper: Option<BpfHelper>,
) -> Option<(&'static str, &'static str)> {
    let context_floor = context_requirement.map(|requirement| {
        (
            requirement.minimum_kernel(),
            requirement.minimum_kernel_source(),
        )
    });
    let helper_floor =
        helper.and_then(|helper| Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?)));

    later_kernel_floor(context_floor, helper_floor)
}

#[cfg(target_os = "linux")]
fn context_projection_compatibility_floor(
    context_requirement: Option<&ContextFieldCompatibilityRequirement>,
    helper: Option<BpfHelper>,
    read_helper: Option<BpfHelper>,
) -> Option<(&'static str, &'static str)> {
    let base_floor = context_surface_compatibility_floor(context_requirement, helper);
    let read_helper_floor = read_helper
        .and_then(|helper| Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?)));

    later_kernel_floor(base_floor, read_helper_floor)
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
                    "compatibility_minimum_kernel" => optional_static_str(projection.compatibility_minimum_kernel, span),
                    "compatibility_minimum_kernel_source" => optional_static_str(projection.compatibility_minimum_kernel_source, span),
                    "context_field_requirement_key" => optional_string(projection.context_field_requirement_key, span),
                    "minimum_kernel" => optional_static_str(projection.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(projection.minimum_kernel_source, span),
                    "helper" => optional_static_str(projection.helper, span),
                    "helper_requirement_key" => optional_string(projection.helper_requirement_key, span),
                    "helper_minimum_kernel" => optional_static_str(projection.helper_minimum_kernel, span),
                    "helper_minimum_kernel_source" => optional_static_str(projection.helper_minimum_kernel_source, span),
                    "read_helper" => optional_static_str(projection.read_helper, span),
                    "read_helper_requirement_key" => optional_string(projection.read_helper_requirement_key, span),
                    "read_helper_minimum_kernel" => optional_static_str(projection.read_helper_minimum_kernel, span),
                    "read_helper_minimum_kernel_source" => optional_static_str(projection.read_helper_minimum_kernel_source, span),
                    "type" => Value::string(projection.ty, span),
                    "offset" => optional_usize(projection.offset, span),
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
        Ok(Some(tracepoint)) => (spec_tracepoint_fields_from_context(spec, tracepoint), None),
        Ok(None) => (Vec::new(), None),
        Err(err) => (Vec::new(), Some(err)),
    }
}

#[cfg(target_os = "linux")]
fn spec_tracepoint_fields_from_context(
    spec: &crate::program_spec::ProgramSpec,
    tracepoint: TracepointContext,
) -> Vec<SpecTracepointField> {
    let source = tracepoint.source.label();
    let field_compatibility_metadata =
        tracepoint.source == TracepointContextSource::WellKnownSyscallFallback;
    let minimum_kernel = tracepoint.minimum_kernel();
    let minimum_kernel_source = tracepoint.minimum_kernel_source();
    let source_path = tracepoint.source_path.clone();
    let context_struct = tracepoint.struct_name.clone();
    let context_size = tracepoint.size;

    tracepoint
        .fields
        .into_iter()
        .map(|field| {
            let compatibility_requirement = field_compatibility_metadata
                .then(|| {
                    ContextFieldCompatibilityRequirement::for_field_on_program_spec(
                        &CtxField::TracepointField(field.name.clone()),
                        spec,
                    )
                })
                .flatten();
            SpecTracepointField {
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
                minimum_kernel: compatibility_requirement
                    .as_ref()
                    .map(ContextFieldCompatibilityRequirement::minimum_kernel)
                    .or(minimum_kernel),
                minimum_kernel_source: compatibility_requirement
                    .as_ref()
                    .map(ContextFieldCompatibilityRequirement::minimum_kernel_source)
                    .or(minimum_kernel_source),
            }
        })
        .collect()
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
                    "minimum_kernel" => optional_static_str(field.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(field.minimum_kernel_source, span),
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
    if spec.struct_ops_value_type_name().is_some() && spec.struct_ops_callback_name().is_none() {
        return (Vec::new(), None);
    }

    match spec.arg_access() {
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
fn intrinsic_backing_helper_records(
    spec: &crate::program_spec::ProgramSpec,
    intrinsic: ProgramIntrinsic,
    span: Span,
) -> Vec<Value> {
    spec.intrinsic_backing_helpers(intrinsic)
        .into_iter()
        .map(|helper| {
            Value::record(
                record! {
                    "helper" => Value::string(helper.name(), span),
                    "helper_requirement_key" => optional_string(helper_requirement_key(helper), span),
                    "minimum_kernel" => optional_static_str(helper.minimum_kernel(), span),
                    "minimum_kernel_source" => optional_static_str(helper.minimum_kernel_source(), span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn intrinsic_context_field_requirement_records(
    spec: &crate::program_spec::ProgramSpec,
    intrinsic: ProgramIntrinsic,
    span: Span,
) -> Vec<Value> {
    spec.intrinsic_context_field_requirements(intrinsic)
        .into_iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "field" => Value::string(requirement.field().display_name(), span),
                    "context_field_requirement_key" => Value::string(requirement.key(), span),
                    "minimum_kernel" => Value::string(requirement.minimum_kernel(), span),
                    "minimum_kernel_source" => Value::string(requirement.minimum_kernel_source(), span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn intrinsic_compatibility_floor(
    spec: &crate::program_spec::ProgramSpec,
    intrinsic: ProgramIntrinsic,
) -> Option<(&'static str, &'static str)> {
    let helper_floor = spec
        .intrinsic_backing_helpers(intrinsic)
        .into_iter()
        .filter_map(|helper| Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?)))
        .fold(None, |floor, helper| {
            later_kernel_floor(floor, Some(helper))
        });
    spec.intrinsic_context_field_requirements(intrinsic)
        .into_iter()
        .map(|requirement| {
            (
                requirement.minimum_kernel(),
                requirement.minimum_kernel_source(),
            )
        })
        .fold(helper_floor, |floor, requirement| {
            later_kernel_floor(floor, Some(requirement))
        })
}

#[cfg(target_os = "linux")]
fn intrinsic_variant_record(
    selector: &'static str,
    value: &'static str,
    helper: BpfHelper,
    map_kind: Option<MapKind>,
    span: Span,
) -> Value {
    Value::record(
        record! {
            "selector" => Value::string(selector, span),
            "value" => Value::string(value, span),
            "backing_helper" => Value::string(helper.name(), span),
            "helper_requirement_key" => optional_string(helper_requirement_key(helper), span),
            "minimum_kernel" => optional_static_str(helper.minimum_kernel(), span),
            "minimum_kernel_source" => optional_static_str(helper.minimum_kernel_source(), span),
            "map_kind" => optional_static_str(map_kind.map(|kind| kind.key()), span),
            "map_requirement_key" => optional_static_str(map_kind.map(|kind| kind.compatibility_feature_key()), span),
            "map_minimum_kernel" => optional_static_str(map_kind.map(|kind| kind.minimum_kernel()), span),
            "map_minimum_kernel_source" => optional_static_str(map_kind.map(|kind| kind.minimum_kernel_source()), span),
        },
        span,
    )
}

#[cfg(target_os = "linux")]
fn intrinsic_variant_records(
    spec: &crate::program_spec::ProgramSpec,
    intrinsic: ProgramIntrinsic,
    span: Span,
) -> Vec<Value> {
    spec.intrinsic_variants(intrinsic)
        .into_iter()
        .map(|variant| {
            intrinsic_variant_record(
                variant.selector(),
                variant.value(),
                variant.helper(),
                variant.map_kind(),
                span,
            )
        })
        .collect()
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
    match spec.retval_access() {
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
fn later_kernel_floor(
    left: Option<(&'static str, &'static str)>,
    right: Option<(&'static str, &'static str)>,
) -> Option<(&'static str, &'static str)> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if ContextFieldCompatibilityRequirement::kernel_version_at_least(left.0, right.0) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(floor), None) | (None, Some(floor)) => Some(floor),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
fn spec_context_writes(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextWrite> {
    spec.ctx_write_surfaces_for_spec()
        .into_iter()
        .map(|surface| {
            let kfunc_requirement = surface
                .kfunc
                .and_then(|kfunc| spec.kfunc_compatibility_requirement_for_name(kfunc));
            let direct_floor = surface.minimum_kernel.zip(surface.minimum_kernel_source);
            let helper_floor = surface.helper.and_then(|helper| {
                Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?))
            });
            let kfunc_floor = kfunc_requirement.as_ref().map(|requirement| {
                (
                    requirement.minimum_kernel(),
                    requirement.minimum_kernel_source(),
                )
            });
            let compatibility_floor =
                later_kernel_floor(later_kernel_floor(direct_floor, helper_floor), kfunc_floor);
            SpecContextWrite {
                field: surface.field_name,
                kind: surface.kind,
                indexed: surface.indexed,
                abi_field: surface.abi_field.as_ref().map(|field| field.display_name()),
                direct_store_offset: surface.direct_store_offset,
                indexed_store_base_offset: surface.indexed_store_base_offset,
                indexed_store_count: surface.indexed_store_count,
                indexed_store_convert_to_big_endian: surface.indexed_store_convert_to_big_endian,
                transformed_store_offset: surface.transformed_store_offset,
                transformed_store_transform: surface.transformed_store_transform,
                compatibility_minimum_kernel: compatibility_floor.map(|floor| floor.0),
                compatibility_minimum_kernel_source: compatibility_floor.map(|floor| floor.1),
                context_field_requirement_key: surface
                    .context_field_requirement
                    .as_ref()
                    .map(ContextFieldCompatibilityRequirement::key),
                minimum_kernel: surface.minimum_kernel,
                minimum_kernel_source: surface.minimum_kernel_source,
                helper: surface.helper.map(BpfHelper::name),
                helper_requirement_key: surface.helper.and_then(helper_requirement_key),
                helper_minimum_kernel: surface.helper.and_then(BpfHelper::minimum_kernel),
                helper_minimum_kernel_source: surface
                    .helper
                    .and_then(BpfHelper::minimum_kernel_source),
                kfunc: surface.kfunc,
                kfunc_requirement_key: kfunc_requirement
                    .as_ref()
                    .map(|requirement| requirement.key()),
                kfunc_minimum_kernel: kfunc_requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel()),
                kfunc_minimum_kernel_source: kfunc_requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel_source()),
                kfunc_maximum_kernel_exclusive: kfunc_requirement
                    .as_ref()
                    .and_then(|requirement| requirement.maximum_kernel_exclusive()),
                kfunc_maximum_kernel_exclusive_source: kfunc_requirement
                    .as_ref()
                    .and_then(|requirement| requirement.maximum_kernel_exclusive_source()),
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
                    "abi_field" => optional_string(surface.abi_field, span),
                    "direct_store_offset" => optional_i16(surface.direct_store_offset, span),
                    "indexed_store_base_offset" => optional_i16(surface.indexed_store_base_offset, span),
                    "indexed_store_count" => optional_usize(surface.indexed_store_count, span),
                    "indexed_store_convert_to_big_endian" => optional_bool(surface.indexed_store_convert_to_big_endian, span),
                    "transformed_store_offset" => optional_i16(surface.transformed_store_offset, span),
                    "transformed_store_transform" => optional_static_str(surface.transformed_store_transform, span),
                    "compatibility_minimum_kernel" => optional_static_str(surface.compatibility_minimum_kernel, span),
                    "compatibility_minimum_kernel_source" => optional_static_str(surface.compatibility_minimum_kernel_source, span),
                    "context_field_requirement_key" => optional_string(surface.context_field_requirement_key, span),
                    "minimum_kernel" => optional_static_str(surface.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(surface.minimum_kernel_source, span),
                    "helper" => optional_static_str(surface.helper, span),
                    "helper_requirement_key" => optional_string(surface.helper_requirement_key, span),
                    "helper_minimum_kernel" => optional_static_str(surface.helper_minimum_kernel, span),
                    "helper_minimum_kernel_source" => optional_static_str(surface.helper_minimum_kernel_source, span),
                    "kfunc" => optional_static_str(surface.kfunc, span),
                    "kfunc_requirement_key" => optional_string(surface.kfunc_requirement_key, span),
                    "kfunc_minimum_kernel" => optional_static_str(surface.kfunc_minimum_kernel, span),
                    "kfunc_minimum_kernel_source" => optional_static_str(surface.kfunc_minimum_kernel_source, span),
                    "kfunc_maximum_kernel_exclusive" => optional_static_str(surface.kfunc_maximum_kernel_exclusive, span),
                    "kfunc_maximum_kernel_exclusive_source" => optional_static_str(surface.kfunc_maximum_kernel_exclusive_source, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_kfunc_calls(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecKfuncCall> {
    spec.kfunc_call_surfaces_for_spec()
        .into_iter()
        .map(|surface| {
            let requirement = spec.kfunc_compatibility_requirement_for_name(surface.kfunc);
            let signature = KfuncSignature::for_name(surface.kfunc);
            let semantics = kfunc_semantics(surface.kfunc);
            let pointer_arg_ref_kinds =
                kfunc_pointer_arg_ref_kinds(surface.kfunc, signature.as_ref());
            SpecKfuncCall {
                kfunc: surface.kfunc,
                policy: surface.policy,
                note: surface.note,
                min_args: signature.as_ref().map(|signature| signature.min_args),
                max_args: signature.as_ref().map(|signature| signature.max_args),
                arg_kinds: signature
                    .as_ref()
                    .map(|signature| {
                        (0..signature.max_args)
                            .map(|idx| kfunc_arg_kind_label(signature.arg_kind(idx)))
                            .collect()
                    })
                    .unwrap_or_default(),
                return_kind: signature
                    .as_ref()
                    .map(|signature| kfunc_ret_kind_label(signature.ret_kind)),
                requirement_key: requirement.as_ref().map(|requirement| requirement.key()),
                minimum_kernel: requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel()),
                minimum_kernel_source: requirement
                    .as_ref()
                    .map(|requirement| requirement.minimum_kernel_source()),
                maximum_kernel_exclusive: requirement
                    .as_ref()
                    .and_then(|requirement| requirement.maximum_kernel_exclusive()),
                maximum_kernel_exclusive_source: requirement
                    .as_ref()
                    .and_then(|requirement| requirement.maximum_kernel_exclusive_source()),
                acquire_ref_kind: kfunc_acquire_ref_kind(surface.kfunc).map(|kind| kind.label()),
                release_ref_kind: kfunc_release_ref_kind(surface.kfunc).map(|kind| kind.label()),
                release_arg_idx: kfunc_release_ref_arg_index(surface.kfunc),
                pointer_arg_ref_kinds,
                pointer_arg_rules: semantics
                    .ptr_arg_rules
                    .iter()
                    .map(|rule| SpecKfuncPtrArgRule {
                        arg_idx: rule.arg_idx,
                        op: rule.op,
                        allow_stack: rule.allowed.allow_stack,
                        allow_map: rule.allowed.allow_map,
                        allow_kernel: rule.allowed.allow_kernel,
                        allow_user: rule.allowed.allow_user,
                        fixed_size: rule.fixed_size,
                        size_from_arg: rule.size_from_arg,
                    })
                    .collect(),
                positive_size_args: semantics.positive_size_args.to_vec(),
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn kfunc_pointer_arg_ref_kinds(
    kfunc: &'static str,
    signature: Option<&KfuncSignature>,
) -> Vec<SpecKfuncArgRefKind> {
    let Some(signature) = signature else {
        return Vec::new();
    };

    (0..signature.max_args)
        .filter_map(|arg_idx| {
            kfunc_pointer_arg_ref_kind(kfunc, arg_idx).map(|kind| SpecKfuncArgRefKind {
                arg_idx,
                ref_kind: kind.label(),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn usize_list(values: Vec<usize>, span: Span) -> Vec<Value> {
    values
        .into_iter()
        .filter_map(|value| i64::try_from(value).ok())
        .map(|value| Value::int(value, span))
        .collect()
}

#[cfg(target_os = "linux")]
fn static_str_list(values: Vec<&'static str>, span: Span) -> Vec<Value> {
    values
        .into_iter()
        .map(|value| Value::string(value, span))
        .collect()
}

#[cfg(target_os = "linux")]
fn kfunc_arg_ref_kind_records(ref_kinds: Vec<SpecKfuncArgRefKind>, span: Span) -> Vec<Value> {
    ref_kinds
        .into_iter()
        .map(|ref_kind| {
            Value::record(
                record! {
                    "arg_idx" => optional_usize(Some(ref_kind.arg_idx), span),
                    "ref_kind" => Value::string(ref_kind.ref_kind, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn kfunc_ptr_arg_rule_records(rules: Vec<SpecKfuncPtrArgRule>, span: Span) -> Vec<Value> {
    rules
        .into_iter()
        .map(|rule| {
            Value::record(
                record! {
                    "arg_idx" => optional_usize(Some(rule.arg_idx), span),
                    "op" => Value::string(rule.op, span),
                    "allow_stack" => Value::bool(rule.allow_stack, span),
                    "allow_map" => Value::bool(rule.allow_map, span),
                    "allow_kernel" => Value::bool(rule.allow_kernel, span),
                    "allow_user" => Value::bool(rule.allow_user, span),
                    "fixed_size" => optional_usize(rule.fixed_size, span),
                    "size_from_arg" => optional_usize(rule.size_from_arg, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn kfunc_call_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_kfunc_calls(spec)
        .into_iter()
        .map(|surface| {
            let arg_kinds = static_str_list(surface.arg_kinds, span);
            let pointer_arg_ref_kinds =
                kfunc_arg_ref_kind_records(surface.pointer_arg_ref_kinds, span);
            let pointer_arg_rules = kfunc_ptr_arg_rule_records(surface.pointer_arg_rules, span);
            let positive_size_args = usize_list(surface.positive_size_args, span);
            Value::record(
                record! {
                    "kfunc" => Value::string(surface.kfunc, span),
                    "policy" => Value::string(surface.policy, span),
                    "note" => Value::string(surface.note, span),
                    "min_args" => optional_usize(surface.min_args, span),
                    "max_args" => optional_usize(surface.max_args, span),
                    "arg_kinds" => Value::list(arg_kinds, span),
                    "return_kind" => optional_static_str(surface.return_kind, span),
                    "requirement_key" => optional_string(surface.requirement_key, span),
                    "minimum_kernel" => optional_static_str(surface.minimum_kernel, span),
                    "minimum_kernel_source" => optional_static_str(surface.minimum_kernel_source, span),
                    "maximum_kernel_exclusive" => optional_static_str(surface.maximum_kernel_exclusive, span),
                    "maximum_kernel_exclusive_source" => optional_static_str(surface.maximum_kernel_exclusive_source, span),
                    "acquire_ref_kind" => optional_static_str(surface.acquire_ref_kind, span),
                    "release_ref_kind" => optional_static_str(surface.release_ref_kind, span),
                    "release_arg_idx" => optional_usize(surface.release_arg_idx, span),
                    "pointer_arg_ref_kinds" => Value::list(pointer_arg_ref_kinds, span),
                    "pointer_arg_rules" => Value::list(pointer_arg_rules, span),
                    "positive_size_args" => Value::list(positive_size_args, span),
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
    let live_attach_status = live_attach_policy.status();
    let live_attach_note = live_attach_policy.note.unwrap_or("");
    let live_attach_unsupported_reason = live_attach_policy.unsupported_reason;
    let live_attach_opt_in_reason = live_attach_policy.opt_in_reason;
    let live_attach_default_test_lane = spec.live_attach_default_test_lane();
    let external_alpha_status = spec.external_alpha_status();
    let kernel_target_validation = program_type.kernel_target_validation();
    let kernel_target_validation_key = kernel_target_validation.map(|validation| validation.key());
    let kernel_target_validation_help =
        kernel_target_validation.and_then(|validation| validation.unsupported_target_help());
    let btf_callable_surface = spec.btf_callable_surface().map(|surface| surface.key());
    let context_fields = context_field_records(&spec, span, resolve_dynamic_args);
    let (tracepoint_fields, tracepoint_field_error) =
        spec_tracepoint_fields(&spec, resolve_dynamic_args);
    let tracepoint_fields = tracepoint_field_records(tracepoint_fields, span);
    let (context_args, context_arg_error) = spec_context_args(&spec, resolve_dynamic_args);
    let context_args = context_arg_records(context_args, span);
    let (context_retval, context_retval_error) = spec_context_retval(&spec, resolve_dynamic_args);
    let context_retval = context_retval_record(context_retval, span);
    let context_writes = context_write_records(&spec, span);
    let packet_headers = packet_header_records(&spec, span);
    let kfunc_calls = kfunc_call_records(&spec, span);
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
        .filter(|intrinsic| spec.supports_intrinsic(**intrinsic))
        .map(|intrinsic| {
            let capability = intrinsic.required_capability();
            let backing_helpers = intrinsic_backing_helper_records(&spec, *intrinsic, span);
            let context_field_requirements =
                intrinsic_context_field_requirement_records(&spec, *intrinsic, span);
            let variants = intrinsic_variant_records(&spec, *intrinsic, span);
            let compatibility_floor = intrinsic_compatibility_floor(&spec, *intrinsic);
            Value::record(
                record! {
                    "command" => Value::string(intrinsic.command_name(), span),
                    "capability" => Value::string(capability.key(), span),
                    "capability_description" => Value::string(capability.description(), span),
                    "compatibility_minimum_kernel" => optional_static_str(compatibility_floor.map(|floor| floor.0), span),
                    "compatibility_minimum_kernel_source" => optional_static_str(compatibility_floor.map(|floor| floor.1), span),
                    "backing_helpers" => Value::list(backing_helpers, span),
                    "context_field_requirements" => Value::list(context_field_requirements, span),
                    "variants" => Value::list(variants, span),
                },
                span,
            )
        })
        .collect();
    let compatibility_requirements = spec.compatibility_requirements();
    let compatibility_minimum_kernel =
        ProgramCompatibilityRequirement::effective_minimum_kernel(&compatibility_requirements);
    let compatibility_minimum_kernel_source =
        ProgramCompatibilityRequirement::effective_minimum_kernel_source(
            &compatibility_requirements,
        );
    let compatibility_default_test_lane = spec.compatibility_default_test_lane();
    let requirements = compatibility_requirements
        .iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "key" => Value::string(requirement.key(), span),
                    "description" => Value::string(requirement.description(), span),
                    "category" => Value::string(requirement.category(), span),
                    "default_test_lane" => Value::string(requirement.test_lane().key(), span),
                    "default_test_lane_description" => Value::string(requirement.test_lane().description(), span),
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
            "struct_ops_value_type" => optional_string(spec.struct_ops_value_type_name().map(str::to_string), span),
            "struct_ops_callback" => optional_string(spec.struct_ops_callback_name().map(str::to_string), span),
            "section" => Value::string(spec.section_name(), span),
            "section_prefix" => Value::string(program_type.section_prefix(), span),
            "section_uses_target" => Value::bool(program_type.section_uses_target(), span),
            "attach_kind" => Value::string(attach_kind.key(), span),
            "attach_shape" => attach_shape_record(&spec, span),
            "target_kind" => Value::string(spec.target_kind().key(), span),
            "kernel_target_validation" => optional_static_str(kernel_target_validation_key, span),
            "kernel_target_validation_help" => optional_static_str(kernel_target_validation_help, span),
            "btf_callable_surface" => optional_static_str(btf_callable_surface, span),
            "sleepable" => Value::bool(spec.sleepable(), span),
            "arg_access" => Value::string(spec.arg_access().key(), span),
            "retval_access" => Value::string(spec.retval_access().key(), span),
            "live_attach_supported" => Value::bool(live_attach_policy.loader_supported, span),
            "live_attach_default_allowed" => Value::bool(live_attach_policy.default_allowed, span),
            "live_attach_requires_opt_in" => Value::bool(live_attach_policy.requires_opt_in, span),
            "live_attach_status" => Value::string(live_attach_status.key(), span),
            "live_attach_status_description" => Value::string(live_attach_status.description(), span),
            "live_attach_unsupported_reason" => optional_static_str(live_attach_unsupported_reason.map(|reason| reason.key()), span),
            "live_attach_unsupported_reason_description" => optional_static_str(live_attach_unsupported_reason.map(|reason| reason.description()), span),
            "live_attach_opt_in_reason" => optional_static_str(live_attach_opt_in_reason.map(|reason| reason.key()), span),
            "live_attach_opt_in_reason_description" => optional_static_str(live_attach_opt_in_reason.map(|reason| reason.description()), span),
            "live_attach_note" => Value::string(live_attach_note, span),
            "live_attach_default_test_lane" => Value::string(live_attach_default_test_lane.key(), span),
            "live_attach_default_test_lane_description" => Value::string(live_attach_default_test_lane.description(), span),
            "external_alpha_status" => Value::string(external_alpha_status.key(), span),
            "external_alpha_status_description" => Value::string(external_alpha_status.description(), span),
            "context_fields" => Value::list(context_fields, span),
            "tracepoint_fields" => Value::list(tracepoint_fields, span),
            "tracepoint_field_error" => optional_string(tracepoint_field_error, span),
            "context_args" => Value::list(context_args, span),
            "context_arg_error" => optional_string(context_arg_error, span),
            "context_retval" => context_retval,
            "context_retval_error" => optional_string(context_retval_error, span),
            "context_writes" => Value::list(context_writes, span),
            "packet_headers" => Value::list(packet_headers, span),
            "kfunc_calls" => Value::list(kfunc_calls, span),
            "context_projections" => Value::list(context_projections, span),
            "capabilities" => Value::list(capabilities, span),
            "intrinsics" => Value::list(intrinsics, span),
            "compatibility_requirements" => Value::list(requirements, span),
            "compatibility_minimum_kernel" => optional_static_str(compatibility_minimum_kernel, span),
            "compatibility_minimum_kernel_source" => optional_static_str(compatibility_minimum_kernel_source, span),
            "compatibility_default_test_lane" => Value::string(compatibility_default_test_lane.key(), span),
            "compatibility_default_test_lane_description" => Value::string(compatibility_default_test_lane.description(), span),
            "return_aliases" => Value::list(return_aliases, span),
        },
        span,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
