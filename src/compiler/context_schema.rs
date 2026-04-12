use crate::compiler::mir::{AddressSpace, CtxField, MirType, StructField};
use crate::compiler::{EbpfProgramType, ProbeContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldTypeSpec {
    pub semantic_ty: MirType,
    pub runtime_ty: MirType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldProjectionSpec {
    pub runtime_ty: MirType,
    pub stack_slot_ty: Option<MirType>,
    pub normalize_u32_words_host_order: bool,
    pub validate_socket_projection: bool,
}

impl ContextFieldTypeSpec {
    fn value(ty: MirType) -> Self {
        Self {
            semantic_ty: ty.clone(),
            runtime_ty: ty,
        }
    }

    fn stack_backed(semantic_ty: MirType) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            semantic_ty,
        }
    }
}

impl ContextFieldProjectionSpec {
    fn direct(runtime_ty: MirType) -> Self {
        Self {
            runtime_ty,
            stack_slot_ty: None,
            normalize_u32_words_host_order: false,
            validate_socket_projection: false,
        }
    }

    fn stack_backed(semantic_ty: MirType, normalize_u32_words_host_order: bool) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            stack_slot_ty: Some(semantic_ty),
            normalize_u32_words_host_order,
            validate_socket_projection: false,
        }
    }
}

pub(crate) fn synthetic_bpf_sock_type() -> MirType {
    MirType::Struct {
        name: Some("bpf_sock".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "bound_dev_if".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "family".to_string(),
                ty: MirType::U32,
                offset: 4,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "type".to_string(),
                ty: MirType::U32,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "protocol".to_string(),
                ty: MirType::U32,
                offset: 12,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "mark".to_string(),
                ty: MirType::U32,
                offset: 16,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "priority".to_string(),
                ty: MirType::U32,
                offset: 20,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_ip4".to_string(),
                ty: MirType::U32,
                offset: 24,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 28,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_port".to_string(),
                ty: MirType::U32,
                offset: 44,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_port".to_string(),
                ty: MirType::U16,
                offset: 48,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_ip4".to_string(),
                ty: MirType::U32,
                offset: 52,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 56,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "state".to_string(),
                ty: MirType::U32,
                offset: 72,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "rx_queue_mapping".to_string(),
                ty: MirType::I32,
                offset: 76,
                synthetic: false,
                bitfield: None,
            },
        ],
    }
}

pub(crate) fn static_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
    Some(match field {
        CtxField::Pid
        | CtxField::Tid
        | CtxField::Uid
        | CtxField::Gid
        | CtxField::Cpu
        | CtxField::PacketLen
        | CtxField::PktType
        | CtxField::QueueMapping
        | CtxField::EthProtocol
        | CtxField::VlanPresent
        | CtxField::VlanTci
        | CtxField::VlanProto
        | CtxField::TcClassid
        | CtxField::NapiId
        | CtxField::WireLen
        | CtxField::GsoSegs
        | CtxField::GsoSize
        | CtxField::IngressIfindex
        | CtxField::Ifindex
        | CtxField::RxQueueIndex
        | CtxField::EgressIfindex
        | CtxField::TcIndex
        | CtxField::SkbHash
        | CtxField::UserFamily
        | CtxField::UserIp4
        | CtxField::UserPort
        | CtxField::Family
        | CtxField::SockType
        | CtxField::Protocol
        | CtxField::BoundDevIf
        | CtxField::SockMark
        | CtxField::SockPriority
        | CtxField::MsgSrcIp4
        | CtxField::RemoteIp4
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalPort
        | CtxField::LircSample
        | CtxField::LircValue
        | CtxField::LircMode
        | CtxField::DeviceAccessType
        | CtxField::DeviceMajor
        | CtxField::DeviceMinor
        | CtxField::SockOp
        | CtxField::IsFullsock
        | CtxField::SockOpsSndCwnd
        | CtxField::SockOpsSrttUs
        | CtxField::SockOpsCbFlags
        | CtxField::SockState
        | CtxField::SockOpsRttMin
        | CtxField::SockOpsSndSsthresh
        | CtxField::SockOpsRcvNxt
        | CtxField::SockOpsSndNxt
        | CtxField::SockOpsSndUna
        | CtxField::SockOpsMssCache
        | CtxField::SockOpsEcnFlags
        | CtxField::SockOpsRateDelivered
        | CtxField::SockOpsRateIntervalUs
        | CtxField::SockOpsPacketsOut
        | CtxField::SockOpsRetransOut
        | CtxField::SockOpsTotalRetrans
        | CtxField::SockOpsSegsIn
        | CtxField::SockOpsDataSegsIn
        | CtxField::SockOpsSegsOut
        | CtxField::SockOpsDataSegsOut
        | CtxField::SockOpsLostOut
        | CtxField::SockOpsSackedOut
        | CtxField::SockOpsSkTxhash
        | CtxField::SockOpsSkbLen
        | CtxField::SockOpsSkbTcpFlags
        | CtxField::SysctlWrite
        | CtxField::SysctlFilePos
        | CtxField::SocketUid => ContextFieldTypeSpec::value(MirType::U32),
        CtxField::Timestamp
        | CtxField::CgroupId
        | CtxField::LookupCookie
        | CtxField::SocketCookie
        | CtxField::NetnsCookie
        | CtxField::Hwtstamp
        | CtxField::SockOpsBytesReceived
        | CtxField::SockOpsBytesAcked
        | CtxField::SockOpsSkbHwtstamp => ContextFieldTypeSpec::value(MirType::U64),
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptRetval => ContextFieldTypeSpec::value(MirType::I32),
        CtxField::Context => ContextFieldTypeSpec::value(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::Socket => ContextFieldTypeSpec::value(MirType::Ptr {
            pointee: Box::new(synthetic_bpf_sock_type()),
            address_space: AddressSpace::Kernel,
        }),
        CtxField::SockoptOptval | CtxField::SockoptOptvalEnd => {
            ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            })
        }
        CtxField::UserIp6
        | CtxField::MsgSrcIp6
        | CtxField::RemoteIp6
        | CtxField::LocalIp6
        | CtxField::SockOpsArgs => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U32),
            len: 4,
        }),
        CtxField::SkbCb => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U32),
            len: 5,
        }),
        CtxField::Data | CtxField::DataEnd => ContextFieldTypeSpec::value(MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        }),
        CtxField::Comm => ContextFieldTypeSpec::stack_backed(MirType::Array {
            elem: Box::new(MirType::U8),
            len: 16,
        }),
        CtxField::Arg(_) | CtxField::RetVal | CtxField::KStack | CtxField::UStack => {
            return None;
        }
        CtxField::TracepointField(_) => return None,
    })
}

pub(crate) fn static_ctx_field_projection_spec(
    field: &CtxField,
) -> Option<ContextFieldProjectionSpec> {
    let type_spec = static_ctx_field_type_spec(field)?;
    Some(match field {
        CtxField::Data
        | CtxField::DataEnd
        | CtxField::SockoptOptval
        | CtxField::SockoptOptvalEnd => ContextFieldProjectionSpec::direct(type_spec.runtime_ty),
        CtxField::Socket => ContextFieldProjectionSpec {
            runtime_ty: type_spec.runtime_ty,
            stack_slot_ty: None,
            normalize_u32_words_host_order: false,
            validate_socket_projection: true,
        },
        CtxField::Comm => ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, false),
        CtxField::UserIp6 | CtxField::MsgSrcIp6 => {
            ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, true)
        }
        CtxField::RemoteIp6 | CtxField::LocalIp6 | CtxField::SockOpsArgs | CtxField::SkbCb => {
            ContextFieldProjectionSpec::stack_backed(type_spec.semantic_ty, false)
        }
        _ => return None,
    })
}

fn ctx_field_alias(program_type: EbpfProgramType, field_name: &str) -> Option<CtxField> {
    match (program_type, field_name) {
        (EbpfProgramType::Xdp, "ifindex") => Some(CtxField::IngressIfindex),
        (
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser,
            "ifindex",
        ) => Some(CtxField::Ifindex),
        _ => None,
    }
}

fn generic_ctx_field_from_name(field_name: &str) -> Result<CtxField, String> {
    Ok(match field_name {
        "pid" => CtxField::Pid,
        "tid" | "tgid" => CtxField::Tid,
        "uid" => CtxField::Uid,
        "gid" => CtxField::Gid,
        "comm" => CtxField::Comm,
        "cpu" => CtxField::Cpu,
        "ktime" | "timestamp" => CtxField::Timestamp,
        "cgroup_id" => CtxField::CgroupId,
        "packet_len" | "len" => CtxField::PacketLen,
        "pkt_type" => CtxField::PktType,
        "queue_mapping" => CtxField::QueueMapping,
        "eth_protocol" => CtxField::EthProtocol,
        "vlan_present" => CtxField::VlanPresent,
        "vlan_tci" => CtxField::VlanTci,
        "vlan_proto" => CtxField::VlanProto,
        "cb" => CtxField::SkbCb,
        "tc_classid" => CtxField::TcClassid,
        "napi_id" => CtxField::NapiId,
        "wire_len" => CtxField::WireLen,
        "gso_segs" => CtxField::GsoSegs,
        "gso_size" => CtxField::GsoSize,
        "hwtstamp" => CtxField::Hwtstamp,
        "data" => CtxField::Data,
        "data_end" => CtxField::DataEnd,
        "ingress_ifindex" => CtxField::IngressIfindex,
        "rx_queue_index" => CtxField::RxQueueIndex,
        "egress_ifindex" => CtxField::EgressIfindex,
        "tc_index" => CtxField::TcIndex,
        "hash" => CtxField::SkbHash,
        "user_family" => CtxField::UserFamily,
        "user_ip4" => CtxField::UserIp4,
        "user_ip6" => CtxField::UserIp6,
        "user_port" => CtxField::UserPort,
        "family" => CtxField::Family,
        "sock_type" | "type" => CtxField::SockType,
        "protocol" => CtxField::Protocol,
        "sk" => CtxField::Socket,
        "bound_dev_if" => CtxField::BoundDevIf,
        "mark" => CtxField::SockMark,
        "priority" => CtxField::SockPriority,
        "msg_src_ip4" => CtxField::MsgSrcIp4,
        "msg_src_ip6" => CtxField::MsgSrcIp6,
        "remote_ip4" => CtxField::RemoteIp4,
        "remote_ip6" => CtxField::RemoteIp6,
        "remote_port" => CtxField::RemotePort,
        "local_ip4" => CtxField::LocalIp4,
        "local_ip6" => CtxField::LocalIp6,
        "local_port" => CtxField::LocalPort,
        "cookie" => CtxField::LookupCookie,
        "sample" | "raw" => CtxField::LircSample,
        "value" => CtxField::LircValue,
        "mode" => CtxField::LircMode,
        "socket_cookie" => CtxField::SocketCookie,
        "socket_uid" => CtxField::SocketUid,
        "netns_cookie" => CtxField::NetnsCookie,
        "args" => CtxField::SockOpsArgs,
        "snd_cwnd" => CtxField::SockOpsSndCwnd,
        "srtt_us" => CtxField::SockOpsSrttUs,
        "write" => CtxField::SysctlWrite,
        "file_pos" => CtxField::SysctlFilePos,
        "rtt_min" => CtxField::SockOpsRttMin,
        "snd_ssthresh" => CtxField::SockOpsSndSsthresh,
        "rcv_nxt" => CtxField::SockOpsRcvNxt,
        "snd_nxt" => CtxField::SockOpsSndNxt,
        "snd_una" => CtxField::SockOpsSndUna,
        "packets_out" => CtxField::SockOpsPacketsOut,
        "retrans_out" => CtxField::SockOpsRetransOut,
        "total_retrans" => CtxField::SockOpsTotalRetrans,
        "bytes_received" => CtxField::SockOpsBytesReceived,
        "bytes_acked" => CtxField::SockOpsBytesAcked,
        "skb_len" => CtxField::SockOpsSkbLen,
        "skb_tcp_flags" => CtxField::SockOpsSkbTcpFlags,
        "skb_hwtstamp" => CtxField::SockOpsSkbHwtstamp,
        "level" => CtxField::SockoptLevel,
        "optname" => CtxField::SockoptOptname,
        "optlen" => CtxField::SockoptOptlen,
        "optval" => CtxField::SockoptOptval,
        "optval_end" => CtxField::SockoptOptvalEnd,
        "sockopt_retval" => CtxField::SockoptRetval,
        "retval" => CtxField::RetVal,
        "kstack" => CtxField::KStack,
        "ustack" => CtxField::UStack,
        s if s.starts_with("arg") => {
            let num: u8 = s[3..].parse().map_err(|_| format!("Invalid arg: {}", s))?;
            CtxField::Arg(num)
        }
        _ => CtxField::TracepointField(field_name.to_string()),
    })
}

fn non_tracepoint_ctx_field_from_name(field_name: &str) -> Option<CtxField> {
    Some(match field_name {
        "ifindex" => CtxField::Ifindex,
        "access_type" => CtxField::DeviceAccessType,
        "major" => CtxField::DeviceMajor,
        "minor" => CtxField::DeviceMinor,
        "op" => CtxField::SockOp,
        "is_fullsock" => CtxField::IsFullsock,
        "snd_cwnd" => CtxField::SockOpsSndCwnd,
        "srtt_us" => CtxField::SockOpsSrttUs,
        "cb_flags" => CtxField::SockOpsCbFlags,
        "state" => CtxField::SockState,
        "rtt_min" => CtxField::SockOpsRttMin,
        "snd_ssthresh" => CtxField::SockOpsSndSsthresh,
        "rcv_nxt" => CtxField::SockOpsRcvNxt,
        "snd_nxt" => CtxField::SockOpsSndNxt,
        "snd_una" => CtxField::SockOpsSndUna,
        "mss_cache" => CtxField::SockOpsMssCache,
        "ecn_flags" => CtxField::SockOpsEcnFlags,
        "rate_delivered" => CtxField::SockOpsRateDelivered,
        "rate_interval_us" => CtxField::SockOpsRateIntervalUs,
        "packets_out" => CtxField::SockOpsPacketsOut,
        "retrans_out" => CtxField::SockOpsRetransOut,
        "total_retrans" => CtxField::SockOpsTotalRetrans,
        "segs_in" => CtxField::SockOpsSegsIn,
        "data_segs_in" => CtxField::SockOpsDataSegsIn,
        "segs_out" => CtxField::SockOpsSegsOut,
        "data_segs_out" => CtxField::SockOpsDataSegsOut,
        "lost_out" => CtxField::SockOpsLostOut,
        "sacked_out" => CtxField::SockOpsSackedOut,
        "sk_txhash" => CtxField::SockOpsSkTxhash,
        "bytes_received" => CtxField::SockOpsBytesReceived,
        "bytes_acked" => CtxField::SockOpsBytesAcked,
        "skb_len" => CtxField::SockOpsSkbLen,
        "skb_tcp_flags" => CtxField::SockOpsSkbTcpFlags,
        "skb_hwtstamp" => CtxField::SockOpsSkbHwtstamp,
        _ => return None,
    })
}

fn tracepoint_preserves_builtin_ctx_field(field: &CtxField) -> bool {
    matches!(
        field,
        CtxField::Pid
            | CtxField::Tid
            | CtxField::Uid
            | CtxField::Gid
            | CtxField::Comm
            | CtxField::Cpu
            | CtxField::Timestamp
            | CtxField::CgroupId
            | CtxField::KStack
            | CtxField::UStack
            | CtxField::Arg(_)
    )
}

pub(crate) fn resolve_program_ctx_field_name(
    program_type: EbpfProgramType,
    field_name: &str,
) -> Result<CtxField, String> {
    if let Some(field) = ctx_field_alias(program_type, field_name) {
        return Ok(field);
    }

    if matches!(program_type, EbpfProgramType::Tracepoint) {
        return generic_ctx_field_from_name(field_name);
    }

    if let Some(field) = non_tracepoint_ctx_field_from_name(field_name) {
        return Ok(field);
    }

    generic_ctx_field_from_name(field_name)
}

pub(crate) fn resolve_untyped_ctx_field_name(field_name: &str) -> Result<CtxField, String> {
    if let Some(field) = non_tracepoint_ctx_field_from_name(field_name) {
        return Ok(field);
    }

    generic_ctx_field_from_name(field_name)
}

pub(crate) fn static_ctx_field_access_error(
    probe_ctx: &ProbeContext,
    field: &CtxField,
) -> Option<String> {
    let packet_field_error = |field: &CtxField| {
        if probe_ctx.probe_type.packet_context_kind().is_some() {
            format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                probe_ctx.probe_type.canonical_prefix()
            )
        } else {
            format!(
                "ctx.{} is only available on packet-context programs (xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, and packet-aware sock_ops callbacks)",
                field.display_name()
            )
        }
    };
    let program_type = probe_ctx.probe_type;

    match field {
        CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Comm
            if !program_type.supports_task_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                program_type.canonical_prefix()
            ))
        }
        CtxField::Cpu if !program_type.supports_cpu_ctx_field() => Some(format!(
            "ctx.{} is not available on {} programs",
            field.display_name(),
            program_type.canonical_prefix()
        )),
        CtxField::Timestamp if !program_type.supports_timestamp_ctx_field() => Some(format!(
            "ctx.{} is not available on {} programs",
            field.display_name(),
            program_type.canonical_prefix()
        )),
        CtxField::PacketLen if !program_type.supports_packet_len_ctx_field() => {
            Some(packet_field_error(field))
        }
        CtxField::PktType
        | CtxField::QueueMapping
        | CtxField::EthProtocol
        | CtxField::VlanPresent
        | CtxField::VlanTci
        | CtxField::VlanProto
        | CtxField::SkbCb
        | CtxField::TcClassid
        | CtxField::NapiId
        | CtxField::WireLen
        | CtxField::GsoSegs
        | CtxField::GsoSize
        | CtxField::Hwtstamp
            if !program_type.supports_skb_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ))
        }
        CtxField::Data | CtxField::DataEnd if !program_type.supports_packet_data_ctx_fields() => {
            Some(packet_field_error(field))
        }
        CtxField::IngressIfindex if !program_type.supports_ingress_ifindex_ctx_field() => {
            Some(packet_field_error(field))
        }
        CtxField::Ifindex | CtxField::TcIndex | CtxField::SkbHash
            if !program_type.supports_skb_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ))
        }
        CtxField::RxQueueIndex if !program_type.supports_rx_queue_index_ctx_field() => {
            Some(packet_field_error(field))
        }
        CtxField::EgressIfindex if !program_type.supports_egress_ifindex_ctx_field() => {
            Some(packet_field_error(field))
        }
        CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort
            if !program_type.supports_socket_tuple_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ))
        }
        CtxField::Socket if !program_type.supports_socket_ref_ctx_field() => Some(format!(
            "ctx.{} is only available on cgroup_sock, cgroup_sockopt, sk_lookup, and sk_msg programs",
            field.display_name()
        )),
        CtxField::LookupCookie if !program_type.supports_lookup_cookie_ctx_field() => {
            Some(format!(
                "ctx.{} is only available on sk_lookup programs",
                field.display_name()
            ))
        }
        CtxField::SocketCookie if !program_type.supports_socket_cookie_ctx_field() => {
            Some(format!(
                "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                field.display_name()
            ))
        }
        CtxField::SocketUid if !program_type.supports_socket_uid_ctx_field() => Some(format!(
            "ctx.{} is only available on socket_filter, tc, cgroup_skb, and sk_skb programs",
            field.display_name()
        )),
        CtxField::NetnsCookie if !program_type.supports_netns_cookie_ctx_field() => {
            Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
                field.display_name()
            ))
        }
        CtxField::DeviceAccessType | CtxField::DeviceMajor | CtxField::DeviceMinor
            if !program_type.supports_device_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_device programs",
                field.display_name()
            ))
        }
        CtxField::SockOp
        | CtxField::SockOpsArgs
        | CtxField::IsFullsock
        | CtxField::SockOpsSndCwnd
        | CtxField::SockOpsSrttUs
        | CtxField::SockOpsCbFlags
        | CtxField::SockState
        | CtxField::SockOpsRttMin
        | CtxField::SockOpsSndSsthresh
        | CtxField::SockOpsRcvNxt
        | CtxField::SockOpsSndNxt
        | CtxField::SockOpsSndUna
        | CtxField::SockOpsMssCache
        | CtxField::SockOpsEcnFlags
        | CtxField::SockOpsRateDelivered
        | CtxField::SockOpsRateIntervalUs
        | CtxField::SockOpsPacketsOut
        | CtxField::SockOpsRetransOut
        | CtxField::SockOpsTotalRetrans
        | CtxField::SockOpsSegsIn
        | CtxField::SockOpsDataSegsIn
        | CtxField::SockOpsSegsOut
        | CtxField::SockOpsDataSegsOut
        | CtxField::SockOpsLostOut
        | CtxField::SockOpsSackedOut
        | CtxField::SockOpsSkTxhash
        | CtxField::SockOpsBytesReceived
        | CtxField::SockOpsBytesAcked
        | CtxField::SockOpsSkbLen
        | CtxField::SockOpsSkbTcpFlags
        | CtxField::SockOpsSkbHwtstamp
            if !program_type.supports_sock_ops_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on sock_ops programs",
                field.display_name()
            ))
        }
        CtxField::UserFamily | CtxField::UserPort
            if !program_type.supports_cgroup_sock_addr_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_sock_addr programs",
                field.display_name()
            ))
        }
        CtxField::Family if !program_type.supports_socket_common_ctx_fields() => Some(format!(
            "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
            field.display_name()
        )),
        CtxField::SockType | CtxField::Protocol
            if !program_type.supports_sock_type_protocol_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                field.display_name()
            ))
        }
        CtxField::BoundDevIf if !program_type.supports_cgroup_sock_ctx_fields() => {
            Some(format!(
                "ctx.{} is only available on cgroup_sock programs",
                field.display_name()
            ))
        }
        CtxField::SockMark | CtxField::SockPriority
            if !program_type.supports_sock_mark_priority_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ))
        }
        CtxField::SysctlWrite | CtxField::SysctlFilePos
            if !program_type.supports_cgroup_sysctl_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_sysctl programs",
                field.display_name()
            ))
        }
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptOptval
        | CtxField::SockoptOptvalEnd
            if !program_type.supports_cgroup_sockopt_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on cgroup_sockopt programs",
                field.display_name()
            ))
        }
        CtxField::SockoptRetval if !program_type.supports_cgroup_sockopt_ctx_fields() => {
            Some("ctx.sockopt_retval is only available on cgroup_sockopt programs".to_string())
        }
        CtxField::LircSample | CtxField::LircValue | CtxField::LircMode
            if !program_type.supports_lirc_ctx_fields() =>
        {
            Some(format!(
                "ctx.{} is only available on lirc_mode2 programs",
                field.display_name()
            ))
        }
        CtxField::Arg(_) if !program_type.supports_ctx_args() => Some(format!(
            "ctx.{} is only available on contexts with argument access (kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, and raw_tracepoint)",
            field.display_name()
        )),
        CtxField::RetVal if !program_type.supports_ctx_retval() => Some(
            "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit)".to_string(),
        ),
        CtxField::KStack | CtxField::UStack if !program_type.supports_stack_ctx_fields() => {
            Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                program_type.canonical_prefix()
            ))
        }
        CtxField::TracepointField(name) if !program_type.supports_tracepoint_fields() => {
            Some(format!(
                "ctx.{} is only available on typed tracepoints (`tracepoint:category/name`)",
                name
            ))
        }
        _ => None,
    }
}

pub(crate) fn resolve_probe_ctx_field_name(
    probe_ctx: &ProbeContext,
    field_name: &str,
) -> Result<CtxField, String> {
    if !matches!(probe_ctx.probe_type, EbpfProgramType::Tracepoint) {
        return resolve_program_ctx_field_name(probe_ctx.probe_type, field_name);
    }

    let resolved = resolve_program_ctx_field_name(probe_ctx.probe_type, field_name)?;
    if tracepoint_preserves_builtin_ctx_field(&resolved) {
        Ok(resolved)
    } else {
        Ok(CtxField::TracepointField(field_name.to_string()))
    }
}
