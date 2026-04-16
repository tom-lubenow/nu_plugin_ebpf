use super::{CtxField, EbpfProgramType};
use crate::program_spec::ProgramSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextFieldAccessRequirement {
    CgroupSockoptGetOnly,
    CgroupSockAddrIpv4Only,
    CgroupSockAddrIpv6Only,
    CgroupSockAddrMsgSourceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextFieldAccessSurfaceSpec {
    field: CtxField,
    field_name: &'static str,
    primary_requirement: ContextFieldAccessRequirement,
    secondary_requirement: Option<ContextFieldAccessRequirement>,
}

impl ContextFieldAccessRequirement {
    fn error(self, spec: &ProgramSpec, field_name: &str) -> Option<String> {
        match self {
            Self::CgroupSockoptGetOnly => match spec {
                ProgramSpec::CgroupSockopt { target } if !target.is_get() => Some(format!(
                    "ctx.{field_name} is only available on cgroup_sockopt:get hooks"
                )),
                _ => None,
            },
            Self::CgroupSockAddrIpv4Only => match spec {
                ProgramSpec::CgroupSockAddr { target } if !target.is_ipv4() => Some(format!(
                    "ctx.{field_name} is only available on IPv4 cgroup_sock_addr hooks (*4)"
                )),
                _ => None,
            },
            Self::CgroupSockAddrIpv6Only => match spec {
                ProgramSpec::CgroupSockAddr { target } if !target.is_ipv6() => Some(format!(
                    "ctx.{field_name} is only available on IPv6 cgroup_sock_addr hooks (*6)"
                )),
                _ => None,
            },
            Self::CgroupSockAddrMsgSourceOnly => match spec {
                ProgramSpec::CgroupSockAddr { target } if !target.has_msg_source() => {
                    Some(format!(
                        "ctx.{field_name} is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    ))
                }
                _ => None,
            },
        }
    }
}

impl ContextFieldAccessSurfaceSpec {
    fn new(
        field: CtxField,
        field_name: &'static str,
        primary_requirement: ContextFieldAccessRequirement,
    ) -> Self {
        Self {
            field,
            field_name,
            primary_requirement,
            secondary_requirement: None,
        }
    }

    fn with_secondary_requirement(mut self, requirement: ContextFieldAccessRequirement) -> Self {
        self.secondary_requirement = Some(requirement);
        self
    }

    fn matches_field(&self, field: &CtxField) -> bool {
        &self.field == field
    }

    fn error(&self, spec: &ProgramSpec) -> Option<String> {
        self.primary_requirement
            .error(spec, self.field_name)
            .or_else(|| {
                self.secondary_requirement
                    .and_then(|requirement| requirement.error(spec, self.field_name))
            })
    }
}

fn find_ctx_field_access_surface<const N: usize>(
    field: &CtxField,
    surfaces: [ContextFieldAccessSurfaceSpec; N],
) -> Option<ContextFieldAccessSurfaceSpec> {
    surfaces
        .into_iter()
        .find(|surface| surface.matches_field(field))
}

fn cgroup_sockopt_ctx_field_access_surfaces() -> [ContextFieldAccessSurfaceSpec; 1] {
    [ContextFieldAccessSurfaceSpec::new(
        CtxField::SockoptRetval,
        "sockopt_retval",
        ContextFieldAccessRequirement::CgroupSockoptGetOnly,
    )]
}

fn cgroup_sock_addr_ctx_field_access_surfaces() -> [ContextFieldAccessSurfaceSpec; 4] {
    [
        ContextFieldAccessSurfaceSpec::new(
            CtxField::UserIp4,
            "user_ip4",
            ContextFieldAccessRequirement::CgroupSockAddrIpv4Only,
        ),
        ContextFieldAccessSurfaceSpec::new(
            CtxField::UserIp6,
            "user_ip6",
            ContextFieldAccessRequirement::CgroupSockAddrIpv6Only,
        ),
        ContextFieldAccessSurfaceSpec::new(
            CtxField::MsgSrcIp4,
            "msg_src_ip4",
            ContextFieldAccessRequirement::CgroupSockAddrIpv4Only,
        )
        .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrMsgSourceOnly),
        ContextFieldAccessSurfaceSpec::new(
            CtxField::MsgSrcIp6,
            "msg_src_ip6",
            ContextFieldAccessRequirement::CgroupSockAddrIpv6Only,
        )
        .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrMsgSourceOnly),
    ]
}

fn packet_field_access_error(program_type: EbpfProgramType, field: &CtxField) -> String {
    if program_type.packet_context_kind().is_some() {
        format!(
            "ctx.{} is not available on {} programs",
            field.display_name(),
            program_type.canonical_prefix()
        )
    } else {
        format!(
            "ctx.{} is only available on packet-context programs (xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, and packet-aware sock_ops callbacks)",
            field.display_name()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseContextFieldAccessRequirement {
    TaskFields,
    CpuField,
    TimestampField,
    PerfEventField,
    PacketLenField,
    SkbFields,
    PacketDataFields,
    DataMetaField,
    IngressIfindexField,
    RxQueueIndexField,
    EgressIfindexField,
    SocketTupleFields,
    SocketRefField,
    LookupCookieField,
    SocketCookieField,
    SocketUidField,
    NetnsCookieField,
    DeviceFields,
    SockOpsFields,
    CgroupSockAddrFields,
    SocketCommonFields,
    SockTypeField,
    ProtocolField,
    CgroupSockFields,
    SockMarkPriorityFields,
    CgroupSysctlFields,
    CgroupSockoptFields,
    CgroupSockoptRetvalField,
    LircFields,
    ArgFields,
    RetvalField,
    StackFields,
    TracepointFields,
}

impl BaseContextFieldAccessRequirement {
    fn is_allowed(self, program_type: EbpfProgramType) -> bool {
        match self {
            Self::TaskFields => program_type.supports_task_ctx_fields(),
            Self::CpuField => program_type.supports_cpu_ctx_field(),
            Self::TimestampField => program_type.supports_timestamp_ctx_field(),
            Self::PerfEventField => {
                matches!(program_type, EbpfProgramType::PerfEvent) && cfg!(target_arch = "x86_64")
            }
            Self::PacketLenField => program_type.supports_packet_len_ctx_field(),
            Self::SkbFields => program_type.supports_skb_ctx_fields(),
            Self::PacketDataFields => program_type.supports_packet_data_ctx_fields(),
            Self::DataMetaField => program_type.supports_data_meta_ctx_field(),
            Self::IngressIfindexField => program_type.supports_ingress_ifindex_ctx_field(),
            Self::RxQueueIndexField => program_type.supports_rx_queue_index_ctx_field(),
            Self::EgressIfindexField => program_type.supports_egress_ifindex_ctx_field(),
            Self::SocketTupleFields => program_type.supports_socket_tuple_ctx_fields(),
            Self::SocketRefField => program_type.supports_socket_ref_ctx_field(),
            Self::LookupCookieField => program_type.supports_lookup_cookie_ctx_field(),
            Self::SocketCookieField => program_type.supports_socket_cookie_ctx_field(),
            Self::SocketUidField => program_type.supports_socket_uid_ctx_field(),
            Self::NetnsCookieField => program_type.supports_netns_cookie_ctx_field(),
            Self::DeviceFields => program_type.supports_device_ctx_fields(),
            Self::SockOpsFields => program_type.supports_sock_ops_ctx_fields(),
            Self::CgroupSockAddrFields => program_type.supports_cgroup_sock_addr_ctx_fields(),
            Self::SocketCommonFields => program_type.supports_socket_common_ctx_fields(),
            Self::SockTypeField => program_type.supports_sock_type_ctx_field(),
            Self::ProtocolField => program_type.supports_protocol_ctx_field(),
            Self::CgroupSockFields => program_type.supports_cgroup_sock_ctx_fields(),
            Self::SockMarkPriorityFields => program_type.supports_sock_mark_priority_ctx_fields(),
            Self::CgroupSysctlFields => program_type.supports_cgroup_sysctl_ctx_fields(),
            Self::CgroupSockoptFields | Self::CgroupSockoptRetvalField => {
                program_type.supports_cgroup_sockopt_ctx_fields()
            }
            Self::LircFields => program_type.supports_lirc_ctx_fields(),
            Self::ArgFields => program_type.supports_ctx_args(),
            Self::RetvalField => program_type.supports_ctx_retval(),
            Self::StackFields => program_type.supports_stack_ctx_fields(),
            Self::TracepointFields => program_type.supports_tracepoint_fields(),
        }
    }

    fn error(self, program_type: EbpfProgramType, field: &CtxField) -> String {
        match self {
            Self::TaskFields | Self::CpuField | Self::TimestampField | Self::StackFields => {
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    program_type.canonical_prefix()
                )
            }
            Self::PerfEventField if !matches!(program_type, EbpfProgramType::PerfEvent) => {
                format!(
                    "ctx.{} is only available on perf_event programs",
                    field.display_name()
                )
            }
            Self::PerfEventField => format!(
                "ctx.{} is currently only modeled on x86_64 perf_event programs",
                field.display_name()
            ),
            Self::PacketLenField
            | Self::PacketDataFields
            | Self::IngressIfindexField
            | Self::RxQueueIndexField
            | Self::EgressIfindexField => packet_field_access_error(program_type, field),
            Self::SkbFields => format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::DataMetaField => {
                format!("ctx.{} is only available on xdp and tc programs", field.display_name())
            }
            Self::SocketTupleFields => format!(
                "ctx.{} is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ),
            Self::SocketRefField => format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ),
            Self::LookupCookieField => {
                format!("ctx.{} is only available on sk_lookup programs", field.display_name())
            }
            Self::SocketCookieField => format!(
                "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                field.display_name()
            ),
            Self::SocketUidField => format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::NetnsCookieField => format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
                field.display_name()
            ),
            Self::DeviceFields => format!(
                "ctx.{} is only available on cgroup_device programs",
                field.display_name()
            ),
            Self::SockOpsFields => format!(
                "ctx.{} is only available on sock_ops programs",
                field.display_name()
            ),
            Self::CgroupSockAddrFields => format!(
                "ctx.{} is only available on cgroup_sock_addr programs",
                field.display_name()
            ),
            Self::SocketCommonFields => format!(
                "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ),
            Self::SockTypeField | Self::ProtocolField => format!(
                "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                field.display_name()
            ),
            Self::CgroupSockFields => format!(
                "ctx.{} is only available on cgroup_sock programs",
                field.display_name()
            ),
            Self::SockMarkPriorityFields => format!(
                "ctx.{} is only available on cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::CgroupSysctlFields => format!(
                "ctx.{} is only available on cgroup_sysctl programs",
                field.display_name()
            ),
            Self::CgroupSockoptFields => format!(
                "ctx.{} is only available on cgroup_sockopt programs",
                field.display_name()
            ),
            Self::CgroupSockoptRetvalField => {
                "ctx.sockopt_retval is only available on cgroup_sockopt programs".to_string()
            }
            Self::LircFields => format!(
                "ctx.{} is only available on lirc_mode2 programs",
                field.display_name()
            ),
            Self::ArgFields => format!(
                "ctx.{} is only available on contexts with argument access (kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, and raw_tracepoint)",
                field.display_name()
            ),
            Self::RetvalField => "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit)".to_string(),
            Self::TracepointFields => match field {
                CtxField::TracepointField(name) => format!(
                    "ctx.{} is only available on typed tracepoints (`tracepoint:category/name`)",
                    name
                ),
                _ => unreachable!("tracepoint field requirement only applies to tracepoint fields"),
            },
        }
    }
}

fn base_ctx_field_access_requirement(
    field: &CtxField,
) -> Option<BaseContextFieldAccessRequirement> {
    Some(match field {
        CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Comm => {
            BaseContextFieldAccessRequirement::TaskFields
        }
        CtxField::Cpu => BaseContextFieldAccessRequirement::CpuField,
        CtxField::Timestamp => BaseContextFieldAccessRequirement::TimestampField,
        CtxField::PerfSamplePeriod | CtxField::PerfAddr => {
            BaseContextFieldAccessRequirement::PerfEventField
        }
        CtxField::PacketLen => BaseContextFieldAccessRequirement::PacketLenField,
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
        | CtxField::Tstamp
        | CtxField::TstampType
        | CtxField::Hwtstamp
        | CtxField::Ifindex
        | CtxField::TcIndex
        | CtxField::SkbHash => BaseContextFieldAccessRequirement::SkbFields,
        CtxField::Data | CtxField::DataEnd => BaseContextFieldAccessRequirement::PacketDataFields,
        CtxField::DataMeta => BaseContextFieldAccessRequirement::DataMetaField,
        CtxField::IngressIfindex => BaseContextFieldAccessRequirement::IngressIfindexField,
        CtxField::RxQueueIndex => BaseContextFieldAccessRequirement::RxQueueIndexField,
        CtxField::EgressIfindex => BaseContextFieldAccessRequirement::EgressIfindexField,
        CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort => BaseContextFieldAccessRequirement::SocketTupleFields,
        CtxField::Socket => BaseContextFieldAccessRequirement::SocketRefField,
        CtxField::LookupCookie => BaseContextFieldAccessRequirement::LookupCookieField,
        CtxField::SocketCookie => BaseContextFieldAccessRequirement::SocketCookieField,
        CtxField::SocketUid => BaseContextFieldAccessRequirement::SocketUidField,
        CtxField::NetnsCookie => BaseContextFieldAccessRequirement::NetnsCookieField,
        CtxField::DeviceAccessType | CtxField::DeviceMajor | CtxField::DeviceMinor => {
            BaseContextFieldAccessRequirement::DeviceFields
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
        | CtxField::SockOpsSkbHwtstamp => BaseContextFieldAccessRequirement::SockOpsFields,
        CtxField::UserFamily
        | CtxField::UserIp4
        | CtxField::UserIp6
        | CtxField::UserPort
        | CtxField::MsgSrcIp4
        | CtxField::MsgSrcIp6 => BaseContextFieldAccessRequirement::CgroupSockAddrFields,
        CtxField::Family => BaseContextFieldAccessRequirement::SocketCommonFields,
        CtxField::SockType => BaseContextFieldAccessRequirement::SockTypeField,
        CtxField::Protocol => BaseContextFieldAccessRequirement::ProtocolField,
        CtxField::BoundDevIf => BaseContextFieldAccessRequirement::CgroupSockFields,
        CtxField::SockMark | CtxField::SockPriority => {
            BaseContextFieldAccessRequirement::SockMarkPriorityFields
        }
        CtxField::SysctlWrite | CtxField::SysctlFilePos => {
            BaseContextFieldAccessRequirement::CgroupSysctlFields
        }
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptOptval
        | CtxField::SockoptOptvalEnd => BaseContextFieldAccessRequirement::CgroupSockoptFields,
        CtxField::SockoptRetval => BaseContextFieldAccessRequirement::CgroupSockoptRetvalField,
        CtxField::LircSample | CtxField::LircValue | CtxField::LircMode => {
            BaseContextFieldAccessRequirement::LircFields
        }
        CtxField::Arg(_) => BaseContextFieldAccessRequirement::ArgFields,
        CtxField::RetVal => BaseContextFieldAccessRequirement::RetvalField,
        CtxField::KStack | CtxField::UStack => BaseContextFieldAccessRequirement::StackFields,
        CtxField::TracepointField(_) => BaseContextFieldAccessRequirement::TracepointFields,
        _ => return None,
    })
}

impl EbpfProgramType {
    pub(crate) fn base_ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        let requirement = base_ctx_field_access_requirement(field)?;
        (!requirement.is_allowed(*self)).then(|| requirement.error(*self, field))
    }
}

impl ProgramSpec {
    fn ctx_field_access_surface(&self, field: &CtxField) -> Option<ContextFieldAccessSurfaceSpec> {
        match self {
            ProgramSpec::CgroupSockopt { .. } => {
                find_ctx_field_access_surface(field, cgroup_sockopt_ctx_field_access_surfaces())
            }
            ProgramSpec::CgroupSockAddr { .. } => {
                find_ctx_field_access_surface(field, cgroup_sock_addr_ctx_field_access_surfaces())
            }
            _ => None,
        }
    }

    fn attach_ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        self.ctx_field_access_surface(field)
            .and_then(|surface| surface.error(self))
    }

    pub(crate) fn ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        self.program_type()
            .base_ctx_field_access_error(field)
            .or_else(|| self.attach_ctx_field_access_error(field))
    }
}
