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

impl EbpfProgramType {
    pub(crate) fn base_ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        match field {
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Comm
                if !self.supports_task_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.canonical_prefix()
                ))
            }
            CtxField::Cpu if !self.supports_cpu_ctx_field() => Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                self.canonical_prefix()
            )),
            CtxField::Timestamp if !self.supports_timestamp_ctx_field() => Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                self.canonical_prefix()
            )),
            CtxField::PerfSamplePeriod | CtxField::PerfAddr
                if !matches!(self, EbpfProgramType::PerfEvent) =>
            {
                Some(format!(
                    "ctx.{} is only available on perf_event programs",
                    field.display_name()
                ))
            }
            CtxField::PerfSamplePeriod | CtxField::PerfAddr if !cfg!(target_arch = "x86_64") => {
                Some(format!(
                    "ctx.{} is currently only modeled on x86_64 perf_event programs",
                    field.display_name()
                ))
            }
            CtxField::PacketLen if !self.supports_packet_len_ctx_field() => {
                Some(packet_field_access_error(*self, field))
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
            | CtxField::Tstamp
            | CtxField::TstampType
            | CtxField::Hwtstamp
                if !self.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::Data | CtxField::DataEnd if !self.supports_packet_data_ctx_fields() => {
                Some(packet_field_access_error(*self, field))
            }
            CtxField::DataMeta if !self.supports_data_meta_ctx_field() => Some(format!(
                "ctx.{} is only available on xdp and tc programs",
                field.display_name()
            )),
            CtxField::IngressIfindex if !self.supports_ingress_ifindex_ctx_field() => {
                Some(packet_field_access_error(*self, field))
            }
            CtxField::Ifindex | CtxField::TcIndex | CtxField::SkbHash
                if !self.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::RxQueueIndex if !self.supports_rx_queue_index_ctx_field() => {
                Some(packet_field_access_error(*self, field))
            }
            CtxField::EgressIfindex if !self.supports_egress_ifindex_ctx_field() => {
                Some(packet_field_access_error(*self, field))
            }
            CtxField::RemoteIp4
            | CtxField::RemoteIp6
            | CtxField::RemotePort
            | CtxField::LocalIp4
            | CtxField::LocalIp6
            | CtxField::LocalPort
                if !self.supports_socket_tuple_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::Socket if !self.supports_socket_ref_ctx_field() => Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            )),
            CtxField::LookupCookie if !self.supports_lookup_cookie_ctx_field() => Some(format!(
                "ctx.{} is only available on sk_lookup programs",
                field.display_name()
            )),
            CtxField::SocketCookie if !self.supports_socket_cookie_ctx_field() => Some(format!(
                "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                field.display_name()
            )),
            CtxField::SocketUid if !self.supports_socket_uid_ctx_field() => Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            )),
            CtxField::NetnsCookie if !self.supports_netns_cookie_ctx_field() => Some(format!(
                "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
                field.display_name()
            )),
            CtxField::DeviceAccessType | CtxField::DeviceMajor | CtxField::DeviceMinor
                if !self.supports_device_ctx_fields() =>
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
                if !self.supports_sock_ops_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::UserFamily
            | CtxField::UserIp4
            | CtxField::UserIp6
            | CtxField::UserPort
            | CtxField::MsgSrcIp4
            | CtxField::MsgSrcIp6
                if !self.supports_cgroup_sock_addr_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock_addr programs",
                    field.display_name()
                ))
            }
            CtxField::Family if !self.supports_socket_common_ctx_fields() => Some(format!(
                "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            )),
            CtxField::SockType if !self.supports_sock_type_ctx_field() => {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::Protocol if !self.supports_protocol_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::BoundDevIf if !self.supports_cgroup_sock_ctx_fields() => Some(format!(
                "ctx.{} is only available on cgroup_sock programs",
                field.display_name()
            )),
            CtxField::SockMark | CtxField::SockPriority
                if !self.supports_sock_mark_priority_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::SysctlWrite | CtxField::SysctlFilePos
                if !self.supports_cgroup_sysctl_ctx_fields() =>
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
                if !self.supports_cgroup_sockopt_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sockopt programs",
                    field.display_name()
                ))
            }
            CtxField::SockoptRetval if !self.supports_cgroup_sockopt_ctx_fields() => {
                Some("ctx.sockopt_retval is only available on cgroup_sockopt programs".to_string())
            }
            CtxField::LircSample | CtxField::LircValue | CtxField::LircMode
                if !self.supports_lirc_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on lirc_mode2 programs",
                    field.display_name()
                ))
            }
            CtxField::Arg(_) if !self.supports_ctx_args() => Some(format!(
                "ctx.{} is only available on contexts with argument access (kprobe, uprobe, fentry, fexit, tp_btf, lsm, struct_ops, and raw_tracepoint)",
                field.display_name()
            )),
            CtxField::RetVal if !self.supports_ctx_retval() => Some(
                "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit)".to_string(),
            ),
            CtxField::KStack | CtxField::UStack if !self.supports_stack_ctx_fields() => {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.canonical_prefix()
                ))
            }
            CtxField::TracepointField(name) if !self.supports_tracepoint_fields() => Some(format!(
                "ctx.{} is only available on typed tracepoints (`tracepoint:category/name`)",
                name
            )),
            _ => None,
        }
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
