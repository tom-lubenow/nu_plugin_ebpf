use super::{CtxField, EbpfProgramType};
use crate::program_spec::{ProgramAttachAddressFamily, ProgramAttachSockAddrHook, ProgramSpec};

type BaseContextFieldAccessSurfaceSpec = (&'static [CtxField], BaseContextFieldAccessRequirement);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextFieldAccessRequirement {
    TcEgressOnly,
    CgroupSockCreateReleaseOnly,
    CgroupSockPostBindOnly,
    CgroupSockPostBindIpv4Only,
    CgroupSockPostBindIpv6Only,
    CgroupSockoptGetOnly,
    CgroupSockAddrInetOnly,
    CgroupSockAddrIpv4Only,
    CgroupSockAddrIpv6Only,
    CgroupSockAddrRemoteTupleOnly,
    CgroupSockAddrLocalIpAliasOnly,
    CgroupSockAddrLocalTupleOnly,
    CgroupSockAddrSendmsgOnly,
    AllowedProgramsLabel(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContextFieldAccessSurfaceSpec {
    field: CtxField,
    field_name: &'static str,
    primary_requirement: ContextFieldAccessRequirement,
    secondary_requirement: Option<ContextFieldAccessRequirement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramContextFieldAccessSurfaceSpec {
    program_type: EbpfProgramType,
    surfaces: &'static [ContextFieldAccessSurfaceSpec],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupSockAddrTupleAliasSpec {
    field: CtxField,
    target_field: CtxField,
    hooks: &'static [ProgramAttachSockAddrHook],
    family: Option<ProgramAttachAddressFamily>,
}

impl ContextFieldAccessRequirement {
    fn error(self, spec: &ProgramSpec, field_name: &str) -> Option<String> {
        let attach_shape = spec.attach_shape();
        match self {
            Self::TcEgressOnly => attach_shape.is_tc_ingress().then(|| {
                format!("ctx.{field_name} is only available on tc/tcx egress programs")
            }),
            Self::CgroupSockCreateReleaseOnly => {
                attach_shape.is_cgroup_sock_post_bind().then(|| {
                    format!(
                    "ctx.{field_name} is only available on cgroup_sock sock_create/sock_release hooks"
                )
                })
            }
            Self::CgroupSockPostBindOnly => attach_shape.is_cgroup_sock_create_release().then(|| {
                format!(
                    "ctx.{field_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
                )
            }),
            Self::CgroupSockPostBindIpv4Only
                if attach_shape.is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv4) =>
            {
                None
            }
            Self::CgroupSockPostBindIpv4Only if attach_shape.is_cgroup_sock() => Some(format!(
                "ctx.{field_name} is only available on cgroup_sock post_bind4 hooks"
            )),
            Self::CgroupSockPostBindIpv4Only => None,
            Self::CgroupSockPostBindIpv6Only
                if attach_shape.is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv6) =>
            {
                None
            }
            Self::CgroupSockPostBindIpv6Only if attach_shape.is_cgroup_sock() => Some(format!(
                "ctx.{field_name} is only available on cgroup_sock post_bind6 hooks"
            )),
            Self::CgroupSockPostBindIpv6Only => None,
            Self::CgroupSockoptGetOnly => attach_shape.is_cgroup_sockopt_set().then(|| {
                format!(
                    "ctx.{field_name} is only available on cgroup_sockopt:get hooks"
                )
            }),
            Self::CgroupSockAddrInetOnly => {
                attach_shape.cgroup_sock_addr().and_then(|(family, _)| {
                    (!family.is_inet()).then(|| {
                        format!(
                            "ctx.{field_name} is only available on IPv4/IPv6 cgroup_sock_addr hooks (*4/*6)"
                        )
                    })
                })
            }
            Self::CgroupSockAddrIpv4Only => attach_shape.cgroup_sock_addr().and_then(|(family, _)| {
                (family != ProgramAttachAddressFamily::Ipv4).then(|| {
                    format!("ctx.{field_name} is only available on IPv4 cgroup_sock_addr hooks (*4)")
                })
            }),
            Self::CgroupSockAddrIpv6Only => attach_shape.cgroup_sock_addr().and_then(|(family, _)| {
                (family != ProgramAttachAddressFamily::Ipv6).then(|| {
                    format!("ctx.{field_name} is only available on IPv6 cgroup_sock_addr hooks (*6)")
                })
            }),
            Self::CgroupSockAddrRemoteTupleOnly => {
                attach_shape.cgroup_sock_addr().and_then(|(_, hook)| {
                    (!hook.exposes_remote_tuple()).then(|| format!(
                    "ctx.{field_name} is only available on cgroup_sock_addr connect4/connect6, getpeername4/getpeername6, sendmsg4/sendmsg6, and recvmsg4/recvmsg6 hooks"
                    ))
                })
            }
            Self::CgroupSockAddrLocalIpAliasOnly => {
                attach_shape.cgroup_sock_addr().and_then(|(_, hook)| {
                    (!hook.exposes_local_ip_alias()).then(|| format!(
                    "ctx.{field_name} is only available on cgroup_sock_addr bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6 hooks"
                    ))
                })
            }
            Self::CgroupSockAddrLocalTupleOnly => {
                attach_shape.cgroup_sock_addr().and_then(|(_, hook)| {
                    (!hook.exposes_local_tuple()).then(|| format!(
                    "ctx.{field_name} is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks"
                    ))
                })
            }
            Self::CgroupSockAddrSendmsgOnly => {
                attach_shape.cgroup_sock_addr().and_then(|(_, hook)| {
                    (!hook.is_sendmsg()).then(|| format!(
                    "ctx.{field_name} is only available on cgroup_sock_addr sendmsg4/sendmsg6 hooks"
                    ))
                })
            },
            Self::AllowedProgramsLabel(label) => {
                Some(format!("ctx.{field_name} is only available on {label}"))
            }
        }
    }
}

impl ContextFieldAccessSurfaceSpec {
    const fn new(
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

    const fn with_secondary_requirement(
        mut self,
        requirement: ContextFieldAccessRequirement,
    ) -> Self {
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

impl CgroupSockAddrTupleAliasSpec {
    const fn new(
        field: CtxField,
        target_field: CtxField,
        hooks: &'static [ProgramAttachSockAddrHook],
        family: Option<ProgramAttachAddressFamily>,
    ) -> Self {
        Self {
            field,
            target_field,
            hooks,
            family,
        }
    }

    fn matches(
        &self,
        field: &CtxField,
        hook: ProgramAttachSockAddrHook,
        family: ProgramAttachAddressFamily,
    ) -> bool {
        &self.field == field
            && self.hooks.contains(&hook)
            && match self.family {
                Some(required_family) => required_family == family,
                None => family.is_inet(),
            }
    }
}

const CGROUP_SOCK_ADDR_REMOTE_TUPLE_HOOKS: &[ProgramAttachSockAddrHook] = &[
    ProgramAttachSockAddrHook::Connect,
    ProgramAttachSockAddrHook::GetPeerName,
    ProgramAttachSockAddrHook::SendMsg,
    ProgramAttachSockAddrHook::RecvMsg,
];

const CGROUP_SOCK_ADDR_LOCAL_IP_ALIAS_HOOKS: &[ProgramAttachSockAddrHook] = &[
    ProgramAttachSockAddrHook::Bind,
    ProgramAttachSockAddrHook::GetSockName,
];

const CGROUP_SOCK_ADDR_SENDMSG_HOOKS: &[ProgramAttachSockAddrHook] =
    &[ProgramAttachSockAddrHook::SendMsg];

const CGROUP_SOCK_ADDR_LOCAL_TUPLE_HOOKS: &[ProgramAttachSockAddrHook] = &[
    ProgramAttachSockAddrHook::Bind,
    ProgramAttachSockAddrHook::GetSockName,
];

const CGROUP_SOCK_ADDR_TUPLE_ALIAS_FIELDS: &[CgroupSockAddrTupleAliasSpec] = &[
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::RemoteIp4,
        CtxField::UserIp4,
        CGROUP_SOCK_ADDR_REMOTE_TUPLE_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv4),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::RemoteIp6,
        CtxField::UserIp6,
        CGROUP_SOCK_ADDR_REMOTE_TUPLE_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv6),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::RemotePort,
        CtxField::UserPort,
        CGROUP_SOCK_ADDR_REMOTE_TUPLE_HOOKS,
        None,
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::LocalIp4,
        CtxField::UserIp4,
        CGROUP_SOCK_ADDR_LOCAL_IP_ALIAS_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv4),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::LocalIp4,
        CtxField::MsgSrcIp4,
        CGROUP_SOCK_ADDR_SENDMSG_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv4),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::LocalIp6,
        CtxField::UserIp6,
        CGROUP_SOCK_ADDR_LOCAL_IP_ALIAS_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv6),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::LocalIp6,
        CtxField::MsgSrcIp6,
        CGROUP_SOCK_ADDR_SENDMSG_HOOKS,
        Some(ProgramAttachAddressFamily::Ipv6),
    ),
    CgroupSockAddrTupleAliasSpec::new(
        CtxField::LocalPort,
        CtxField::UserPort,
        CGROUP_SOCK_ADDR_LOCAL_TUPLE_HOOKS,
        None,
    ),
];

const SOCKET_FILTER_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TcClassid,
        "tc_classid",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::WireLen,
        "wire_len",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Tstamp,
        "tstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TstampType,
        "tstamp_type",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Hwtstamp,
        "hwtstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
];

const TC_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::CgroupClassid,
        "cgroup_classid",
        ContextFieldAccessRequirement::TcEgressOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::RouteRealm,
        "route_realm",
        ContextFieldAccessRequirement::TcEgressOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::SkbCgroupId,
        "skb_cgroup_id",
        ContextFieldAccessRequirement::TcEgressOnly,
    ),
];

const CGROUP_SKB_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TcClassid,
        "tc_classid",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::WireLen,
        "wire_len",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TstampType,
        "tstamp_type",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
];

const SK_SKB_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TcClassid,
        "tc_classid",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::WireLen,
        "wire_len",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Tstamp,
        "tstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TstampType,
        "tstamp_type",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Hwtstamp,
        "hwtstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::SockMark,
        "mark",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
];

const LWT_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TcClassid,
        "tc_classid",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::WireLen,
        "wire_len",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Tstamp,
        "tstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::TstampType,
        "tstamp_type",
        ContextFieldAccessRequirement::AllowedProgramsLabel("tc_action, tc, and tcx programs"),
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::Hwtstamp,
        "hwtstamp",
        ContextFieldAccessRequirement::AllowedProgramsLabel(
            "tc_action, tc, tcx, and cgroup_skb programs",
        ),
    ),
];

const PROGRAM_CTX_FIELD_ACCESS_SURFACES: &[ProgramContextFieldAccessSurfaceSpec] = &[
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::SocketFilter,
        surfaces: SOCKET_FILTER_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::Tc,
        surfaces: TC_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::Tcx,
        surfaces: TC_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::CgroupSkb,
        surfaces: CGROUP_SKB_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::SkSkb,
        surfaces: SK_SKB_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::SkSkbParser,
        surfaces: SK_SKB_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::LwtIn,
        surfaces: LWT_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::LwtOut,
        surfaces: LWT_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::LwtXmit,
        surfaces: LWT_CTX_FIELD_ACCESS_SURFACES,
    },
    ProgramContextFieldAccessSurfaceSpec {
        program_type: EbpfProgramType::LwtSeg6Local,
        surfaces: LWT_CTX_FIELD_ACCESS_SURFACES,
    },
];

const CGROUP_SOCK_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
    ContextFieldAccessSurfaceSpec::new(
        CtxField::BoundDevIf,
        "bound_dev_if",
        ContextFieldAccessRequirement::CgroupSockCreateReleaseOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::SockMark,
        "mark",
        ContextFieldAccessRequirement::CgroupSockCreateReleaseOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::SockPriority,
        "priority",
        ContextFieldAccessRequirement::CgroupSockCreateReleaseOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalIp4,
        "local_ip4",
        ContextFieldAccessRequirement::CgroupSockPostBindIpv4Only,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalIp6,
        "local_ip6",
        ContextFieldAccessRequirement::CgroupSockPostBindIpv6Only,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalPort,
        "local_port",
        ContextFieldAccessRequirement::CgroupSockPostBindOnly,
    ),
];

const CGROUP_SOCKOPT_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] =
    &[ContextFieldAccessSurfaceSpec::new(
        CtxField::SockoptRetval,
        "sockopt_retval",
        ContextFieldAccessRequirement::CgroupSockoptGetOnly,
    )];

const CGROUP_SOCK_ADDR_CTX_FIELD_ACCESS_SURFACES: &[ContextFieldAccessSurfaceSpec] = &[
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
        CtxField::UserPort,
        "user_port",
        ContextFieldAccessRequirement::CgroupSockAddrInetOnly,
    ),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::MsgSrcIp4,
        "msg_src_ip4",
        ContextFieldAccessRequirement::CgroupSockAddrIpv4Only,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrSendmsgOnly),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::MsgSrcIp6,
        "msg_src_ip6",
        ContextFieldAccessRequirement::CgroupSockAddrIpv6Only,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrSendmsgOnly),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::RemoteIp4,
        "remote_ip4",
        ContextFieldAccessRequirement::CgroupSockAddrRemoteTupleOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrIpv4Only),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::RemoteIp6,
        "remote_ip6",
        ContextFieldAccessRequirement::CgroupSockAddrRemoteTupleOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrIpv6Only),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::RemotePort,
        "remote_port",
        ContextFieldAccessRequirement::CgroupSockAddrRemoteTupleOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrInetOnly),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalIp4,
        "local_ip4",
        ContextFieldAccessRequirement::CgroupSockAddrLocalIpAliasOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrIpv4Only),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalIp6,
        "local_ip6",
        ContextFieldAccessRequirement::CgroupSockAddrLocalIpAliasOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrIpv6Only),
    ContextFieldAccessSurfaceSpec::new(
        CtxField::LocalPort,
        "local_port",
        ContextFieldAccessRequirement::CgroupSockAddrLocalTupleOnly,
    )
    .with_secondary_requirement(ContextFieldAccessRequirement::CgroupSockAddrInetOnly),
];

const TASK_CTX_FIELDS: &[CtxField] = &[
    CtxField::Pid,
    CtxField::Tgid,
    CtxField::Uid,
    CtxField::Gid,
    CtxField::Comm,
    CtxField::Task,
];
const PERF_EVENT_CTX_FIELDS: &[CtxField] = &[CtxField::PerfSamplePeriod, CtxField::PerfAddr];
const SKB_CTX_FIELDS: &[CtxField] = &[
    CtxField::PktType,
    CtxField::QueueMapping,
    CtxField::VlanPresent,
    CtxField::VlanTci,
    CtxField::VlanProto,
    CtxField::SkbCb,
    CtxField::TcClassid,
    CtxField::NapiId,
    CtxField::WireLen,
    CtxField::GsoSegs,
    CtxField::GsoSize,
    CtxField::Tstamp,
    CtxField::TstampType,
    CtxField::Hwtstamp,
    CtxField::Ifindex,
    CtxField::TcIndex,
];
const REUSEPORT_CTX_FIELDS: &[CtxField] = &[CtxField::BindInany, CtxField::MigratingSocket];
const FLOW_DISSECTOR_CTX_FIELDS: &[CtxField] = &[CtxField::FlowKeys];
const NETFILTER_CTX_FIELDS: &[CtxField] = &[
    CtxField::NetfilterState,
    CtxField::NetfilterSkb,
    CtxField::NetfilterHook,
    CtxField::NetfilterProtocolFamily,
];
const SOCKET_TUPLE_CTX_FIELDS: &[CtxField] = &[
    CtxField::RemoteIp4,
    CtxField::RemoteIp6,
    CtxField::RemotePort,
    CtxField::LocalIp4,
    CtxField::LocalIp6,
    CtxField::LocalPort,
];
const DEVICE_CTX_FIELDS: &[CtxField] = &[
    CtxField::DeviceAccessType,
    CtxField::DeviceAccess,
    CtxField::DeviceType,
    CtxField::DeviceMajor,
    CtxField::DeviceMinor,
];
const SOCK_OPS_CTX_FIELDS: &[CtxField] = &[
    CtxField::SockOp,
    CtxField::SockOpsArgs,
    CtxField::IsFullsock,
    CtxField::SockOpsSndCwnd,
    CtxField::SockOpsSrttUs,
    CtxField::SockOpsCbFlags,
    CtxField::SockOpsRttMin,
    CtxField::SockOpsSndSsthresh,
    CtxField::SockOpsRcvNxt,
    CtxField::SockOpsSndNxt,
    CtxField::SockOpsSndUna,
    CtxField::SockOpsMssCache,
    CtxField::SockOpsEcnFlags,
    CtxField::SockOpsRateDelivered,
    CtxField::SockOpsRateIntervalUs,
    CtxField::SockOpsPacketsOut,
    CtxField::SockOpsRetransOut,
    CtxField::SockOpsTotalRetrans,
    CtxField::SockOpsSegsIn,
    CtxField::SockOpsDataSegsIn,
    CtxField::SockOpsSegsOut,
    CtxField::SockOpsDataSegsOut,
    CtxField::SockOpsLostOut,
    CtxField::SockOpsSackedOut,
    CtxField::SockOpsSkTxhash,
    CtxField::SockOpsBytesReceived,
    CtxField::SockOpsBytesAcked,
    CtxField::SockOpsSkbLen,
    CtxField::SockOpsSkbTcpFlags,
    CtxField::SockOpsSkbHwtstamp,
];
const CGROUP_SOCK_ADDR_CTX_FIELDS: &[CtxField] = &[
    CtxField::UserFamily,
    CtxField::UserIp4,
    CtxField::UserIp6,
    CtxField::UserPort,
    CtxField::MsgSrcIp4,
    CtxField::MsgSrcIp6,
];
const SOCK_MARK_PRIORITY_CTX_FIELDS: &[CtxField] = &[CtxField::SockMark, CtxField::SockPriority];
const CGROUP_SYSCTL_CTX_FIELDS: &[CtxField] = &[
    CtxField::SysctlWrite,
    CtxField::SysctlFilePos,
    CtxField::SysctlName,
    CtxField::SysctlBaseName,
    CtxField::SysctlCurrentValue,
    CtxField::SysctlNewValue,
];
const CGROUP_SOCKOPT_CTX_FIELDS: &[CtxField] = &[
    CtxField::SockoptLevel,
    CtxField::SockoptOptname,
    CtxField::SockoptOptlen,
    CtxField::SockoptOptval,
    CtxField::SockoptOptvalEnd,
];
const LIRC_CTX_FIELDS: &[CtxField] = &[
    CtxField::LircSample,
    CtxField::LircValue,
    CtxField::LircMode,
];
const STACK_CTX_FIELDS: &[CtxField] = &[CtxField::KStack, CtxField::UStack];
const TRACING_HELPER_CTX_FIELDS: &[CtxField] = &[CtxField::FuncIp, CtxField::AttachCookie];
const PERF_EVENT_HELPER_CTX_FIELDS: &[CtxField] = &[
    CtxField::PerfCounter,
    CtxField::PerfEnabled,
    CtxField::PerfRunning,
];

const BASE_CONTEXT_FIELD_ACCESS_SURFACES: &[BaseContextFieldAccessSurfaceSpec] = &[
    (
        TASK_CTX_FIELDS,
        BaseContextFieldAccessRequirement::TaskFields,
    ),
    (
        &[CtxField::Cpu, CtxField::NumaNode],
        BaseContextFieldAccessRequirement::CpuField,
    ),
    (
        &[
            CtxField::Timestamp,
            CtxField::BootTimestamp,
            CtxField::CoarseTimestamp,
            CtxField::TaiTimestamp,
            CtxField::Jiffies,
        ],
        BaseContextFieldAccessRequirement::TimestampField,
    ),
    (
        PERF_EVENT_CTX_FIELDS,
        BaseContextFieldAccessRequirement::PerfEventField,
    ),
    (
        PERF_EVENT_HELPER_CTX_FIELDS,
        BaseContextFieldAccessRequirement::PerfEventHelperFields,
    ),
    (
        &[CtxField::XdpBuffLen],
        BaseContextFieldAccessRequirement::XdpHelperFields,
    ),
    (
        &[CtxField::PacketLen],
        BaseContextFieldAccessRequirement::PacketLenField,
    ),
    (
        &[CtxField::EthProtocol],
        BaseContextFieldAccessRequirement::EthProtocolField,
    ),
    (
        &[CtxField::CsumLevel],
        BaseContextFieldAccessRequirement::SkbChecksumHelperFields,
    ),
    (
        &[CtxField::HashRecalc],
        BaseContextFieldAccessRequirement::SkbHashHelperFields,
    ),
    (
        &[CtxField::CgroupClassid, CtxField::RouteRealm],
        BaseContextFieldAccessRequirement::TcLwtHelperFields,
    ),
    (
        &[CtxField::SkbCgroupId],
        BaseContextFieldAccessRequirement::TcEgressHelperFields,
    ),
    (SKB_CTX_FIELDS, BaseContextFieldAccessRequirement::SkbFields),
    (
        &[CtxField::SkbHash],
        BaseContextFieldAccessRequirement::PacketHashField,
    ),
    (
        &[CtxField::Data, CtxField::DataEnd],
        BaseContextFieldAccessRequirement::PacketDataFields,
    ),
    (
        REUSEPORT_CTX_FIELDS,
        BaseContextFieldAccessRequirement::ReuseportFields,
    ),
    (
        FLOW_DISSECTOR_CTX_FIELDS,
        BaseContextFieldAccessRequirement::FlowDissectorFields,
    ),
    (
        NETFILTER_CTX_FIELDS,
        BaseContextFieldAccessRequirement::NetfilterFields,
    ),
    (
        &[CtxField::DataMeta],
        BaseContextFieldAccessRequirement::DataMetaField,
    ),
    (
        &[CtxField::IngressIfindex],
        BaseContextFieldAccessRequirement::IngressIfindexField,
    ),
    (
        &[CtxField::RxQueueIndex],
        BaseContextFieldAccessRequirement::RxQueueIndexField,
    ),
    (
        &[CtxField::EgressIfindex],
        BaseContextFieldAccessRequirement::EgressIfindexField,
    ),
    (
        SOCKET_TUPLE_CTX_FIELDS,
        BaseContextFieldAccessRequirement::SocketTupleFields,
    ),
    (
        &[CtxField::Socket, CtxField::MigratingSocket],
        BaseContextFieldAccessRequirement::SocketRefField,
    ),
    (
        &[CtxField::LookupCookie],
        BaseContextFieldAccessRequirement::LookupCookieField,
    ),
    (
        &[CtxField::SocketCookie],
        BaseContextFieldAccessRequirement::SocketCookieField,
    ),
    (
        &[CtxField::SocketUid],
        BaseContextFieldAccessRequirement::SocketUidField,
    ),
    (
        &[CtxField::NetnsCookie],
        BaseContextFieldAccessRequirement::NetnsCookieField,
    ),
    (
        DEVICE_CTX_FIELDS,
        BaseContextFieldAccessRequirement::DeviceFields,
    ),
    (
        SOCK_OPS_CTX_FIELDS,
        BaseContextFieldAccessRequirement::SockOpsFields,
    ),
    (
        &[CtxField::SockState],
        BaseContextFieldAccessRequirement::SockStateField,
    ),
    (
        CGROUP_SOCK_ADDR_CTX_FIELDS,
        BaseContextFieldAccessRequirement::CgroupSockAddrFields,
    ),
    (
        &[CtxField::Family],
        BaseContextFieldAccessRequirement::SocketCommonFields,
    ),
    (
        &[CtxField::SockType],
        BaseContextFieldAccessRequirement::SockTypeField,
    ),
    (
        &[CtxField::Protocol],
        BaseContextFieldAccessRequirement::ProtocolField,
    ),
    (
        &[CtxField::BoundDevIf, CtxField::SockRxQueueMapping],
        BaseContextFieldAccessRequirement::CgroupSockFields,
    ),
    (
        SOCK_MARK_PRIORITY_CTX_FIELDS,
        BaseContextFieldAccessRequirement::SockMarkPriorityFields,
    ),
    (
        CGROUP_SYSCTL_CTX_FIELDS,
        BaseContextFieldAccessRequirement::CgroupSysctlFields,
    ),
    (
        CGROUP_SOCKOPT_CTX_FIELDS,
        BaseContextFieldAccessRequirement::CgroupSockoptFields,
    ),
    (
        &[CtxField::SockoptRetval],
        BaseContextFieldAccessRequirement::CgroupSockoptRetvalField,
    ),
    (
        LIRC_CTX_FIELDS,
        BaseContextFieldAccessRequirement::LircFields,
    ),
    (
        STACK_CTX_FIELDS,
        BaseContextFieldAccessRequirement::StackFields,
    ),
    (
        TRACING_HELPER_CTX_FIELDS,
        BaseContextFieldAccessRequirement::TracingHelperFields,
    ),
];

fn find_ctx_field_access_surface(
    field: &CtxField,
    surfaces: &[ContextFieldAccessSurfaceSpec],
) -> Option<ContextFieldAccessSurfaceSpec> {
    surfaces
        .iter()
        .find(|surface| surface.matches_field(field))
        .cloned()
}

fn program_ctx_field_access_surfaces(
    program_type: EbpfProgramType,
) -> Option<&'static [ContextFieldAccessSurfaceSpec]> {
    PROGRAM_CTX_FIELD_ACCESS_SURFACES
        .iter()
        .find(|surface| surface.program_type == program_type)
        .map(|surface| surface.surfaces)
}

fn find_base_ctx_field_access_requirement(
    field: &CtxField,
) -> Option<BaseContextFieldAccessRequirement> {
    BASE_CONTEXT_FIELD_ACCESS_SURFACES
        .iter()
        .find(|(fields, _)| fields.contains(field))
        .map(|(_, requirement)| *requirement)
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
            "ctx.{} is only available on packet-context programs (xdp, flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, cgroup_skb, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and packet-aware sock_ops callbacks)",
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
    PerfEventHelperFields,
    XdpHelperFields,
    PacketLenField,
    EthProtocolField,
    SkbChecksumHelperFields,
    SkbHashHelperFields,
    TcLwtHelperFields,
    SkbFields,
    PacketHashField,
    PacketDataFields,
    ReuseportFields,
    FlowDissectorFields,
    NetfilterFields,
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
    SockStateField,
    CgroupSockAddrFields,
    SocketCommonFields,
    SockTypeField,
    ProtocolField,
    TcEgressHelperFields,
    CgroupSockFields,
    SockMarkPriorityFields,
    CgroupSysctlFields,
    CgroupSockoptFields,
    CgroupSockoptRetvalField,
    LircFields,
    ArgFields,
    ArgCountField,
    RetvalField,
    StackFields,
    TracingHelperFields,
    TracepointFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseContextFieldAccessProgramSurfaceSpec {
    requirement: BaseContextFieldAccessRequirement,
    program_types: &'static [EbpfProgramType],
}

const SKB_CHECKSUM_HELPER_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::LwtXmit,
    EbpfProgramType::TcAction,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];

const SKB_HASH_HELPER_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::TcAction,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];

const TC_LWT_HELPER_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::TcAction,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
];

const BTF_ARG_COUNT_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Lsm,
    EbpfProgramType::LsmCgroup,
];

const PERF_EVENT_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::PerfEvent];

const TASK_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::KprobeMulti,
    EbpfProgramType::KretprobeMulti,
    EbpfProgramType::Ksyscall,
    EbpfProgramType::KretSyscall,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::RawTracepointWritable,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::UprobeMulti,
    EbpfProgramType::UretprobeMulti,
    EbpfProgramType::Lsm,
    EbpfProgramType::LsmCgroup,
    EbpfProgramType::PerfEvent,
];

const BASE_RUNTIME_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::KprobeMulti,
    EbpfProgramType::KretprobeMulti,
    EbpfProgramType::Ksyscall,
    EbpfProgramType::KretSyscall,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::RawTracepointWritable,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::UprobeMulti,
    EbpfProgramType::UretprobeMulti,
    EbpfProgramType::Lsm,
    EbpfProgramType::LsmCgroup,
    EbpfProgramType::Xdp,
    EbpfProgramType::PerfEvent,
    EbpfProgramType::SocketFilter,
    EbpfProgramType::CgroupDevice,
    EbpfProgramType::SkLookup,
    EbpfProgramType::FlowDissector,
    EbpfProgramType::Netfilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkReuseport,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSysctl,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::LircMode2,
];

const PACKET_LEN_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Xdp,
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkReuseport,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
];

const PACKET_DATA_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Xdp,
    EbpfProgramType::FlowDissector,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkReuseport,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
];

const INGRESS_IFINDEX_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Xdp,
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkLookup,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
];

const XDP_MD_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp];

const STACK_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::KprobeMulti,
    EbpfProgramType::KretprobeMulti,
    EbpfProgramType::Ksyscall,
    EbpfProgramType::KretSyscall,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::RawTracepointWritable,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::UprobeMulti,
    EbpfProgramType::UretprobeMulti,
    EbpfProgramType::PerfEvent,
];

const SKB_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];

const ETH_PROTOCOL_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SkReuseport,
];

const PACKET_HASH_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SkReuseport,
];

const REUSEPORT_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkReuseport];

const FLOW_DISSECTOR_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::FlowDissector];
const NETFILTER_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Netfilter];

const DEVICE_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupDevice];

const SOCK_OPS_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SockOps];

const CGROUP_SOCK_ADDR_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSockAddr];

const CGROUP_SOCK_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSock];

const CGROUP_SYSCTL_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSysctl];

const CGROUP_SOCKOPT_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSockopt];

const LIRC_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::LircMode2];

const TRACING_HELPER_FIELD_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::KprobeMulti,
    EbpfProgramType::KretprobeMulti,
    EbpfProgramType::Ksyscall,
    EbpfProgramType::KretSyscall,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::UprobeMulti,
    EbpfProgramType::UretprobeMulti,
    EbpfProgramType::PerfEvent,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::RawTracepointWritable,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
];

const TRACEPOINT_FIELD_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Tracepoint];

const BASE_CONTEXT_FIELD_ACCESS_PROGRAM_SURFACES: &[BaseContextFieldAccessProgramSurfaceSpec] = &[
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TaskFields,
        program_types: TASK_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CpuField,
        program_types: BASE_RUNTIME_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TimestampField,
        program_types: BASE_RUNTIME_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::XdpHelperFields,
        program_types: XDP_MD_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::PacketLenField,
        program_types: PACKET_LEN_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::EthProtocolField,
        program_types: ETH_PROTOCOL_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::SkbChecksumHelperFields,
        program_types: SKB_CHECKSUM_HELPER_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::SkbHashHelperFields,
        program_types: SKB_HASH_HELPER_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TcLwtHelperFields,
        program_types: TC_LWT_HELPER_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TcEgressHelperFields,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
        ],
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::ArgCountField,
        program_types: BTF_ARG_COUNT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::PerfEventField,
        program_types: PERF_EVENT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::PerfEventHelperFields,
        program_types: PERF_EVENT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::SkbFields,
        program_types: SKB_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::PacketHashField,
        program_types: PACKET_HASH_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::PacketDataFields,
        program_types: PACKET_DATA_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::ReuseportFields,
        program_types: REUSEPORT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::FlowDissectorFields,
        program_types: FLOW_DISSECTOR_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::NetfilterFields,
        program_types: NETFILTER_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::IngressIfindexField,
        program_types: INGRESS_IFINDEX_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::RxQueueIndexField,
        program_types: XDP_MD_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::EgressIfindexField,
        program_types: XDP_MD_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::DeviceFields,
        program_types: DEVICE_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::SockOpsFields,
        program_types: SOCK_OPS_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CgroupSockAddrFields,
        program_types: CGROUP_SOCK_ADDR_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CgroupSockFields,
        program_types: CGROUP_SOCK_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CgroupSysctlFields,
        program_types: CGROUP_SYSCTL_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CgroupSockoptFields,
        program_types: CGROUP_SOCKOPT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::CgroupSockoptRetvalField,
        program_types: CGROUP_SOCKOPT_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::LircFields,
        program_types: LIRC_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TracingHelperFields,
        program_types: TRACING_HELPER_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::StackFields,
        program_types: STACK_FIELD_PROGRAMS,
    },
    BaseContextFieldAccessProgramSurfaceSpec {
        requirement: BaseContextFieldAccessRequirement::TracepointFields,
        program_types: TRACEPOINT_FIELD_PROGRAMS,
    },
];

fn base_context_field_access_program_surface(
    requirement: BaseContextFieldAccessRequirement,
) -> Option<&'static [EbpfProgramType]> {
    BASE_CONTEXT_FIELD_ACCESS_PROGRAM_SURFACES
        .iter()
        .find(|surface| surface.requirement == requirement)
        .map(|surface| surface.program_types)
}

impl BaseContextFieldAccessRequirement {
    fn allowed_by_program_surface(self, program_type: EbpfProgramType) -> bool {
        base_context_field_access_program_surface(self)
            .is_some_and(|program_types| program_types.contains(&program_type))
    }

    fn is_allowed(self, program_type: EbpfProgramType) -> bool {
        match self {
            Self::TaskFields => self.allowed_by_program_surface(program_type),
            Self::CpuField => self.allowed_by_program_surface(program_type),
            Self::TimestampField => self.allowed_by_program_surface(program_type),
            Self::PerfEventField => {
                self.allowed_by_program_surface(program_type) && cfg!(target_arch = "x86_64")
            }
            Self::PerfEventHelperFields => self.allowed_by_program_surface(program_type),
            Self::XdpHelperFields => self.allowed_by_program_surface(program_type),
            Self::PacketLenField => self.allowed_by_program_surface(program_type),
            Self::EthProtocolField => self.allowed_by_program_surface(program_type),
            Self::SkbChecksumHelperFields => self.allowed_by_program_surface(program_type),
            Self::SkbHashHelperFields => self.allowed_by_program_surface(program_type),
            Self::TcLwtHelperFields => self.allowed_by_program_surface(program_type),
            Self::SkbFields => self.allowed_by_program_surface(program_type),
            Self::PacketHashField => self.allowed_by_program_surface(program_type),
            Self::PacketDataFields => self.allowed_by_program_surface(program_type),
            Self::ReuseportFields => self.allowed_by_program_surface(program_type),
            Self::FlowDissectorFields => self.allowed_by_program_surface(program_type),
            Self::NetfilterFields => self.allowed_by_program_surface(program_type),
            Self::DataMetaField => program_type.supports_data_meta_ctx_field(),
            Self::IngressIfindexField => self.allowed_by_program_surface(program_type),
            Self::RxQueueIndexField => self.allowed_by_program_surface(program_type),
            Self::EgressIfindexField => self.allowed_by_program_surface(program_type),
            Self::SocketTupleFields => program_type.supports_socket_tuple_ctx_fields(),
            Self::SocketRefField => program_type.supports_socket_ref_ctx_field(),
            Self::LookupCookieField => program_type.supports_lookup_cookie_ctx_field(),
            Self::SocketCookieField => program_type.supports_socket_cookie_ctx_field(),
            Self::SocketUidField => program_type.supports_socket_uid_ctx_field(),
            Self::NetnsCookieField => program_type.supports_netns_cookie_ctx_field(),
            Self::DeviceFields => self.allowed_by_program_surface(program_type),
            Self::SockOpsFields => self.allowed_by_program_surface(program_type),
            Self::SockStateField => program_type.supports_sock_state_ctx_field(),
            Self::CgroupSockAddrFields => self.allowed_by_program_surface(program_type),
            Self::SocketCommonFields => program_type.supports_socket_common_ctx_fields(),
            Self::SockTypeField => program_type.supports_sock_type_ctx_field(),
            Self::ProtocolField => program_type.supports_protocol_ctx_field(),
            Self::TcEgressHelperFields => self.allowed_by_program_surface(program_type),
            Self::CgroupSockFields => self.allowed_by_program_surface(program_type),
            Self::SockMarkPriorityFields => program_type.supports_sock_mark_priority_ctx_fields(),
            Self::CgroupSysctlFields => self.allowed_by_program_surface(program_type),
            Self::CgroupSockoptFields | Self::CgroupSockoptRetvalField => {
                self.allowed_by_program_surface(program_type)
            }
            Self::LircFields => self.allowed_by_program_surface(program_type),
            Self::ArgFields => program_type.supports_ctx_args(),
            Self::ArgCountField => self.allowed_by_program_surface(program_type),
            Self::RetvalField => program_type.supports_ctx_retval(),
            Self::StackFields => self.allowed_by_program_surface(program_type),
            Self::TracingHelperFields => self.allowed_by_program_surface(program_type),
            Self::TracepointFields => self.allowed_by_program_surface(program_type),
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
            Self::TracingHelperFields => format!(
                "ctx.{} is only available on kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs",
                field.display_name()
            ),
            Self::PerfEventField if !program_type.uses_perf_event_context() => {
                format!(
                    "ctx.{} is only available on perf_event programs",
                    field.display_name()
                )
            }
            Self::PerfEventField => format!(
                "ctx.{} is currently only modeled on x86_64 perf_event programs",
                field.display_name()
            ),
            Self::PerfEventHelperFields => format!(
                "ctx.{} is only available on perf_event programs",
                field.display_name()
            ),
            Self::XdpHelperFields => format!(
                "ctx.{} is only available on xdp programs",
                field.display_name()
            ),
            Self::PacketLenField
            | Self::EthProtocolField
            | Self::PacketHashField
            | Self::PacketDataFields
            | Self::IngressIfindexField
            | Self::RxQueueIndexField
            | Self::EgressIfindexField => packet_field_access_error(program_type, field),
            Self::ReuseportFields => format!(
                "ctx.{} is only available on sk_reuseport programs",
                field.display_name()
            ),
            Self::FlowDissectorFields => format!(
                "ctx.{} is only available on flow_dissector programs",
                field.display_name()
            ),
            Self::NetfilterFields => format!(
                "ctx.{} is only available on netfilter programs",
                field.display_name()
            ),
            Self::SkbChecksumHelperFields => format!(
                "ctx.{} is only available on lwt_xmit, tc_action, tc, tcx, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::SkbHashHelperFields => format!(
                "ctx.{} is only available on lwt_*, tc_action, tc, tcx, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::TcLwtHelperFields => format!(
                "ctx.{} is only available on tc_action, tc, tcx, and lwt_* programs",
                field.display_name()
            ),
            Self::SkbFields => {
                let label = match field {
                    CtxField::TcClassid | CtxField::WireLen | CtxField::TstampType => {
                        "tc_action, tc, and tcx programs"
                    }
                    CtxField::Tstamp | CtxField::Hwtstamp => {
                        "tc_action, tc, tcx, and cgroup_skb programs"
                    }
                    _ => "socket_filter, lwt_*, tc_action, tc, tcx, cgroup_skb, sk_skb, and sk_skb_parser programs",
                };
                format!(
                    "ctx.{} is only available on {label}",
                    field.display_name()
                )
            }
            Self::DataMetaField => {
                format!(
                    "ctx.{} is only available on xdp, tc_action, tc, and tcx programs",
                    field.display_name()
                )
            }
            Self::TcEgressHelperFields => format!(
                "ctx.{} is only available on tc_action, tc:egress, and tcx:egress programs",
                field.display_name()
            ),
            Self::SocketTupleFields => format!(
                "ctx.{} is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ),
            Self::SocketRefField => format!(
                "ctx.{} is only available on socket_filter, tc_action, tc, tcx, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
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
                "ctx.{} is only available on socket_filter, tc_action, tc, tcx, cgroup_skb, sk_skb, and sk_skb_parser programs",
                field.display_name()
            ),
            Self::NetnsCookieField => format!(
                "ctx.{} is only available on socket_filter, tc_action, tc, tcx, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
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
            Self::SockStateField => format!(
                "ctx.{} is only available on cgroup_sock and sock_ops programs",
                field.display_name()
            ),
            Self::CgroupSockAddrFields => format!(
                "ctx.{} is only available on cgroup_sock_addr programs",
                field.display_name()
            ),
            Self::SocketCommonFields => format!(
                "ctx.{} is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                field.display_name()
            ),
            Self::SockTypeField => format!(
                "ctx.{} is only available on cgroup_sock and cgroup_sock_addr programs",
                field.display_name()
            ),
            Self::ProtocolField => format!(
                "ctx.{} is only available on skb-backed packet, lwt_*, tc_action, cgroup_sock, cgroup_sock_addr, sk_lookup, and sk_reuseport programs",
                field.display_name()
            ),
            Self::CgroupSockFields => format!(
                "ctx.{} is only available on cgroup_sock programs",
                field.display_name()
            ),
            Self::SockMarkPriorityFields => format!(
                "ctx.{} is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, cgroup_skb, sk_skb, and sk_skb_parser programs",
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
                "ctx.{} is only available on contexts with argument access (kprobe, kprobe.multi, ksyscall, uprobe, uprobe.multi, fentry, fexit, fmod_ret, tp_btf, lsm, lsm_cgroup, struct_ops, and raw_tracepoint)",
                field.display_name()
            ),
            Self::ArgCountField => {
                "ctx.arg_count is only available on BTF-backed tracing contexts (fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup)".to_string()
            }
            Self::RetvalField => "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit, fmod_ret)".to_string(),
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
        CtxField::Arg(_) => BaseContextFieldAccessRequirement::ArgFields,
        CtxField::ArgCount => BaseContextFieldAccessRequirement::ArgCountField,
        CtxField::RetVal => BaseContextFieldAccessRequirement::RetvalField,
        CtxField::TracepointField(_) => BaseContextFieldAccessRequirement::TracepointFields,
        _ => return find_base_ctx_field_access_requirement(field),
    })
}

impl EbpfProgramType {
    pub(crate) fn base_ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        let requirement = base_ctx_field_access_requirement(field)?;
        (!requirement.is_allowed(*self)).then(|| requirement.error(*self, field))
    }
}

impl ProgramSpec {
    fn ctx_field_access_surfaces(&self) -> Option<&'static [ContextFieldAccessSurfaceSpec]> {
        let attach_shape = self.attach_shape();
        if attach_shape.is_cgroup_sock() {
            Some(CGROUP_SOCK_CTX_FIELD_ACCESS_SURFACES)
        } else if attach_shape.is_cgroup_sockopt() {
            Some(CGROUP_SOCKOPT_CTX_FIELD_ACCESS_SURFACES)
        } else if attach_shape.cgroup_sock_addr().is_some() {
            Some(CGROUP_SOCK_ADDR_CTX_FIELD_ACCESS_SURFACES)
        } else {
            program_ctx_field_access_surfaces(self.program_type())
        }
    }

    fn ctx_field_access_surface(&self, field: &CtxField) -> Option<ContextFieldAccessSurfaceSpec> {
        self.ctx_field_access_surfaces()
            .and_then(|surfaces| find_ctx_field_access_surface(field, surfaces))
    }

    pub(crate) fn cgroup_sock_addr_tuple_alias_field(&self, field: &CtxField) -> Option<CtxField> {
        let (family, hook) = self.attach_shape().cgroup_sock_addr()?;

        CGROUP_SOCK_ADDR_TUPLE_ALIAS_FIELDS
            .iter()
            .find(|alias| alias.matches(field, hook, family))
            .map(|alias| alias.target_field.clone())
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
