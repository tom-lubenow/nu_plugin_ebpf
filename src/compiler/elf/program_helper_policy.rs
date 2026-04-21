use super::{EbpfProgramType, GetSocketCookieArgPolicy, MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::MapKind;
use crate::program_spec::{
    ProgramAttachAddressFamily, ProgramAttachShape, ProgramAttachSockAddrHook, ProgramSpec,
};

#[derive(Debug, Clone, Copy)]
struct HelperProgramSurfaceSpec {
    family: HelperProgramSurfaceFamily,
}

#[derive(Debug, Clone, Copy)]
struct HelperZeroArgRequirementSpec {
    helper: BpfHelper,
    program_type: EbpfProgramType,
    arg_idx: usize,
    error_message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperProgramSurfaceFamily {
    LircMode2,
    Xdp,
    TcSkSkb,
    XdpTc,
    Tc,
    SkbLoadBytes,
    SkbLoadBytesRelative,
    PerfEventOutput,
    GetStackId,
    LegacyProbeRead,
    SocketCookie,
    SocketUid,
    NetnsCookie,
    CgroupSkb,
    SkMsg,
    SkSkb,
    SocketLookup,
    SocketRelease,
    TcSkLookup,
    TcCgroupSkb,
    TcpSock,
    SocketCast,
    TaskStorage,
    Lsm,
    SkStorageGet,
    SkStorageDelete,
    TracingSocket,
    Sockopt,
    CgroupSockAddr,
    SockOps,
    CgroupSysctl,
}

impl HelperProgramSurfaceFamily {
    fn allows(self, program_type: EbpfProgramType) -> bool {
        match self {
            Self::LircMode2 => matches!(program_type, EbpfProgramType::LircMode2),
            Self::Xdp => matches!(program_type, EbpfProgramType::Xdp),
            Self::TcSkSkb => matches!(
                program_type,
                EbpfProgramType::Tc | EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser
            ),
            Self::XdpTc => matches!(program_type, EbpfProgramType::Xdp | EbpfProgramType::Tc),
            Self::Tc => matches!(program_type, EbpfProgramType::Tc),
            Self::SkbLoadBytes => matches!(
                program_type,
                EbpfProgramType::SocketFilter
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::SkSkb
                    | EbpfProgramType::SkSkbParser
            ),
            Self::SkbLoadBytesRelative => matches!(
                program_type,
                EbpfProgramType::SocketFilter | EbpfProgramType::Tc | EbpfProgramType::CgroupSkb
            ),
            Self::PerfEventOutput => matches!(
                program_type,
                EbpfProgramType::CgroupDevice
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSock
                    | EbpfProgramType::CgroupSockopt
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::CgroupSysctl
                    | EbpfProgramType::Kprobe
                    | EbpfProgramType::Kretprobe
                    | EbpfProgramType::Uprobe
                    | EbpfProgramType::Uretprobe
                    | EbpfProgramType::PerfEvent
                    | EbpfProgramType::RawTracepoint
                    | EbpfProgramType::Tracepoint
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::SocketFilter
                    | EbpfProgramType::Tc
                    | EbpfProgramType::SkLookup
                    | EbpfProgramType::SkMsg
                    | EbpfProgramType::SkSkb
                    | EbpfProgramType::SkSkbParser
                    | EbpfProgramType::SockOps
                    | EbpfProgramType::Xdp
            ),
            Self::GetStackId => matches!(
                program_type,
                EbpfProgramType::Kprobe
                    | EbpfProgramType::Kretprobe
                    | EbpfProgramType::Uprobe
                    | EbpfProgramType::Uretprobe
                    | EbpfProgramType::PerfEvent
                    | EbpfProgramType::RawTracepoint
                    | EbpfProgramType::Tracepoint
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
            ),
            Self::LegacyProbeRead => matches!(
                program_type,
                EbpfProgramType::Kprobe
                    | EbpfProgramType::Kretprobe
                    | EbpfProgramType::Uprobe
                    | EbpfProgramType::Uretprobe
                    | EbpfProgramType::Lsm
                    | EbpfProgramType::PerfEvent
                    | EbpfProgramType::RawTracepoint
                    | EbpfProgramType::Tracepoint
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
            ),
            Self::SocketCookie => matches!(
                program_type,
                EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::SocketFilter
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSock
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::SockOps
                    | EbpfProgramType::SkSkb
                    | EbpfProgramType::SkSkbParser
            ),
            Self::SocketUid => matches!(
                program_type,
                EbpfProgramType::SocketFilter
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::SkSkb
                    | EbpfProgramType::SkSkbParser
            ),
            Self::NetnsCookie => matches!(
                program_type,
                EbpfProgramType::SocketFilter
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSock
                    | EbpfProgramType::CgroupSockopt
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::SockOps
                    | EbpfProgramType::SkMsg
            ),
            Self::CgroupSkb => matches!(program_type, EbpfProgramType::CgroupSkb),
            Self::SkMsg => matches!(program_type, EbpfProgramType::SkMsg),
            Self::SkSkb => {
                matches!(
                    program_type,
                    EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser
                )
            }
            Self::SocketLookup => matches!(
                program_type,
                EbpfProgramType::Xdp
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::SkSkb
            ),
            Self::SocketRelease => matches!(
                program_type,
                EbpfProgramType::Xdp
                    | EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::SkLookup
                    | EbpfProgramType::SkSkb
            ),
            Self::TcSkLookup => matches!(
                program_type,
                EbpfProgramType::Tc | EbpfProgramType::SkLookup
            ),
            Self::TcCgroupSkb => {
                matches!(
                    program_type,
                    EbpfProgramType::Tc | EbpfProgramType::CgroupSkb
                )
            }
            Self::TcpSock => matches!(
                program_type,
                EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSockopt
                    | EbpfProgramType::SockOps
            ),
            Self::SocketCast => matches!(
                program_type,
                EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::SkLookup
                    | EbpfProgramType::SkMsg
                    | EbpfProgramType::SkSkb
                    | EbpfProgramType::SkSkbParser
                    | EbpfProgramType::SockOps
            ),
            Self::TaskStorage => matches!(
                program_type,
                EbpfProgramType::Kprobe
                    | EbpfProgramType::Kretprobe
                    | EbpfProgramType::Uprobe
                    | EbpfProgramType::Uretprobe
                    | EbpfProgramType::PerfEvent
                    | EbpfProgramType::RawTracepoint
                    | EbpfProgramType::Tracepoint
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::Lsm
            ),
            Self::Lsm => matches!(program_type, EbpfProgramType::Lsm),
            Self::SkStorageGet => matches!(
                program_type,
                EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSock
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::CgroupSockopt
                    | EbpfProgramType::SockOps
                    | EbpfProgramType::SkMsg
                    | EbpfProgramType::StructOps
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::Lsm
            ),
            Self::SkStorageDelete => matches!(
                program_type,
                EbpfProgramType::Tc
                    | EbpfProgramType::CgroupSkb
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::CgroupSockopt
                    | EbpfProgramType::SockOps
                    | EbpfProgramType::SkMsg
                    | EbpfProgramType::StructOps
                    | EbpfProgramType::Fentry
                    | EbpfProgramType::Fexit
                    | EbpfProgramType::TpBtf
                    | EbpfProgramType::Lsm
            ),
            Self::TracingSocket => matches!(
                program_type,
                EbpfProgramType::Fentry | EbpfProgramType::Fexit | EbpfProgramType::TpBtf
            ),
            Self::Sockopt => matches!(
                program_type,
                EbpfProgramType::SockOps
                    | EbpfProgramType::CgroupSockAddr
                    | EbpfProgramType::CgroupSockopt
            ),
            Self::CgroupSockAddr => matches!(program_type, EbpfProgramType::CgroupSockAddr),
            Self::SockOps => matches!(program_type, EbpfProgramType::SockOps),
            Self::CgroupSysctl => matches!(program_type, EbpfProgramType::CgroupSysctl),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::LircMode2 => "lirc_mode2",
            Self::Xdp => "xdp",
            Self::TcSkSkb => "tc, sk_skb, and sk_skb_parser",
            Self::XdpTc => "xdp and tc",
            Self::Tc => "tc",
            Self::SkbLoadBytes => "socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser",
            Self::SkbLoadBytesRelative => "socket_filter, tc, and cgroup_skb",
            Self::PerfEventOutput => {
                "cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, socket_filter, tc, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp"
            }
            Self::GetStackId => {
                "kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf"
            }
            Self::LegacyProbeRead => {
                "kprobe, kretprobe, uprobe, uretprobe, lsm, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf"
            }
            Self::SocketCookie => {
                "fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser"
            }
            Self::SocketUid => "socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser",
            Self::NetnsCookie => {
                "socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg"
            }
            Self::CgroupSkb => "cgroup_skb",
            Self::SkMsg => "sk_msg",
            Self::SkSkb => "sk_skb and sk_skb_parser",
            Self::SocketLookup => "xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb",
            Self::SocketRelease => "xdp, tc, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb",
            Self::TcSkLookup => "tc and sk_lookup",
            Self::TcCgroupSkb => "tc and cgroup_skb",
            Self::TcpSock => "tc, cgroup_skb, cgroup_sockopt, and sock_ops",
            Self::SocketCast => {
                "fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops"
            }
            Self::TaskStorage => {
                "kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm"
            }
            Self::Lsm => "lsm",
            Self::SkStorageGet => {
                "tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm"
            }
            Self::SkStorageDelete => {
                "tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm"
            }
            Self::TracingSocket => "fentry, fexit, and tp_btf",
            Self::Sockopt => "sock_ops, cgroup_sock_addr, and cgroup_sockopt",
            Self::CgroupSockAddr => "cgroup_sock_addr",
            Self::SockOps => "sock_ops",
            Self::CgroupSysctl => "cgroup_sysctl",
        }
    }
}

impl HelperProgramSurfaceSpec {
    fn allows(self, program_type: EbpfProgramType) -> bool {
        self.family.allows(program_type)
    }

    fn error(self, helper: BpfHelper) -> String {
        format!(
            "helper '{}' is only valid in {} programs",
            helper.name(),
            self.family.label()
        )
    }
}

fn helper_ids_equal(lhs: BpfHelper, rhs: BpfHelper) -> bool {
    lhs as u32 == rhs as u32
}

fn helper_list_contains(helpers: &[BpfHelper], helper: BpfHelper) -> bool {
    helpers
        .iter()
        .copied()
        .any(|candidate| helper_ids_equal(candidate, helper))
}

const TC_INGRESS_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::RedirectPeer, BpfHelper::SkAssign];
const TC_EGRESS_ONLY_HELPERS: &[BpfHelper] = &[
    BpfHelper::GetCgroupClassid,
    BpfHelper::GetRouteRealm,
    BpfHelper::SkbCgroupId,
    BpfHelper::SkbAncestorCgroupId,
];
const CGROUP_SOCK_ADDR_CONNECT_ONLY_HELPERS: &[BpfHelper] = &[
    BpfHelper::Bind,
    BpfHelper::GetSockOpt,
    BpfHelper::SetSockOpt,
];
const CGROUP_SOCK_POST_BIND_ONLY_MEMBERS: &[&str] = &["src_port"];
const CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS: &[&str] = &["src_ip4"];
const CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS: &[&str] = &["src_ip6"];
const HELPER_ZERO_ARG_REQUIREMENTS: &[HelperZeroArgRequirementSpec] = &[
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::Redirect,
        program_type: EbpfProgramType::Xdp,
        arg_idx: 1,
        error_message: "helper 'bpf_redirect' requires arg1 = 0 in xdp programs",
    },
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::SkAssign,
        program_type: EbpfProgramType::Tc,
        arg_idx: 2,
        error_message: "helper 'bpf_sk_assign' requires arg2 = 0 in tc programs",
    },
];

fn helper_program_surface_spec(helper: BpfHelper) -> Option<HelperProgramSurfaceSpec> {
    Some(match helper {
        BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::LircMode2,
            }
        }
        BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::Xdp,
            }
        }
        BpfHelper::XdpGetBuffLen | BpfHelper::XdpLoadBytes | BpfHelper::XdpStoreBytes => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::Xdp,
            }
        }
        BpfHelper::RedirectMap => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Xdp,
        },
        BpfHelper::SkbChangeTail
        | BpfHelper::SkbStoreBytes
        | BpfHelper::L3CsumReplace
        | BpfHelper::L4CsumReplace
        | BpfHelper::GetHashRecalc
        | BpfHelper::SkbPullData
        | BpfHelper::CsumUpdate
        | BpfHelper::SetHashInvalid
        | BpfHelper::SkbChangeHead
        | BpfHelper::SkbAdjustRoom => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkSkb,
        },
        BpfHelper::SkbLoadBytes => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytes,
        },
        BpfHelper::SkbLoadBytesRelative => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytesRelative,
        },
        BpfHelper::Redirect => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::RedirectPeer
        | BpfHelper::RedirectNeigh
        | BpfHelper::SkbSetTstamp
        | BpfHelper::SkbUnderCgroup
        | BpfHelper::GetCgroupClassid
        | BpfHelper::GetRouteRealm
        | BpfHelper::SkbCgroupId
        | BpfHelper::SkbAncestorCgroupId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Tc,
        },
        BpfHelper::PerfEventOutput => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::PerfEventOutput,
        },
        BpfHelper::GetStackId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::GetStackId,
        },
        BpfHelper::ProbeRead => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::LegacyProbeRead,
        },
        BpfHelper::GetSocketCookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketCookie,
        },
        BpfHelper::GetSocketUid => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketUid,
        },
        BpfHelper::GetNetnsCookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::NetnsCookie,
        },
        BpfHelper::SkCgroupId | BpfHelper::SkAncestorCgroupId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSkb,
        },
        BpfHelper::MsgApplyBytes
        | BpfHelper::MsgCorkBytes
        | BpfHelper::MsgPullData
        | BpfHelper::MsgPushData
        | BpfHelper::MsgPopData
        | BpfHelper::MsgRedirectMap
        | BpfHelper::MsgRedirectHash => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkMsg,
        },
        BpfHelper::SkRedirectMap | BpfHelper::SkRedirectHash => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkSkb,
        },
        BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::SocketLookup,
            }
        }
        BpfHelper::TcpCheckSyncookie | BpfHelper::TcpGenSyncookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::SkRelease => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketRelease,
        },
        BpfHelper::SkAssign => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkLookup,
        },
        BpfHelper::GetListenerSock | BpfHelper::SkFullsock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcCgroupSkb,
        },
        BpfHelper::TcpSock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcpSock,
        },
        BpfHelper::SkcToTcpSock
        | BpfHelper::SkcToTcp6Sock
        | BpfHelper::SkcToTcpTimewaitSock
        | BpfHelper::SkcToTcpRequestSock
        | BpfHelper::SkcToUdp6Sock
        | BpfHelper::SkcToUnixSock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketCast,
        },
        BpfHelper::TaskStorageGet | BpfHelper::TaskStorageDelete | BpfHelper::GetCurrentTaskBtf => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::TaskStorage,
            }
        }
        BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Lsm,
        },
        BpfHelper::SkStorageGet => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkStorageGet,
        },
        BpfHelper::SkStorageDelete => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkStorageDelete,
        },
        BpfHelper::SockFromFile => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TracingSocket,
        },
        BpfHelper::SetSockOpt | BpfHelper::GetSockOpt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Sockopt,
        },
        BpfHelper::Bind => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSockAddr,
        },
        BpfHelper::SockOpsCbFlagsSet
        | BpfHelper::SockMapUpdate
        | BpfHelper::SockHashUpdate
        | BpfHelper::LoadHdrOpt
        | BpfHelper::StoreHdrOpt
        | BpfHelper::ReserveHdrOpt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SockOps,
        },
        BpfHelper::SysctlGetName
        | BpfHelper::SysctlGetCurrentValue
        | BpfHelper::SysctlGetNewValue
        | BpfHelper::SysctlSetNewValue => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSysctl,
        },
        _ => return None,
    })
}

impl EbpfProgramType {
    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        helper_program_surface_spec(helper)
            .filter(|spec| !spec.allows(*self))
            .map(|spec| spec.error(helper))
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        HELPER_ZERO_ARG_REQUIREMENTS
            .iter()
            .find(|spec| helper_ids_equal(spec.helper, helper) && spec.program_type == *self)
            .map(|spec| (spec.arg_idx, spec.error_message))
    }

    pub(crate) fn get_socket_cookie_arg_policy(&self) -> Option<GetSocketCookieArgPolicy> {
        if matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SockOps
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
        ) {
            Some(GetSocketCookieArgPolicy::Context)
        } else if matches!(self, EbpfProgramType::CgroupSock) {
            Some(GetSocketCookieArgPolicy::ContextOrSocket)
        } else if matches!(
            self,
            EbpfProgramType::Fentry | EbpfProgramType::Fexit | EbpfProgramType::TpBtf
        ) {
            Some(GetSocketCookieArgPolicy::Socket)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::XdpTc.allows(*self) {
            Some(BpfHelper::Redirect)
        } else {
            None
        }
    }

    pub(crate) fn packet_adjust_helper(&self, mode: PacketAdjustMode) -> Option<BpfHelper> {
        match mode {
            PacketAdjustMode::Head => {
                if HelperProgramSurfaceFamily::Xdp.allows(*self) {
                    Some(BpfHelper::XdpAdjustHead)
                } else if HelperProgramSurfaceFamily::TcSkSkb.allows(*self) {
                    Some(BpfHelper::SkbChangeHead)
                } else {
                    None
                }
            }
            PacketAdjustMode::Meta => HelperProgramSurfaceFamily::Xdp
                .allows(*self)
                .then_some(BpfHelper::XdpAdjustMeta),
            PacketAdjustMode::Tail => {
                if HelperProgramSurfaceFamily::Xdp.allows(*self) {
                    Some(BpfHelper::XdpAdjustTail)
                } else if HelperProgramSurfaceFamily::TcSkSkb.allows(*self) {
                    Some(BpfHelper::SkbChangeTail)
                } else {
                    None
                }
            }
            PacketAdjustMode::Pull => HelperProgramSurfaceFamily::TcSkSkb
                .allows(*self)
                .then_some(BpfHelper::SkbPullData),
            PacketAdjustMode::Room => HelperProgramSurfaceFamily::TcSkSkb
                .allows(*self)
                .then_some(BpfHelper::SkbAdjustRoom),
        }
    }

    pub(crate) fn message_adjust_helper(&self, mode: MessageAdjustMode) -> Option<BpfHelper> {
        HelperProgramSurfaceFamily::SkMsg
            .allows(*self)
            .then_some(match mode {
                MessageAdjustMode::Apply => BpfHelper::MsgApplyBytes,
                MessageAdjustMode::Cork => BpfHelper::MsgCorkBytes,
                MessageAdjustMode::Pull => BpfHelper::MsgPullData,
                MessageAdjustMode::Push => BpfHelper::MsgPushData,
                MessageAdjustMode::Pop => BpfHelper::MsgPopData,
            })
    }

    pub(crate) fn packet_redirect_peer_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::Tc.allows(*self) {
            Some(BpfHelper::RedirectPeer)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_neigh_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::Tc.allows(*self) {
            Some(BpfHelper::RedirectNeigh)
        } else {
            None
        }
    }

    pub(crate) fn socket_redirect_helper(&self, map_kind: MapKind) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::SkMsg.allows(*self) {
            match map_kind {
                MapKind::SockMap => Some(BpfHelper::MsgRedirectMap),
                MapKind::SockHash => Some(BpfHelper::MsgRedirectHash),
                _ => None,
            }
        } else if HelperProgramSurfaceFamily::SkSkb.allows(*self) {
            match map_kind {
                MapKind::SockMap => Some(BpfHelper::SkRedirectMap),
                MapKind::SockHash => Some(BpfHelper::SkRedirectHash),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl ProgramSpec {
    fn attach_helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match self.attach_shape() {
            ProgramAttachShape::Tc { ingress: false }
                if helper_list_contains(TC_INGRESS_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc ingress programs",
                    helper.name()
                ))
            }
            ProgramAttachShape::Tc { ingress: true }
                if helper_list_contains(TC_EGRESS_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc egress programs",
                    helper.name()
                ))
            }
            ProgramAttachShape::CgroupSockAddr {
                hook: hook_kind, ..
            } if helper_list_contains(CGROUP_SOCK_ADDR_CONNECT_ONLY_HELPERS, helper) => {
                if !matches!(hook_kind, ProgramAttachSockAddrHook::Connect) {
                    Some(format!(
                        "helper '{}' is only valid on cgroup_sock_addr connect4/connect6 hooks",
                        helper.name()
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        self.program_type()
            .helper_call_error(helper)
            .or_else(|| self.attach_helper_call_error(helper))
    }

    pub(crate) fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        match self.attach_shape() {
            ProgramAttachShape::CgroupSock {
                post_bind: false, ..
            } if CGROUP_SOCK_POST_BIND_ONLY_MEMBERS.contains(&member_name) => Some(format!(
                "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
            )),
            ProgramAttachShape::CgroupSock {
                post_bind: true,
                family: Some(ProgramAttachAddressFamily::Ipv4),
            } if CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS.contains(&member_name) => None,
            ProgramAttachShape::CgroupSock { .. }
                if CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS.contains(&member_name) =>
            {
                Some(format!(
                    "ctx.sk.{member_name} is only available on cgroup_sock post_bind4 hooks"
                ))
            }
            ProgramAttachShape::CgroupSock {
                post_bind: true,
                family: Some(ProgramAttachAddressFamily::Ipv6),
            } if CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS.contains(&member_name) => None,
            ProgramAttachShape::CgroupSock { .. }
                if CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS.contains(&member_name) =>
            {
                Some(format!(
                    "ctx.sk.{member_name} is only available on cgroup_sock post_bind6 hooks"
                ))
            }
            _ => None,
        }
    }
}
