use super::{EbpfProgramType, GetSocketCookieArgPolicy, MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::MapKind;
use crate::program_spec::{
    ProgramAttachAddressFamily, ProgramAttachShape, ProgramAttachSockAddrHook, ProgramSpec,
};

#[derive(Debug, Clone, Copy)]
struct HelperProgramSurfaceSpec {
    allowed_programs: &'static [EbpfProgramType],
    allowed_programs_label: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct HelperZeroArgRequirementSpec {
    helper: BpfHelper,
    program_type: EbpfProgramType,
    arg_idx: usize,
    error_message: &'static str,
}

impl HelperProgramSurfaceSpec {
    fn allows(self, program_type: EbpfProgramType) -> bool {
        self.allowed_programs.contains(&program_type)
    }

    fn error(self, helper: BpfHelper) -> String {
        format!(
            "helper '{}' is only valid in {} programs",
            helper.name(),
            self.allowed_programs_label
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

const LIRC_MODE2_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::LircMode2];
const XDP_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp];
const TC_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Tc];
const TC_SK_SKB_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Tc,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const XDP_TC_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp, EbpfProgramType::Tc];
const SOCKET_COOKIE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SockOps,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const SOCKET_UID_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const NETNS_COOKIE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SockOps,
    EbpfProgramType::SkMsg,
];
const CGROUP_SKB_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSkb];
const SK_MSG_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkMsg];
const SK_SKB_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkSkb, EbpfProgramType::SkSkbParser];
const SOCKET_LOOKUP_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Xdp,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SkSkb,
];
const SOCKET_RELEASE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Xdp,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SkLookup,
    EbpfProgramType::SkSkb,
];
const TC_SK_LOOKUP_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Tc, EbpfProgramType::SkLookup];
const TC_CGROUP_SKB_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Tc, EbpfProgramType::CgroupSkb];
const TCP_SOCK_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::SockOps,
];
const SOCKET_CAST_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
    EbpfProgramType::SkLookup,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
];
const TASK_STORAGE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::PerfEvent,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Lsm,
];
const LSM_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Lsm];
const SK_STORAGE_GET_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::SockOps,
    EbpfProgramType::SkMsg,
    EbpfProgramType::StructOps,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Lsm,
];
const SK_STORAGE_DELETE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::SockOps,
    EbpfProgramType::SkMsg,
    EbpfProgramType::StructOps,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Lsm,
];
const TRACING_SOCKET_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
];
const SOCKOPT_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SockOps,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::CgroupSockopt,
];
const CGROUP_SOCK_ADDR_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSockAddr];
const SOCK_OPS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SockOps];
const CGROUP_SYSCTL_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSysctl];
const GET_SOCKET_COOKIE_CONTEXT_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SockOps,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const GET_SOCKET_COOKIE_CONTEXT_OR_SOCKET_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::CgroupSock];
const GET_SOCKET_COOKIE_SOCKET_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::TpBtf,
];
const TC_INGRESS_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::RedirectPeer, BpfHelper::SkAssign];
const CGROUP_SOCK_ADDR_CONNECT_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::Bind];
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
                allowed_programs: LIRC_MODE2_PROGRAMS,
                allowed_programs_label: "lirc_mode2",
            }
        }
        BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail => {
            HelperProgramSurfaceSpec {
                allowed_programs: XDP_PROGRAMS,
                allowed_programs_label: "xdp",
            }
        }
        BpfHelper::RedirectMap => HelperProgramSurfaceSpec {
            allowed_programs: XDP_PROGRAMS,
            allowed_programs_label: "xdp",
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
            allowed_programs: TC_SK_SKB_PROGRAMS,
            allowed_programs_label: "tc, sk_skb, and sk_skb_parser",
        },
        BpfHelper::Redirect => HelperProgramSurfaceSpec {
            allowed_programs: XDP_TC_PROGRAMS,
            allowed_programs_label: "xdp and tc",
        },
        BpfHelper::RedirectPeer | BpfHelper::RedirectNeigh | BpfHelper::SkbSetTstamp => {
            HelperProgramSurfaceSpec {
                allowed_programs: TC_PROGRAMS,
                allowed_programs_label: "tc",
            }
        }
        BpfHelper::GetSocketCookie => HelperProgramSurfaceSpec {
            allowed_programs: SOCKET_COOKIE_PROGRAMS,
            allowed_programs_label: "fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser",
        },
        BpfHelper::GetSocketUid => HelperProgramSurfaceSpec {
            allowed_programs: SOCKET_UID_PROGRAMS,
            allowed_programs_label: "socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser",
        },
        BpfHelper::GetNetnsCookie => HelperProgramSurfaceSpec {
            allowed_programs: NETNS_COOKIE_PROGRAMS,
            allowed_programs_label: "socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg",
        },
        BpfHelper::SkCgroupId | BpfHelper::SkAncestorCgroupId => HelperProgramSurfaceSpec {
            allowed_programs: CGROUP_SKB_PROGRAMS,
            allowed_programs_label: "cgroup_skb",
        },
        BpfHelper::MsgApplyBytes
        | BpfHelper::MsgCorkBytes
        | BpfHelper::MsgPullData
        | BpfHelper::MsgPushData
        | BpfHelper::MsgPopData
        | BpfHelper::MsgRedirectMap
        | BpfHelper::MsgRedirectHash => HelperProgramSurfaceSpec {
            allowed_programs: SK_MSG_PROGRAMS,
            allowed_programs_label: "sk_msg",
        },
        BpfHelper::SkRedirectMap | BpfHelper::SkRedirectHash => HelperProgramSurfaceSpec {
            allowed_programs: SK_SKB_PROGRAMS,
            allowed_programs_label: "sk_skb and sk_skb_parser",
        },
        BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
            HelperProgramSurfaceSpec {
                allowed_programs: SOCKET_LOOKUP_PROGRAMS,
                allowed_programs_label: "xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb",
            }
        }
        BpfHelper::TcpCheckSyncookie | BpfHelper::TcpGenSyncookie => HelperProgramSurfaceSpec {
            allowed_programs: XDP_TC_PROGRAMS,
            allowed_programs_label: "xdp and tc",
        },
        BpfHelper::SkRelease => HelperProgramSurfaceSpec {
            allowed_programs: SOCKET_RELEASE_PROGRAMS,
            allowed_programs_label: "xdp, tc, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb",
        },
        BpfHelper::SkAssign => HelperProgramSurfaceSpec {
            allowed_programs: TC_SK_LOOKUP_PROGRAMS,
            allowed_programs_label: "tc and sk_lookup",
        },
        BpfHelper::GetListenerSock | BpfHelper::SkFullsock => HelperProgramSurfaceSpec {
            allowed_programs: TC_CGROUP_SKB_PROGRAMS,
            allowed_programs_label: "tc and cgroup_skb",
        },
        BpfHelper::TcpSock => HelperProgramSurfaceSpec {
            allowed_programs: TCP_SOCK_PROGRAMS,
            allowed_programs_label: "tc, cgroup_skb, cgroup_sockopt, and sock_ops",
        },
        BpfHelper::SkcToTcpSock
        | BpfHelper::SkcToTcp6Sock
        | BpfHelper::SkcToTcpTimewaitSock
        | BpfHelper::SkcToTcpRequestSock
        | BpfHelper::SkcToUdp6Sock
        | BpfHelper::SkcToUnixSock => HelperProgramSurfaceSpec {
            allowed_programs: SOCKET_CAST_PROGRAMS,
            allowed_programs_label: "fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops",
        },
        BpfHelper::TaskStorageGet | BpfHelper::TaskStorageDelete => HelperProgramSurfaceSpec {
            allowed_programs: TASK_STORAGE_PROGRAMS,
            allowed_programs_label: "kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm",
        },
        BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete => HelperProgramSurfaceSpec {
            allowed_programs: LSM_PROGRAMS,
            allowed_programs_label: "lsm",
        },
        BpfHelper::SkStorageGet => HelperProgramSurfaceSpec {
            allowed_programs: SK_STORAGE_GET_PROGRAMS,
            allowed_programs_label: "tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm",
        },
        BpfHelper::SkStorageDelete => HelperProgramSurfaceSpec {
            allowed_programs: SK_STORAGE_DELETE_PROGRAMS,
            allowed_programs_label: "tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm",
        },
        BpfHelper::SockFromFile => HelperProgramSurfaceSpec {
            allowed_programs: TRACING_SOCKET_PROGRAMS,
            allowed_programs_label: "fentry, fexit, and tp_btf",
        },
        BpfHelper::SetSockOpt | BpfHelper::GetSockOpt => HelperProgramSurfaceSpec {
            allowed_programs: SOCKOPT_PROGRAMS,
            allowed_programs_label: "sock_ops, cgroup_sock_addr, and cgroup_sockopt",
        },
        BpfHelper::Bind => HelperProgramSurfaceSpec {
            allowed_programs: CGROUP_SOCK_ADDR_PROGRAMS,
            allowed_programs_label: "cgroup_sock_addr",
        },
        BpfHelper::SockOpsCbFlagsSet
        | BpfHelper::SockMapUpdate
        | BpfHelper::SockHashUpdate
        | BpfHelper::LoadHdrOpt
        | BpfHelper::StoreHdrOpt
        | BpfHelper::ReserveHdrOpt => HelperProgramSurfaceSpec {
            allowed_programs: SOCK_OPS_PROGRAMS,
            allowed_programs_label: "sock_ops",
        },
        BpfHelper::SysctlGetName
        | BpfHelper::SysctlGetCurrentValue
        | BpfHelper::SysctlGetNewValue
        | BpfHelper::SysctlSetNewValue => HelperProgramSurfaceSpec {
            allowed_programs: CGROUP_SYSCTL_PROGRAMS,
            allowed_programs_label: "cgroup_sysctl",
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
        if GET_SOCKET_COOKIE_CONTEXT_PROGRAMS.contains(self) {
            Some(GetSocketCookieArgPolicy::Context)
        } else if GET_SOCKET_COOKIE_CONTEXT_OR_SOCKET_PROGRAMS.contains(self) {
            Some(GetSocketCookieArgPolicy::ContextOrSocket)
        } else if GET_SOCKET_COOKIE_SOCKET_PROGRAMS.contains(self) {
            Some(GetSocketCookieArgPolicy::Socket)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_helper(&self) -> Option<BpfHelper> {
        if XDP_TC_PROGRAMS.contains(self) {
            Some(BpfHelper::Redirect)
        } else {
            None
        }
    }

    pub(crate) fn packet_adjust_helper(&self, mode: PacketAdjustMode) -> Option<BpfHelper> {
        match mode {
            PacketAdjustMode::Head => {
                if XDP_PROGRAMS.contains(self) {
                    Some(BpfHelper::XdpAdjustHead)
                } else if TC_SK_SKB_PROGRAMS.contains(self) {
                    Some(BpfHelper::SkbChangeHead)
                } else {
                    None
                }
            }
            PacketAdjustMode::Meta => XDP_PROGRAMS
                .contains(self)
                .then_some(BpfHelper::XdpAdjustMeta),
            PacketAdjustMode::Tail => {
                if XDP_PROGRAMS.contains(self) {
                    Some(BpfHelper::XdpAdjustTail)
                } else if TC_SK_SKB_PROGRAMS.contains(self) {
                    Some(BpfHelper::SkbChangeTail)
                } else {
                    None
                }
            }
            PacketAdjustMode::Pull => TC_SK_SKB_PROGRAMS
                .contains(self)
                .then_some(BpfHelper::SkbPullData),
            PacketAdjustMode::Room => TC_SK_SKB_PROGRAMS
                .contains(self)
                .then_some(BpfHelper::SkbAdjustRoom),
        }
    }

    pub(crate) fn message_adjust_helper(&self, mode: MessageAdjustMode) -> Option<BpfHelper> {
        SK_MSG_PROGRAMS.contains(self).then_some(match mode {
            MessageAdjustMode::Apply => BpfHelper::MsgApplyBytes,
            MessageAdjustMode::Cork => BpfHelper::MsgCorkBytes,
            MessageAdjustMode::Pull => BpfHelper::MsgPullData,
            MessageAdjustMode::Push => BpfHelper::MsgPushData,
            MessageAdjustMode::Pop => BpfHelper::MsgPopData,
        })
    }

    pub(crate) fn packet_redirect_peer_helper(&self) -> Option<BpfHelper> {
        if TC_PROGRAMS.contains(self) {
            Some(BpfHelper::RedirectPeer)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_neigh_helper(&self) -> Option<BpfHelper> {
        if TC_PROGRAMS.contains(self) {
            Some(BpfHelper::RedirectNeigh)
        } else {
            None
        }
    }

    pub(crate) fn socket_redirect_helper(&self, map_kind: MapKind) -> Option<BpfHelper> {
        if SK_MSG_PROGRAMS.contains(self) {
            match map_kind {
                MapKind::SockMap => Some(BpfHelper::MsgRedirectMap),
                MapKind::SockHash => Some(BpfHelper::MsgRedirectHash),
                _ => None,
            }
        } else if SK_SKB_PROGRAMS.contains(self) {
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
