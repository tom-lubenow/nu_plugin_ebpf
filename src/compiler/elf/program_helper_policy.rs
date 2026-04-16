use super::{EbpfProgramType, GetSocketCookieArgPolicy};
use crate::compiler::instruction::BpfHelper;
use crate::program_spec::{CgroupSockAddrTarget, CgroupSockTarget, ProgramSpec, TcTarget};

impl TcTarget {
    fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::RedirectPeer if !self.is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            BpfHelper::SkAssign if !self.is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            _ => None,
        }
    }
}

impl CgroupSockAddrTarget {
    fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::Bind if !self.is_connect() => Some(format!(
                "helper '{}' is only valid on cgroup_sock_addr connect4/connect6 hooks",
                helper.name()
            )),
            _ => None,
        }
    }
}

impl CgroupSockTarget {
    fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        let requires_post_bind = matches!(
            member_name,
            "src_ip4" | "src_ip6" | "src_port" | "dst_port" | "dst_ip4" | "dst_ip6"
        );
        if !requires_post_bind || self.is_post_bind() {
            return None;
        }
        Some(format!(
            "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
        ))
    }
}

impl EbpfProgramType {
    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel
                if *self != EbpfProgramType::LircMode2 =>
            {
                Some(format!(
                    "helper '{}' is only valid in lirc_mode2 programs",
                    helper.name()
                ))
            }
            BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail
                if *self != EbpfProgramType::Xdp =>
            {
                Some(format!(
                    "helper '{}' is only valid in xdp programs",
                    helper.name()
                ))
            }
            BpfHelper::SkbChangeTail
            | BpfHelper::SkbStoreBytes
            | BpfHelper::L3CsumReplace
            | BpfHelper::L4CsumReplace
            | BpfHelper::GetHashRecalc
            | BpfHelper::SkbPullData
            | BpfHelper::CsumUpdate
            | BpfHelper::SetHashInvalid
            | BpfHelper::SkbChangeHead
            | BpfHelper::SkbAdjustRoom
                if !matches!(
                    self,
                    EbpfProgramType::Tc | EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc, sk_skb, and sk_skb_parser programs",
                    helper.name()
                ))
            }
            BpfHelper::Redirect if !matches!(self, EbpfProgramType::Xdp | EbpfProgramType::Tc) => {
                Some(format!(
                    "helper '{}' is only valid in xdp and tc programs",
                    helper.name()
                ))
            }
            BpfHelper::RedirectPeer if *self != EbpfProgramType::Tc => Some(format!(
                "helper '{}' is only valid in tc programs",
                helper.name()
            )),
            BpfHelper::SkbSetTstamp if *self != EbpfProgramType::Tc => Some(format!(
                "helper '{}' is only valid in tc programs",
                helper.name()
            )),
            BpfHelper::RedirectNeigh if *self != EbpfProgramType::Tc => Some(format!(
                "helper '{}' is only valid in tc programs",
                helper.name()
            )),
            BpfHelper::GetSocketCookie
                if !matches!(
                    self,
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
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser programs",
                    helper.name()
                ))
            }
            BpfHelper::GetSocketUid
                if !matches!(
                    self,
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    helper.name()
                ))
            }
            BpfHelper::GetNetnsCookie
                if !matches!(
                    self,
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::CgroupSockopt
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::SockOps
                        | EbpfProgramType::SkMsg
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg programs",
                    helper.name()
                ))
            }
            BpfHelper::SkCgroupId | BpfHelper::SkAncestorCgroupId
                if *self != EbpfProgramType::CgroupSkb =>
            {
                Some(format!(
                    "helper '{}' is only valid in cgroup_skb programs",
                    helper.name()
                ))
            }
            BpfHelper::MsgApplyBytes
            | BpfHelper::MsgCorkBytes
            | BpfHelper::MsgPullData
            | BpfHelper::MsgPushData
            | BpfHelper::MsgPopData
            | BpfHelper::MsgRedirectMap
            | BpfHelper::MsgRedirectHash
                if *self != EbpfProgramType::SkMsg =>
            {
                Some(format!(
                    "helper '{}' is only valid in sk_msg programs",
                    helper.name()
                ))
            }
            BpfHelper::SkRedirectMap | BpfHelper::SkRedirectHash
                if !matches!(self, EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser) =>
            {
                Some(format!(
                    "helper '{}' is only valid in sk_skb and sk_skb_parser programs",
                    helper.name()
                ))
            }
            BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp
                if !matches!(
                    self,
                    EbpfProgramType::Xdp
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::SkSkb
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb programs",
                    helper.name()
                ))
            }
            BpfHelper::TcpCheckSyncookie | BpfHelper::TcpGenSyncookie
                if !matches!(self, EbpfProgramType::Xdp | EbpfProgramType::Tc) =>
            {
                Some(format!(
                    "helper '{}' is only valid in xdp and tc programs",
                    helper.name()
                ))
            }
            BpfHelper::SkRelease
                if !matches!(
                    self,
                    EbpfProgramType::Xdp
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::SkLookup
                        | EbpfProgramType::SkSkb
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb programs",
                    helper.name()
                ))
            }
            BpfHelper::SkAssign
                if !matches!(self, EbpfProgramType::Tc | EbpfProgramType::SkLookup) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc and sk_lookup programs",
                    helper.name()
                ))
            }
            BpfHelper::GetListenerSock | BpfHelper::SkFullsock
                if !matches!(self, EbpfProgramType::Tc | EbpfProgramType::CgroupSkb) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc and cgroup_skb programs",
                    helper.name()
                ))
            }
            BpfHelper::TcpSock
                if !matches!(
                    self,
                    EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSockopt
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc, cgroup_skb, cgroup_sockopt, and sock_ops programs",
                    helper.name()
                ))
            }
            BpfHelper::SkcToTcpSock
            | BpfHelper::SkcToTcp6Sock
            | BpfHelper::SkcToTcpTimewaitSock
            | BpfHelper::SkcToTcpRequestSock
            | BpfHelper::SkcToUdp6Sock
            | BpfHelper::SkcToUnixSock
                if !matches!(
                    self,
                    EbpfProgramType::Fentry
                        | EbpfProgramType::Fexit
                        | EbpfProgramType::TpBtf
                        | EbpfProgramType::SkLookup
                        | EbpfProgramType::SkMsg
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    helper.name()
                ))
            }
            BpfHelper::TaskStorageGet | BpfHelper::TaskStorageDelete
                if !matches!(
                    self,
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
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs",
                    helper.name()
                ))
            }
            BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete
                if *self != EbpfProgramType::Lsm =>
            {
                Some(format!(
                    "helper '{}' is only valid in lsm programs",
                    helper.name()
                ))
            }
            BpfHelper::SkStorageGet
                if !matches!(
                    self,
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
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs",
                    helper.name()
                ))
            }
            BpfHelper::SkStorageDelete
                if !matches!(
                    self,
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
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs",
                    helper.name()
                ))
            }
            BpfHelper::SockFromFile
                if !matches!(
                    self,
                    EbpfProgramType::Fentry | EbpfProgramType::Fexit | EbpfProgramType::TpBtf
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in fentry, fexit, and tp_btf programs",
                    helper.name()
                ))
            }
            BpfHelper::SetSockOpt | BpfHelper::GetSockOpt
                if !matches!(
                    self,
                    EbpfProgramType::SockOps
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::CgroupSockopt
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs",
                    helper.name()
                ))
            }
            BpfHelper::Bind if *self != EbpfProgramType::CgroupSockAddr => Some(format!(
                "helper '{}' is only valid in cgroup_sock_addr programs",
                helper.name()
            )),
            BpfHelper::SockOpsCbFlagsSet if *self != EbpfProgramType::SockOps => Some(format!(
                "helper '{}' is only valid in sock_ops programs",
                helper.name()
            )),
            BpfHelper::SockMapUpdate | BpfHelper::SockHashUpdate
                if *self != EbpfProgramType::SockOps =>
            {
                Some(format!(
                    "helper '{}' is only valid in sock_ops programs",
                    helper.name()
                ))
            }
            BpfHelper::LoadHdrOpt | BpfHelper::StoreHdrOpt | BpfHelper::ReserveHdrOpt
                if *self != EbpfProgramType::SockOps =>
            {
                Some(format!(
                    "helper '{}' is only valid in sock_ops programs",
                    helper.name()
                ))
            }
            BpfHelper::SysctlGetName
            | BpfHelper::SysctlGetCurrentValue
            | BpfHelper::SysctlGetNewValue
            | BpfHelper::SysctlSetNewValue
                if *self != EbpfProgramType::CgroupSysctl =>
            {
                Some(format!(
                    "helper '{}' is only valid in cgroup_sysctl programs",
                    helper.name()
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        match (helper, self) {
            (BpfHelper::Redirect, EbpfProgramType::Xdp) => {
                Some((1, "helper 'bpf_redirect' requires arg1 = 0 in xdp programs"))
            }
            (BpfHelper::SkAssign, EbpfProgramType::Tc) => {
                Some((2, "helper 'bpf_sk_assign' requires arg2 = 0 in tc programs"))
            }
            _ => None,
        }
    }

    pub(crate) fn get_socket_cookie_arg_policy(&self) -> Option<GetSocketCookieArgPolicy> {
        match self {
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::CgroupSockAddr
            | EbpfProgramType::SockOps
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(GetSocketCookieArgPolicy::Context),
            EbpfProgramType::CgroupSock => Some(GetSocketCookieArgPolicy::ContextOrSocket),
            EbpfProgramType::Fentry | EbpfProgramType::Fexit | EbpfProgramType::TpBtf => {
                Some(GetSocketCookieArgPolicy::Socket)
            }
            _ => None,
        }
    }
}

impl ProgramSpec {
    fn attach_helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match self {
            ProgramSpec::Tc { target } => target.helper_call_error(helper),
            ProgramSpec::CgroupSockAddr { target } => target.helper_call_error(helper),
            _ => None,
        }
    }

    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        self.program_type()
            .helper_call_error(helper)
            .or_else(|| self.attach_helper_call_error(helper))
    }

    pub(crate) fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        match self {
            ProgramSpec::CgroupSock { target } => {
                target.socket_projection_access_error(member_name)
            }
            _ => None,
        }
    }
}
