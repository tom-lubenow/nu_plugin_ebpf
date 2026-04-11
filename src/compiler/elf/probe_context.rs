use super::{CompileError, CtxField, EbpfProgramType, ProbeContext, ProgramTargetKind};
use crate::compiler::instruction::BpfHelper;
use crate::program_spec::{
    CgroupSockAddrTarget, CgroupSockTarget, CgroupSockoptTarget, ProgramSpec, TcTarget,
};
use aya::programs::{CgroupSockAddrAttachType, CgroupSockoptAttachType};

impl ProbeContext {
    pub(crate) fn parsed_program_spec(&self) -> Option<ProgramSpec> {
        ProgramSpec::from_program_type_target(self.probe_type, &self.target).ok()
    }

    pub(crate) fn tc_target(&self) -> Option<TcTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::Tc { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn tc_is_ingress(&self) -> bool {
        self.tc_target().is_some_and(|target| target.is_ingress())
    }

    pub(crate) fn cgroup_sock_target(&self) -> Option<CgroupSockTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSock { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn cgroup_sock_is_post_bind(&self) -> bool {
        self.cgroup_sock_target()
            .is_some_and(|target| target.is_post_bind())
    }

    fn cgroup_sock_addr_target(&self) -> Option<CgroupSockAddrTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSockAddr { target } => Some(target),
            _ => None,
        }
    }

    fn cgroup_sock_addr_is_ipv4(&self) -> bool {
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::Bind4
                    | CgroupSockAddrAttachType::Connect4
                    | CgroupSockAddrAttachType::GetPeerName4
                    | CgroupSockAddrAttachType::GetSockName4
                    | CgroupSockAddrAttachType::UDPSendMsg4
                    | CgroupSockAddrAttachType::UDPRecvMsg4
            )
        })
    }

    fn cgroup_sock_addr_is_ipv6(&self) -> bool {
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::Bind6
                    | CgroupSockAddrAttachType::Connect6
                    | CgroupSockAddrAttachType::GetPeerName6
                    | CgroupSockAddrAttachType::GetSockName6
                    | CgroupSockAddrAttachType::UDPSendMsg6
                    | CgroupSockAddrAttachType::UDPRecvMsg6
            )
        })
    }

    fn cgroup_sock_addr_has_msg_source(&self) -> bool {
        self.cgroup_sock_addr_target().is_some_and(|target| {
            matches!(
                target.attach_type,
                CgroupSockAddrAttachType::UDPSendMsg4
                    | CgroupSockAddrAttachType::UDPSendMsg6
                    | CgroupSockAddrAttachType::UDPRecvMsg4
                    | CgroupSockAddrAttachType::UDPRecvMsg6
            )
        })
    }

    fn cgroup_sockopt_target(&self) -> Option<CgroupSockoptTarget> {
        match self.parsed_program_spec()? {
            ProgramSpec::CgroupSockopt { target } => Some(target),
            _ => None,
        }
    }

    fn cgroup_sockopt_is_get(&self) -> bool {
        self.cgroup_sockopt_target()
            .is_some_and(|target| matches!(target.attach_type, CgroupSockoptAttachType::Get))
    }

    /// Create a new probe context
    pub fn new(probe_type: EbpfProgramType, target: impl Into<String>) -> Self {
        Self {
            probe_type,
            target: target.into(),
            struct_ops_value_type_name: None,
        }
    }

    /// Create a probe context for a `struct_ops` callback.
    pub fn new_struct_ops_callback(
        value_type_name: impl Into<String>,
        callback_name: impl Into<String>,
    ) -> Self {
        Self {
            probe_type: EbpfProgramType::StructOps,
            target: callback_name.into(),
            struct_ops_value_type_name: Some(value_type_name.into()),
        }
    }

    /// Create a default probe context for tests or legacy code
    ///
    /// Defaults to kprobe with empty target, which means:
    /// - Not a return probe (retval access will fail)
    /// - Not userspace (read-str defaults to kernel reads)
    pub fn default_for_tests() -> Self {
        Self {
            probe_type: EbpfProgramType::Kprobe,
            target: String::new(),
            struct_ops_value_type_name: None,
        }
    }

    /// Returns true if this is a return probe
    pub fn is_return_probe(&self) -> bool {
        self.probe_type.is_return_probe()
    }

    /// Returns true if this is a userspace probe
    pub fn is_userspace(&self) -> bool {
        self.probe_type.is_userspace()
    }

    /// Returns true if this is a tracepoint
    pub fn is_tracepoint(&self) -> bool {
        matches!(self.probe_type.target_kind(), ProgramTargetKind::Tracepoint)
    }

    /// Get tracepoint category and name
    ///
    /// For tracepoint "syscalls/sys_enter_openat", returns Some(("syscalls", "sys_enter_openat"))
    pub fn tracepoint_parts(&self) -> Option<(String, String)> {
        match self.parsed_program_spec()? {
            ProgramSpec::Tracepoint { category, name } => Some((category, name)),
            _ => None,
        }
    }

    /// Returns a user-facing error message when a context field is not valid
    /// for this program type.
    pub fn ctx_field_access_error(&self, field: &CtxField) -> Option<String> {
        let packet_field_error = |field: &CtxField| {
            if self.probe_type.packet_context_kind().is_some() {
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                )
            } else {
                format!(
                    "ctx.{} is only available on packet-context programs (xdp, socket_filter, tc, cgroup_skb, sk_msg, sk_skb, sk_skb_parser, and packet-aware sock_ops callbacks)",
                    field.display_name()
                )
            }
        };
        let program_type = self.probe_type;

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
            CtxField::Timestamp if !program_type.supports_timestamp_ctx_field() => Some(
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    program_type.canonical_prefix()
                ),
            ),
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
            CtxField::Data | CtxField::DataEnd if !program_type.supports_packet_data_ctx_fields() =>
            {
                Some(packet_field_error(field))
            }
            CtxField::IngressIfindex if !program_type.supports_ingress_ifindex_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::Ifindex if !program_type.supports_skb_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::TcIndex | CtxField::SkbHash if !program_type.supports_skb_ctx_fields() =>
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
            CtxField::Socket if !program_type.supports_socket_ref_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sockopt, sk_lookup, and sk_msg programs",
                    field.display_name()
                ))
            }
            CtxField::LookupCookie if !program_type.supports_lookup_cookie_ctx_field() => {
                Some(format!(
                    "ctx.{} is only available on sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::SocketCookie if !program_type.supports_socket_cookie_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::SocketUid if !program_type.supports_socket_uid_ctx_field() =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, and sk_skb programs",
                    field.display_name()
                ))
            }
            CtxField::NetnsCookie if !program_type.supports_netns_cookie_ctx_field() =>
            {
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
            CtxField::Family if !program_type.supports_socket_common_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
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
            CtxField::UserIp4 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.user_ip4 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp4 if !self.cgroup_sock_addr_is_ipv4() => Some(
                "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)".to_string(),
            ),
            CtxField::UserIp6 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.user_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)".to_string(),
            ),
            CtxField::MsgSrcIp4 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.msg_src_ip4 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::MsgSrcIp4 if !self.cgroup_sock_addr_is_ipv4() => Some(
                "ctx.msg_src_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)"
                    .to_string(),
            ),
            CtxField::MsgSrcIp4 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
            CtxField::MsgSrcIp6 if !program_type.supports_cgroup_sock_addr_ctx_fields() => {
                Some("ctx.msg_src_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.msg_src_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)"
                    .to_string(),
            ),
            CtxField::MsgSrcIp6 if !self.cgroup_sock_addr_has_msg_source() => Some(
                "ctx.msg_src_ip6 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks"
                    .to_string(),
            ),
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
            CtxField::SockoptRetval if !self.cgroup_sockopt_is_get() => Some(
                "ctx.sockopt_retval is only available on cgroup_sockopt:get hooks".to_string(),
            ),
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

    pub fn validate_ctx_field_access(&self, field: &CtxField) -> Result<(), CompileError> {
        if let Some(message) = self.ctx_field_access_error(field) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        Ok(())
    }

    /// Returns a user-facing error message when a helper is not valid
    /// for this program type or attach context.
    pub fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel
                if self.probe_type != EbpfProgramType::LircMode2 =>
            {
                Some(format!(
                    "helper '{}' is only valid in lirc_mode2 programs",
                    helper.name()
                ))
            }
            BpfHelper::Redirect
                if !matches!(self.probe_type, EbpfProgramType::Xdp | EbpfProgramType::Tc) =>
            {
                Some(format!(
                    "helper '{}' is only valid in xdp and tc programs",
                    helper.name()
                ))
            }
            BpfHelper::RedirectNeigh if self.probe_type != EbpfProgramType::Tc => Some(format!(
                "helper '{}' is only valid in tc programs",
                helper.name()
            )),
            BpfHelper::RedirectPeer if !self.tc_is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            BpfHelper::MsgApplyBytes
            | BpfHelper::MsgCorkBytes
            | BpfHelper::MsgPullData
            | BpfHelper::MsgPushData
            | BpfHelper::MsgPopData
                if self.probe_type != EbpfProgramType::SkMsg =>
            {
                Some(format!(
                    "helper '{}' is only valid in sk_msg programs",
                    helper.name()
                ))
            }
            _ => None,
        }
    }

    /// Returns a user-facing error message when a socket projection member is
    /// not valid for this program type or attach context.
    pub fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        let requires_post_bind = matches!(
            member_name,
            "src_ip4" | "src_ip6" | "src_port" | "dst_port" | "dst_ip4" | "dst_ip6"
        );
        if self.probe_type != EbpfProgramType::CgroupSock || !requires_post_bind {
            return None;
        }
        if self.cgroup_sock_is_post_bind() {
            return None;
        }
        Some(format!(
            "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
        ))
    }
}
