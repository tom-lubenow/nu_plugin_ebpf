use super::{
    CompileError, CtxField, EbpfProgramType, PacketContextKind, ProbeContext, ProgramTargetKind,
};

impl ProbeContext {
    fn cgroup_sock_addr_attach_kind(&self) -> Option<&str> {
        if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) {
            return None;
        }
        self.target
            .rsplit_once(':')
            .map(|(_, attach_kind)| attach_kind)
    }

    fn cgroup_sock_addr_is_ipv4(&self) -> bool {
        matches!(
            self.cgroup_sock_addr_attach_kind(),
            Some("bind4" | "connect4" | "getpeername4" | "getsockname4" | "sendmsg4" | "recvmsg4")
        )
    }

    fn cgroup_sock_addr_is_ipv6(&self) -> bool {
        matches!(
            self.cgroup_sock_addr_attach_kind(),
            Some("bind6" | "connect6" | "getpeername6" | "getsockname6" | "sendmsg6" | "recvmsg6")
        )
    }

    fn cgroup_sock_addr_has_msg_source(&self) -> bool {
        matches!(
            self.cgroup_sock_addr_attach_kind(),
            Some("sendmsg4" | "sendmsg6" | "recvmsg4" | "recvmsg6")
        )
    }

    fn cgroup_sockopt_attach_kind(&self) -> Option<&str> {
        if !matches!(self.probe_type, EbpfProgramType::CgroupSockopt) {
            return None;
        }
        self.target
            .rsplit_once(':')
            .map(|(_, attach_kind)| attach_kind)
    }

    fn cgroup_sockopt_is_get(&self) -> bool {
        matches!(self.cgroup_sockopt_attach_kind(), Some("get"))
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
    pub fn tracepoint_parts(&self) -> Option<(&str, &str)> {
        if !self.is_tracepoint() {
            return None;
        }

        let mut parts = self.target.splitn(2, '/');
        match (parts.next(), parts.next()) {
            (Some(category), Some(name)) => Some((category, name)),
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

        match field {
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Comm
                if !self.probe_type.supports_task_ctx_fields() =>
            {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                ))
            }
            CtxField::Cpu if !self.probe_type.supports_cpu_ctx_field() => Some(format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                self.probe_type.canonical_prefix()
            )),
            CtxField::Timestamp if !self.probe_type.supports_timestamp_ctx_field() => Some(
                format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                ),
            ),
            CtxField::CgroupId
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::Kprobe
                        | EbpfProgramType::Kretprobe
                        | EbpfProgramType::Fentry
                        | EbpfProgramType::Fexit
                        | EbpfProgramType::Tracepoint
                        | EbpfProgramType::RawTracepoint
                        | EbpfProgramType::Uprobe
                        | EbpfProgramType::Uretprobe
                        | EbpfProgramType::Lsm
                        | EbpfProgramType::Xdp
                        | EbpfProgramType::PerfEvent
                        | EbpfProgramType::SocketFilter
                        | EbpfProgramType::CgroupDevice
                        | EbpfProgramType::SkLookup
                        | EbpfProgramType::SkMsg
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                        | EbpfProgramType::SockOps
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::CgroupSysctl
                        | EbpfProgramType::CgroupSockopt
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::LircMode2
                        | EbpfProgramType::StructOps
                ) =>
            {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                ))
            }
            CtxField::PacketLen if !self.probe_type.supports_packet_len_ctx_field() => {
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
                if self.probe_type.packet_context_kind() != Some(PacketContextKind::SkBuff) =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::Data | CtxField::DataEnd
                if !self.probe_type.supports_packet_data_ctx_fields() =>
            {
                Some(packet_field_error(field))
            }
            CtxField::IngressIfindex if !self.probe_type.supports_ingress_ifindex_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::Ifindex
                if self.probe_type.packet_context_kind() != Some(PacketContextKind::SkBuff) =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::TcIndex | CtxField::SkbHash
                if self.probe_type.packet_context_kind() != Some(PacketContextKind::SkBuff) =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::RxQueueIndex if !self.probe_type.supports_rx_queue_index_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::EgressIfindex if !self.probe_type.supports_egress_ifindex_ctx_field() => {
                Some(packet_field_error(field))
            }
            CtxField::RemoteIp4
            | CtxField::RemoteIp6
            | CtxField::RemotePort
            | CtxField::LocalIp4
            | CtxField::LocalIp6
            | CtxField::LocalPort
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::SkLookup
                        | EbpfProgramType::SkMsg
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::Socket
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::CgroupSock
                        | EbpfProgramType::CgroupSockopt
                        | EbpfProgramType::SkLookup
                        | EbpfProgramType::SkMsg
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sockopt, sk_lookup, and sk_msg programs",
                    field.display_name()
                ))
            }
            CtxField::LookupCookie if !matches!(self.probe_type, EbpfProgramType::SkLookup) => {
                Some(format!(
                    "ctx.{} is only available on sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::SocketCookie
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on skb-backed packet programs, cgroup_sock, cgroup_sock_addr, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::SocketUid
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::SkSkb
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, and sk_skb programs",
                    field.display_name()
                ))
            }
            CtxField::NetnsCookie
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::CgroupSockopt
                        | EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::SkMsg
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::DeviceAccessType | CtxField::DeviceMajor | CtxField::DeviceMinor
                if !matches!(self.probe_type, EbpfProgramType::CgroupDevice) =>
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
                if !matches!(self.probe_type, EbpfProgramType::SockOps) =>
            {
                Some(format!(
                    "ctx.{} is only available on sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::UserFamily
            | CtxField::UserPort
                if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock_addr programs",
                    field.display_name()
                ))
            }
            CtxField::Family
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::SkLookup
                        | EbpfProgramType::SkMsg
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                        | EbpfProgramType::SockOps
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs",
                    field.display_name()
                ))
            }
            CtxField::SockType | CtxField::Protocol
                if !matches!(
                    self.probe_type,
                    EbpfProgramType::CgroupSockAddr
                        | EbpfProgramType::CgroupSock
                        | EbpfProgramType::SkLookup
                ) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs",
                    field.display_name()
                ))
            }
            CtxField::BoundDevIf if !matches!(self.probe_type, EbpfProgramType::CgroupSock) => {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock programs",
                    field.display_name()
                ))
            }
            CtxField::SockMark | CtxField::SockPriority
                if !matches!(self.probe_type, EbpfProgramType::CgroupSock)
                    && self.probe_type.packet_context_kind() != Some(PacketContextKind::SkBuff) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sock, socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
                    field.display_name()
                ))
            }
            CtxField::UserIp4 if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) => {
                Some("ctx.user_ip4 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp4 if !self.cgroup_sock_addr_is_ipv4() => Some(
                "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks (*4)".to_string(),
            ),
            CtxField::UserIp6 if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) => {
                Some("ctx.user_ip6 is only available on cgroup_sock_addr programs".to_string())
            }
            CtxField::UserIp6 if !self.cgroup_sock_addr_is_ipv6() => Some(
                "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks (*6)".to_string(),
            ),
            CtxField::MsgSrcIp4 if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) => {
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
            CtxField::MsgSrcIp6 if !matches!(self.probe_type, EbpfProgramType::CgroupSockAddr) => {
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
                if !matches!(self.probe_type, EbpfProgramType::CgroupSysctl) =>
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
                if !matches!(self.probe_type, EbpfProgramType::CgroupSockopt) =>
            {
                Some(format!(
                    "ctx.{} is only available on cgroup_sockopt programs",
                    field.display_name()
                ))
            }
            CtxField::SockoptRetval if !matches!(self.probe_type, EbpfProgramType::CgroupSockopt) => {
                Some("ctx.sockopt_retval is only available on cgroup_sockopt programs".to_string())
            }
            CtxField::SockoptRetval if !self.cgroup_sockopt_is_get() => Some(
                "ctx.sockopt_retval is only available on cgroup_sockopt:get hooks".to_string(),
            ),
            CtxField::LircSample | CtxField::LircValue | CtxField::LircMode
                if !matches!(self.probe_type, EbpfProgramType::LircMode2) =>
            {
                Some(format!(
                    "ctx.{} is only available on lirc_mode2 programs",
                    field.display_name()
                ))
            }
            CtxField::Arg(_) if !self.probe_type.supports_ctx_args() => Some(format!(
                "ctx.{} is only available on contexts with argument access (kprobe, uprobe, fentry, fexit, tp_btf, lsm, and struct_ops)",
                field.display_name()
            )),
            CtxField::RetVal if !self.probe_type.supports_ctx_retval() => Some(
                "ctx.retval is only available on return probes with return-value access (kretprobe, uretprobe, fexit)".to_string(),
            ),
            CtxField::KStack | CtxField::UStack if !self.probe_type.supports_stack_ctx_fields() => {
                Some(format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    self.probe_type.canonical_prefix()
                ))
            }
            CtxField::TracepointField(name) if !self.probe_type.supports_tracepoint_fields() => {
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
}
