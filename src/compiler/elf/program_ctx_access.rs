use super::{CtxField, EbpfProgramType};

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
