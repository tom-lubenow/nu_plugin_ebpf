use super::{CtxField, EbpfProgramType};

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
        "data_meta" => CtxField::DataMeta,
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

impl EbpfProgramType {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolve_ctx_field_name(&self, field_name: &str) -> Result<CtxField, String> {
        if let Some(field) = ctx_field_alias(*self, field_name) {
            return Ok(field);
        }

        if matches!(self, EbpfProgramType::Tracepoint) {
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

    pub(crate) fn resolve_tracepoint_ctx_field_name(
        &self,
        field_name: &str,
    ) -> Result<CtxField, String> {
        let resolved = self.resolve_ctx_field_name(field_name)?;
        if tracepoint_preserves_builtin_ctx_field(&resolved) {
            Ok(resolved)
        } else {
            Ok(CtxField::TracepointField(field_name.to_string()))
        }
    }
}
