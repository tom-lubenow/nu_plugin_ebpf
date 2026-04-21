use super::{CtxField, EbpfProgramType};
use crate::program_spec::ProgramSpec;

type CtxFieldNameEntry = (&'static str, CtxField);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtxFieldNameResolutionMode {
    Default,
    TracepointPreserveBuiltins,
}

const XDP_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("ifindex", CtxField::IngressIfindex)];
const SKB_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("ifindex", CtxField::Ifindex)];
const SK_MSG_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("size", CtxField::PacketLen)];
const CGROUP_SYSCTL_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[
    ("name", CtxField::SysctlName),
    ("base_name", CtxField::SysctlBaseName),
];
const CGROUP_SOCKOPT_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] =
    &[("retval", CtxField::SockoptRetval)];
const GENERIC_CTX_FIELD_NAME_ENTRIES: &[CtxFieldNameEntry] = &[
    ("pid", CtxField::Pid),
    ("tid", CtxField::Pid),
    ("tgid", CtxField::Tgid),
    ("uid", CtxField::Uid),
    ("gid", CtxField::Gid),
    ("comm", CtxField::Comm),
    ("task", CtxField::Task),
    ("cpu", CtxField::Cpu),
    ("numa_node", CtxField::NumaNode),
    ("numa_node_id", CtxField::NumaNode),
    ("ktime", CtxField::Timestamp),
    ("timestamp", CtxField::Timestamp),
    ("ktime_boot", CtxField::BootTimestamp),
    ("boot_ktime", CtxField::BootTimestamp),
    ("boot_time", CtxField::BootTimestamp),
    ("ktime_coarse", CtxField::CoarseTimestamp),
    ("coarse_ktime", CtxField::CoarseTimestamp),
    ("coarse_time", CtxField::CoarseTimestamp),
    ("ktime_tai", CtxField::TaiTimestamp),
    ("tai_ktime", CtxField::TaiTimestamp),
    ("tai_time", CtxField::TaiTimestamp),
    ("jiffies", CtxField::Jiffies),
    ("func_ip", CtxField::FuncIp),
    ("function_ip", CtxField::FuncIp),
    ("attach_cookie", CtxField::AttachCookie),
    ("bpf_cookie", CtxField::AttachCookie),
    ("cgroup_id", CtxField::CgroupId),
    ("sample_period", CtxField::PerfSamplePeriod),
    ("addr", CtxField::PerfAddr),
    ("perf_counter", CtxField::PerfCounter),
    ("perf_enabled", CtxField::PerfEnabled),
    ("perf_running", CtxField::PerfRunning),
    ("xdp_buff_len", CtxField::XdpBuffLen),
    ("xdp_buffer_len", CtxField::XdpBuffLen),
    ("packet_len", CtxField::PacketLen),
    ("len", CtxField::PacketLen),
    ("pkt_type", CtxField::PktType),
    ("queue_mapping", CtxField::QueueMapping),
    ("eth_protocol", CtxField::EthProtocol),
    ("vlan_present", CtxField::VlanPresent),
    ("vlan_tci", CtxField::VlanTci),
    ("vlan_proto", CtxField::VlanProto),
    ("cb", CtxField::SkbCb),
    ("tc_classid", CtxField::TcClassid),
    ("cgroup_classid", CtxField::CgroupClassid),
    ("route_realm", CtxField::RouteRealm),
    ("csum_level", CtxField::CsumLevel),
    ("skb_cgroup_id", CtxField::SkbCgroupId),
    ("napi_id", CtxField::NapiId),
    ("wire_len", CtxField::WireLen),
    ("gso_segs", CtxField::GsoSegs),
    ("gso_size", CtxField::GsoSize),
    ("tstamp", CtxField::Tstamp),
    ("tstamp_type", CtxField::TstampType),
    ("hwtstamp", CtxField::Hwtstamp),
    ("data", CtxField::Data),
    ("data_meta", CtxField::DataMeta),
    ("data_end", CtxField::DataEnd),
    ("ingress_ifindex", CtxField::IngressIfindex),
    ("rx_queue_index", CtxField::RxQueueIndex),
    ("egress_ifindex", CtxField::EgressIfindex),
    ("tc_index", CtxField::TcIndex),
    ("hash", CtxField::SkbHash),
    ("hash_recalc", CtxField::HashRecalc),
    ("recalc_hash", CtxField::HashRecalc),
    ("user_family", CtxField::UserFamily),
    ("user_ip4", CtxField::UserIp4),
    ("user_ip6", CtxField::UserIp6),
    ("user_port", CtxField::UserPort),
    ("family", CtxField::Family),
    ("sock_type", CtxField::SockType),
    ("type", CtxField::SockType),
    ("protocol", CtxField::Protocol),
    ("sk", CtxField::Socket),
    ("bound_dev_if", CtxField::BoundDevIf),
    ("mark", CtxField::SockMark),
    ("priority", CtxField::SockPriority),
    ("msg_src_ip4", CtxField::MsgSrcIp4),
    ("msg_src_ip6", CtxField::MsgSrcIp6),
    ("remote_ip4", CtxField::RemoteIp4),
    ("remote_ip6", CtxField::RemoteIp6),
    ("remote_port", CtxField::RemotePort),
    ("local_ip4", CtxField::LocalIp4),
    ("local_ip6", CtxField::LocalIp6),
    ("local_port", CtxField::LocalPort),
    ("cookie", CtxField::LookupCookie),
    ("sample", CtxField::LircSample),
    ("raw", CtxField::LircSample),
    ("value", CtxField::LircValue),
    ("mode", CtxField::LircMode),
    ("socket_cookie", CtxField::SocketCookie),
    ("socket_uid", CtxField::SocketUid),
    ("netns_cookie", CtxField::NetnsCookie),
    ("args", CtxField::SockOpsArgs),
    ("snd_cwnd", CtxField::SockOpsSndCwnd),
    ("srtt_us", CtxField::SockOpsSrttUs),
    ("write", CtxField::SysctlWrite),
    ("file_pos", CtxField::SysctlFilePos),
    ("sysctl_name", CtxField::SysctlName),
    ("sysctl_base_name", CtxField::SysctlBaseName),
    ("rtt_min", CtxField::SockOpsRttMin),
    ("snd_ssthresh", CtxField::SockOpsSndSsthresh),
    ("rcv_nxt", CtxField::SockOpsRcvNxt),
    ("snd_nxt", CtxField::SockOpsSndNxt),
    ("snd_una", CtxField::SockOpsSndUna),
    ("packets_out", CtxField::SockOpsPacketsOut),
    ("retrans_out", CtxField::SockOpsRetransOut),
    ("total_retrans", CtxField::SockOpsTotalRetrans),
    ("bytes_received", CtxField::SockOpsBytesReceived),
    ("bytes_acked", CtxField::SockOpsBytesAcked),
    ("skb_len", CtxField::SockOpsSkbLen),
    ("skb_tcp_flags", CtxField::SockOpsSkbTcpFlags),
    ("skb_hwtstamp", CtxField::SockOpsSkbHwtstamp),
    ("level", CtxField::SockoptLevel),
    ("optname", CtxField::SockoptOptname),
    ("optlen", CtxField::SockoptOptlen),
    ("optval", CtxField::SockoptOptval),
    ("optval_end", CtxField::SockoptOptvalEnd),
    ("sockopt_retval", CtxField::SockoptRetval),
    ("retval", CtxField::RetVal),
    ("arg_count", CtxField::ArgCount),
    ("kstack", CtxField::KStack),
    ("ustack", CtxField::UStack),
];
const NON_TRACEPOINT_CTX_FIELD_NAME_ENTRIES: &[CtxFieldNameEntry] = &[
    ("ifindex", CtxField::Ifindex),
    ("access_type", CtxField::DeviceAccessType),
    ("major", CtxField::DeviceMajor),
    ("minor", CtxField::DeviceMinor),
    ("op", CtxField::SockOp),
    ("is_fullsock", CtxField::IsFullsock),
    ("snd_cwnd", CtxField::SockOpsSndCwnd),
    ("srtt_us", CtxField::SockOpsSrttUs),
    ("cb_flags", CtxField::SockOpsCbFlags),
    ("state", CtxField::SockState),
    ("rx_queue_mapping", CtxField::SockRxQueueMapping),
    ("rtt_min", CtxField::SockOpsRttMin),
    ("snd_ssthresh", CtxField::SockOpsSndSsthresh),
    ("rcv_nxt", CtxField::SockOpsRcvNxt),
    ("snd_nxt", CtxField::SockOpsSndNxt),
    ("snd_una", CtxField::SockOpsSndUna),
    ("mss_cache", CtxField::SockOpsMssCache),
    ("ecn_flags", CtxField::SockOpsEcnFlags),
    ("rate_delivered", CtxField::SockOpsRateDelivered),
    ("rate_interval_us", CtxField::SockOpsRateIntervalUs),
    ("packets_out", CtxField::SockOpsPacketsOut),
    ("retrans_out", CtxField::SockOpsRetransOut),
    ("total_retrans", CtxField::SockOpsTotalRetrans),
    ("segs_in", CtxField::SockOpsSegsIn),
    ("data_segs_in", CtxField::SockOpsDataSegsIn),
    ("segs_out", CtxField::SockOpsSegsOut),
    ("data_segs_out", CtxField::SockOpsDataSegsOut),
    ("lost_out", CtxField::SockOpsLostOut),
    ("sacked_out", CtxField::SockOpsSackedOut),
    ("sk_txhash", CtxField::SockOpsSkTxhash),
    ("bytes_received", CtxField::SockOpsBytesReceived),
    ("bytes_acked", CtxField::SockOpsBytesAcked),
    ("skb_len", CtxField::SockOpsSkbLen),
    ("skb_tcp_flags", CtxField::SockOpsSkbTcpFlags),
    ("skb_hwtstamp", CtxField::SockOpsSkbHwtstamp),
];
const TRACEPOINT_PRESERVED_CTX_FIELD_NAMES: &[&str] = &[
    "pid",
    "tid",
    "tgid",
    "uid",
    "gid",
    "comm",
    "cpu",
    "numa_node",
    "numa_node_id",
    "ktime",
    "timestamp",
    "ktime_boot",
    "boot_ktime",
    "boot_time",
    "ktime_coarse",
    "coarse_ktime",
    "coarse_time",
    "ktime_tai",
    "tai_ktime",
    "tai_time",
    "jiffies",
    "cgroup_id",
    "arg_count",
    "kstack",
    "ustack",
];

fn find_ctx_field_name_entry(entries: &[CtxFieldNameEntry], field_name: &str) -> Option<CtxField> {
    entries
        .iter()
        .find(|(name, _)| *name == field_name)
        .map(|(_, field)| field.clone())
}

fn is_ctx_arg_field_name(field_name: &str) -> bool {
    field_name
        .strip_prefix("arg")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()))
}

fn ctx_field_alias(program_type: EbpfProgramType, field_name: &str) -> Option<CtxField> {
    program_type
        .ctx_field_alias_entries()
        .and_then(|entries| find_ctx_field_name_entry(entries, field_name))
}

fn ctx_field_name_resolution_mode(program_type: EbpfProgramType) -> CtxFieldNameResolutionMode {
    if program_type.preserves_tracepoint_builtin_ctx_field_names() {
        CtxFieldNameResolutionMode::TracepointPreserveBuiltins
    } else {
        CtxFieldNameResolutionMode::Default
    }
}

fn generic_ctx_field_from_name(field_name: &str) -> Result<CtxField, String> {
    if let Some(field) = find_ctx_field_name_entry(GENERIC_CTX_FIELD_NAME_ENTRIES, field_name) {
        return Ok(field);
    }

    if let Some(suffix) = field_name.strip_prefix("arg") {
        let num: u8 = suffix
            .parse()
            .map_err(|_| format!("Invalid arg: {}", field_name))?;
        return Ok(CtxField::Arg(num));
    }

    Ok(CtxField::TracepointField(field_name.to_string()))
}

fn non_tracepoint_ctx_field_from_name(field_name: &str) -> Option<CtxField> {
    find_ctx_field_name_entry(NON_TRACEPOINT_CTX_FIELD_NAME_ENTRIES, field_name)
}

fn tracepoint_preserves_builtin_ctx_field_name(field_name: &str) -> bool {
    TRACEPOINT_PRESERVED_CTX_FIELD_NAMES.contains(&field_name) || is_ctx_arg_field_name(field_name)
}

impl EbpfProgramType {
    fn ctx_field_alias_entries(&self) -> Option<&'static [CtxFieldNameEntry]> {
        match self {
            EbpfProgramType::Xdp => Some(XDP_CTX_FIELD_ALIAS_ENTRIES),
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(SKB_CTX_FIELD_ALIAS_ENTRIES),
            EbpfProgramType::SkMsg => Some(SK_MSG_CTX_FIELD_ALIAS_ENTRIES),
            EbpfProgramType::CgroupSysctl => Some(CGROUP_SYSCTL_CTX_FIELD_ALIAS_ENTRIES),
            EbpfProgramType::CgroupSockopt => Some(CGROUP_SOCKOPT_CTX_FIELD_ALIAS_ENTRIES),
            _ => None,
        }
    }

    fn preserves_tracepoint_builtin_ctx_field_names(&self) -> bool {
        matches!(self, EbpfProgramType::Tracepoint)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolve_ctx_field_name(&self, field_name: &str) -> Result<CtxField, String> {
        if let Some(field) = ctx_field_alias(*self, field_name) {
            return Ok(field);
        }

        match ctx_field_name_resolution_mode(*self) {
            CtxFieldNameResolutionMode::Default => {
                if let Some(field) = non_tracepoint_ctx_field_from_name(field_name) {
                    return Ok(field);
                }

                generic_ctx_field_from_name(field_name)
            }
            CtxFieldNameResolutionMode::TracepointPreserveBuiltins => {
                self.resolve_tracepoint_ctx_field_name(field_name)
            }
        }
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
        if tracepoint_preserves_builtin_ctx_field_name(field_name) {
            generic_ctx_field_from_name(field_name)
        } else {
            Ok(CtxField::TracepointField(field_name.to_string()))
        }
    }
}

impl ProgramSpec {
    pub(crate) fn resolve_ctx_field_name(&self, field_name: &str) -> Result<CtxField, String> {
        self.program_type().resolve_ctx_field_name(field_name)
    }
}
