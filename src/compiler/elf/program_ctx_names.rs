use super::{CtxField, EbpfProgramType};
use crate::program_spec::ProgramSpec;

type CtxFieldNameEntry = (&'static str, CtxField);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldNameEntry {
    pub(crate) name: &'static str,
    pub(crate) field: CtxField,
}

struct CtxFieldAliasSurface {
    program_types: &'static [EbpfProgramType],
    entries: &'static [CtxFieldNameEntry],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtxFieldNameResolutionMode {
    Default,
    TracepointPreserveBuiltins,
}

const XDP_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp];
const SKB_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::Netkit,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const SK_MSG_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkMsg];
const CGROUP_SYSCTL_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSysctl];
const CGROUP_SOCKOPT_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::CgroupSockopt];
const NETFILTER_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Netfilter];
const ITER_CTX_FIELD_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Iter];
const TRACEPOINT_PRESERVE_BUILTIN_CTX_FIELD_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Tracepoint];

const XDP_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("ifindex", CtxField::IngressIfindex)];
const SKB_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("ifindex", CtxField::Ifindex)];
const SK_MSG_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[("size", CtxField::PacketLen)];
const CGROUP_SYSCTL_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[
    ("name", CtxField::SysctlName),
    ("base_name", CtxField::SysctlBaseName),
    ("current_value", CtxField::SysctlCurrentValue),
    ("new_value", CtxField::SysctlNewValue),
];
const CGROUP_SOCKOPT_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] =
    &[("retval", CtxField::SockoptRetval)];
const NETFILTER_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[
    ("state", CtxField::NetfilterState),
    ("nf_state", CtxField::NetfilterState),
    ("skb", CtxField::NetfilterSkb),
    ("hook", CtxField::NetfilterHook),
    ("pf", CtxField::NetfilterProtocolFamily),
    ("protocol_family", CtxField::NetfilterProtocolFamily),
];
const ITER_CTX_FIELD_ALIAS_ENTRIES: &[CtxFieldNameEntry] = &[
    ("task", CtxField::IterTask),
    ("iter_task", CtxField::IterTask),
    ("meta", CtxField::IterMeta),
    ("iter_meta", CtxField::IterMeta),
    ("fd", CtxField::IterFd),
    ("iter_fd", CtxField::IterFd),
    ("file", CtxField::IterFile),
    ("iter_file", CtxField::IterFile),
    ("vma", CtxField::IterVma),
    ("iter_vma", CtxField::IterVma),
    ("cgroup", CtxField::IterCgroup),
    ("iter_cgroup", CtxField::IterCgroup),
    ("map", CtxField::IterMap),
    ("iter_map", CtxField::IterMap),
    ("key", CtxField::IterMapKey),
    ("iter_key", CtxField::IterMapKey),
    ("value", CtxField::IterMapValue),
    ("iter_value", CtxField::IterMapValue),
    ("prog", CtxField::IterProg),
    ("iter_prog", CtxField::IterProg),
    ("link", CtxField::IterLink),
    ("iter_link", CtxField::IterLink),
    ("sk_common", CtxField::IterSkCommon),
    ("sock_common", CtxField::IterSkCommon),
    ("iter_sk_common", CtxField::IterSkCommon),
    ("udp_sk", CtxField::IterUdpSk),
    ("iter_udp_sk", CtxField::IterUdpSk),
    ("unix_sk", CtxField::IterUnixSk),
    ("iter_unix_sk", CtxField::IterUnixSk),
    ("uid", CtxField::IterUid),
    ("iter_uid", CtxField::IterUid),
    ("bucket", CtxField::IterBucket),
    ("iter_bucket", CtxField::IterBucket),
    ("dmabuf", CtxField::IterDmabuf),
    ("iter_dmabuf", CtxField::IterDmabuf),
    ("rt", CtxField::IterIpv6Route),
    ("route", CtxField::IterIpv6Route),
    ("ipv6_route", CtxField::IterIpv6Route),
    ("iter_ipv6_route", CtxField::IterIpv6Route),
    ("cache", CtxField::IterKmemCache),
    ("kmem_cache", CtxField::IterKmemCache),
    ("iter_kmem_cache", CtxField::IterKmemCache),
    ("ksym", CtxField::IterKsym),
    ("iter_ksym", CtxField::IterKsym),
    ("netlink_sk", CtxField::IterNetlinkSk),
    ("iter_netlink_sk", CtxField::IterNetlinkSk),
    ("sk", CtxField::IterSock),
    ("sock", CtxField::IterSock),
    ("iter_sock", CtxField::IterSock),
];
const CTX_FIELD_ALIAS_SURFACES: &[CtxFieldAliasSurface] = &[
    CtxFieldAliasSurface {
        program_types: XDP_CTX_FIELD_ALIAS_PROGRAMS,
        entries: XDP_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: SKB_CTX_FIELD_ALIAS_PROGRAMS,
        entries: SKB_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: SK_MSG_CTX_FIELD_ALIAS_PROGRAMS,
        entries: SK_MSG_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: CGROUP_SYSCTL_CTX_FIELD_ALIAS_PROGRAMS,
        entries: CGROUP_SYSCTL_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: CGROUP_SOCKOPT_CTX_FIELD_ALIAS_PROGRAMS,
        entries: CGROUP_SOCKOPT_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: NETFILTER_CTX_FIELD_ALIAS_PROGRAMS,
        entries: NETFILTER_CTX_FIELD_ALIAS_ENTRIES,
    },
    CtxFieldAliasSurface {
        program_types: ITER_CTX_FIELD_ALIAS_PROGRAMS,
        entries: ITER_CTX_FIELD_ALIAS_ENTRIES,
    },
];
const GENERIC_CTX_FIELD_NAME_ENTRIES: &[CtxFieldNameEntry] = &[
    ("pid", CtxField::Pid),
    ("tid", CtxField::Pid),
    ("tgid", CtxField::Tgid),
    ("pid_tgid", CtxField::PidTgid),
    ("current_pid_tgid", CtxField::PidTgid),
    ("uid", CtxField::Uid),
    ("gid", CtxField::Gid),
    ("uid_gid", CtxField::UidGid),
    ("current_uid_gid", CtxField::UidGid),
    ("comm", CtxField::Comm),
    ("task", CtxField::Task),
    ("current_task", CtxField::Task),
    ("cgroup", CtxField::Cgroup),
    ("current_cgroup", CtxField::Cgroup),
    ("cpu", CtxField::Cpu),
    ("numa_node", CtxField::NumaNode),
    ("numa_node_id", CtxField::NumaNode),
    ("random", CtxField::Random),
    ("prandom_u32", CtxField::Random),
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
    ("ip_protocol", CtxField::Protocol),
    ("sk", CtxField::Socket),
    ("flow_keys", CtxField::FlowKeys),
    ("netfilter_hook", CtxField::NetfilterHook),
    ("netfilter_pf", CtxField::NetfilterProtocolFamily),
    ("bind_inany", CtxField::BindInany),
    ("migrating_sk", CtxField::MigratingSocket),
    ("migrating_socket", CtxField::MigratingSocket),
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
    ("reply", CtxField::SockOpsReply),
    ("replylong", CtxField::SockOpsReplyLong),
    ("snd_cwnd", CtxField::SockOpsSndCwnd),
    ("srtt_us", CtxField::SockOpsSrttUs),
    ("write", CtxField::SysctlWrite),
    ("file_pos", CtxField::SysctlFilePos),
    ("sysctl_name", CtxField::SysctlName),
    ("sysctl_base_name", CtxField::SysctlBaseName),
    ("sysctl_current_value", CtxField::SysctlCurrentValue),
    ("sysctl_new_value", CtxField::SysctlNewValue),
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
    ("device_access", CtxField::DeviceAccess),
    ("device_type", CtxField::DeviceType),
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
    "pid_tgid",
    "current_pid_tgid",
    "uid",
    "gid",
    "uid_gid",
    "current_uid_gid",
    "comm",
    "current_task",
    "current_cgroup",
    "cpu",
    "numa_node",
    "numa_node_id",
    "random",
    "prandom_u32",
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
    "func_ip",
    "function_ip",
    "attach_cookie",
    "bpf_cookie",
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

fn push_unique_ctx_field_name_entries(
    out: &mut Vec<ContextFieldNameEntry>,
    entries: &[CtxFieldNameEntry],
) {
    for (name, field) in entries {
        if out.iter().any(|entry| entry.name == *name) {
            continue;
        }

        out.push(ContextFieldNameEntry {
            name: *name,
            field: field.clone(),
        });
    }
}

fn push_tracepoint_preserved_ctx_field_name_entries(out: &mut Vec<ContextFieldNameEntry>) {
    for name in TRACEPOINT_PRESERVED_CTX_FIELD_NAMES {
        if out.iter().any(|entry| entry.name == *name) {
            continue;
        }

        let Ok(field) = generic_ctx_field_from_name(name) else {
            continue;
        };

        out.push(ContextFieldNameEntry { name: *name, field });
    }
}

impl EbpfProgramType {
    fn ctx_field_alias_entries(&self) -> Option<&'static [CtxFieldNameEntry]> {
        CTX_FIELD_ALIAS_SURFACES
            .iter()
            .find(|surface| surface.program_types.contains(self))
            .map(|surface| surface.entries)
    }

    fn preserves_tracepoint_builtin_ctx_field_names(&self) -> bool {
        TRACEPOINT_PRESERVE_BUILTIN_CTX_FIELD_PROGRAMS.contains(self)
    }

    pub(crate) fn ctx_field_name_entries(&self) -> Vec<ContextFieldNameEntry> {
        let mut entries = Vec::new();

        if let Some(alias_entries) = self.ctx_field_alias_entries() {
            push_unique_ctx_field_name_entries(&mut entries, alias_entries);
        }

        match ctx_field_name_resolution_mode(*self) {
            CtxFieldNameResolutionMode::Default => {
                push_unique_ctx_field_name_entries(
                    &mut entries,
                    NON_TRACEPOINT_CTX_FIELD_NAME_ENTRIES,
                );
                push_unique_ctx_field_name_entries(&mut entries, GENERIC_CTX_FIELD_NAME_ENTRIES);
            }
            CtxFieldNameResolutionMode::TracepointPreserveBuiltins => {
                push_tracepoint_preserved_ctx_field_name_entries(&mut entries);
            }
        }

        entries
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::ContextFieldCompatibilityRequirement;
    use crate::compiler::{BpfHelper, ctx_field_backing_helper};
    use crate::program_spec::ProgramSpec;
    use std::collections::HashSet;

    fn assert_unique_ctx_field_entry_names(table_name: &str, entries: &[CtxFieldNameEntry]) {
        let mut seen = HashSet::new();

        for (name, field) in entries {
            assert!(
                seen.insert(*name),
                "duplicate context field alias '{name}' in {table_name} for {field:?}"
            );
        }
    }

    fn resolved_field_from_entries(
        entries: &[ContextFieldNameEntry],
        name: &str,
    ) -> Option<CtxField> {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.field.clone())
    }

    fn verifier_diff_const_body<'a>(source: &'a str, name: &str, delimiter: char) -> &'a str {
        let marker = format!("const {name} = {delimiter}");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("expected verifier_diff.nu constant {name}"))
            + marker.len();
        let end_marker = format!("\n{}", if delimiter == '[' { ']' } else { '}' });
        let end = source[start..]
            .find(&end_marker)
            .unwrap_or_else(|| panic!("expected verifier_diff.nu constant {name} to terminate"));
        &source[start..start + end]
    }

    fn verifier_diff_quoted_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
        let marker = format!("{field}: \"");
        let start = line.find(&marker)? + marker.len();
        let rest = &line[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    fn verifier_diff_dollar_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
        let marker = format!("{field}: $");
        let start = line.find(&marker)? + marker.len();
        let rest = &line[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '}')
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }

    fn verifier_diff_feature_record<'a>(
        script: &'a str,
        feature_const: &str,
    ) -> (&'a str, &'a str, &'a str, Option<&'a str>) {
        let body = verifier_diff_const_body(script, feature_const, '{');
        let key = verifier_diff_quoted_field(body, "key")
            .unwrap_or_else(|| panic!("expected {feature_const} to declare key"));
        let min_kernel = verifier_diff_quoted_field(body, "min_kernel")
            .unwrap_or_else(|| panic!("expected {feature_const} to declare min_kernel"));
        let source = verifier_diff_quoted_field(body, "source")
            .unwrap_or_else(|| panic!("expected {feature_const} to declare source"));
        let max_kernel = verifier_diff_quoted_field(body, "max_kernel_exclusive");
        (key, min_kernel, source, max_kernel)
    }

    #[test]
    fn test_context_field_name_tables_are_unique() {
        assert_unique_ctx_field_entry_names(
            "generic context field names",
            GENERIC_CTX_FIELD_NAME_ENTRIES,
        );
        assert_unique_ctx_field_entry_names(
            "non-tracepoint context field names",
            NON_TRACEPOINT_CTX_FIELD_NAME_ENTRIES,
        );

        let mut preserved_names = HashSet::new();
        for name in TRACEPOINT_PRESERVED_CTX_FIELD_NAMES {
            assert!(
                preserved_names.insert(*name),
                "duplicate tracepoint-preserved context field name '{name}'"
            );
        }

        let mut surfaced_program_types = HashSet::new();
        for (index, surface) in CTX_FIELD_ALIAS_SURFACES.iter().enumerate() {
            assert_unique_ctx_field_entry_names(
                &format!("context alias surface #{index}"),
                surface.entries,
            );

            let mut local_program_types = HashSet::new();
            for program_type in surface.program_types {
                assert!(
                    EbpfProgramType::supported_program_types().contains(program_type),
                    "{program_type:?} in context alias surface #{index} must be a supported program type"
                );
                assert!(
                    local_program_types.insert(*program_type),
                    "duplicate program type {program_type:?} in context alias surface #{index}"
                );
                assert!(
                    surfaced_program_types.insert(*program_type),
                    "program type {program_type:?} appears in multiple context alias surfaces"
                );
            }
        }
    }

    #[test]
    fn test_context_field_name_tables_resolve_through_program_types() {
        for (name, expected) in GENERIC_CTX_FIELD_NAME_ENTRIES {
            assert_eq!(
                EbpfProgramType::Kprobe
                    .resolve_ctx_field_name(name)
                    .unwrap_or_else(|err| panic!("generic ctx.{name} should resolve: {err}")),
                *expected,
                "generic ctx.{name} should resolve to {expected:?}"
            );
        }

        for (name, expected) in NON_TRACEPOINT_CTX_FIELD_NAME_ENTRIES {
            assert_eq!(
                EbpfProgramType::Kprobe
                    .resolve_ctx_field_name(name)
                    .unwrap_or_else(|err| {
                        panic!("non-tracepoint ctx.{name} should resolve: {err}")
                    }),
                *expected,
                "non-tracepoint ctx.{name} should resolve to {expected:?}"
            );
        }

        for surface in CTX_FIELD_ALIAS_SURFACES {
            for program_type in surface.program_types {
                for (name, expected) in surface.entries {
                    assert_eq!(
                        program_type
                            .resolve_ctx_field_name(name)
                            .unwrap_or_else(|err| panic!(
                                "{program_type:?} ctx.{name} should resolve: {err}"
                            )),
                        *expected,
                        "{program_type:?} ctx.{name} alias should resolve to {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_verifier_diff_generic_context_field_metadata_matches_rust() {
        let verifier_diff = include_str!("../../../scripts/verifier_diff.nu");
        let table_body =
            verifier_diff_const_body(verifier_diff, "CONTEXT_FIELD_KERNEL_FEATURES", '[');

        for line in table_body.lines() {
            let Some(field_name) = verifier_diff_quoted_field(line, "field") else {
                continue;
            };
            let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu context feature for ctx.{field_name}")
            });
            let field = EbpfProgramType::resolve_untyped_ctx_field_name(field_name)
                .unwrap_or_else(|err| panic!("ctx.{field_name} should resolve in Rust: {err}"));
            let requirement = ContextFieldCompatibilityRequirement::for_field(&field)
                .unwrap_or_else(|| {
                    panic!("ctx.{field_name} should have Rust compatibility metadata")
                });
            let (key, min_kernel, source, max_kernel) =
                verifier_diff_feature_record(verifier_diff, feature_const);

            assert_eq!(
                key,
                requirement.key(),
                "verifier_diff.nu context feature key drifted for ctx.{field_name}"
            );
            assert_eq!(
                min_kernel,
                requirement.minimum_kernel(),
                "verifier_diff.nu context min_kernel drifted for ctx.{field_name}"
            );
            assert_eq!(
                source,
                requirement.minimum_kernel_source(),
                "verifier_diff.nu context source drifted for ctx.{field_name}"
            );
            assert_eq!(
                max_kernel, None,
                "context fields should not have max_kernel_exclusive metadata"
            );
        }
    }

    #[test]
    fn test_verifier_diff_target_context_field_metadata_matches_rust() {
        let verifier_diff = include_str!("../../../scripts/verifier_diff.nu");
        let table_body = verifier_diff_const_body(
            verifier_diff,
            "TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS",
            '[',
        );

        for line in table_body.lines() {
            let Some(target) = verifier_diff_quoted_field(line, "target") else {
                continue;
            };
            let field_name = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu target context field for {target}")
            });
            let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
                panic!(
                    "expected verifier_diff.nu target context feature for {target} ctx.{field_name}"
                )
            });
            let spec = ProgramSpec::parse(target)
                .unwrap_or_else(|err| panic!("{target} should parse in Rust: {err}"));
            let program_type = spec.program_type();
            let target_string = spec.target_string();
            let field = program_type
                .resolve_ctx_field_name(field_name)
                .unwrap_or_else(|err| {
                    panic!("{target} ctx.{field_name} should resolve in Rust: {err}")
                });
            let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_target(
                &field,
                Some(program_type),
                Some(&target_string),
            )
            .unwrap_or_else(|| {
                panic!("{target} ctx.{field_name} should have Rust compatibility metadata")
            });
            let (key, min_kernel, source, max_kernel) =
                verifier_diff_feature_record(verifier_diff, feature_const);

            assert_eq!(
                key,
                requirement.key(),
                "verifier_diff.nu target context key drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                min_kernel,
                requirement.minimum_kernel(),
                "verifier_diff.nu target context min_kernel drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                source,
                requirement.minimum_kernel_source(),
                "verifier_diff.nu target context source drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                max_kernel, None,
                "target context fields should not have max_kernel_exclusive metadata"
            );
        }
    }

    #[test]
    fn test_verifier_diff_context_field_helper_metadata_matches_rust() {
        let verifier_diff = include_str!("../../../scripts/verifier_diff.nu");
        let table_body = verifier_diff_const_body(
            verifier_diff,
            "CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS",
            '[',
        );

        for line in table_body.lines() {
            let Some(target) = verifier_diff_quoted_field(line, "target") else {
                continue;
            };
            let field_name = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu helper-backed context field for {target}")
            });
            let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
                panic!(
                    "expected verifier_diff.nu helper-backed context feature for {target} ctx.{field_name}"
                )
            });
            let spec = ProgramSpec::parse(target)
                .unwrap_or_else(|err| panic!("{target} should parse in Rust: {err}"));
            let program_type = spec.program_type();
            let field = program_type
                .resolve_ctx_field_name(field_name)
                .unwrap_or_else(|err| {
                    panic!("{target} ctx.{field_name} should resolve in Rust: {err}")
                });
            let helper = ctx_field_backing_helper(&field).unwrap_or_else(|| {
                panic!("{target} ctx.{field_name} should have a backing helper")
            });
            let requirement = helper.compatibility_requirement().unwrap_or_else(|| {
                panic!(
                    "{target} ctx.{field_name} backing helper {} should have compatibility metadata",
                    helper.name()
                )
            });
            let (key, min_kernel, source, max_kernel) =
                verifier_diff_feature_record(verifier_diff, feature_const);

            assert_eq!(
                key,
                requirement.key(),
                "verifier_diff.nu context helper key drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                min_kernel,
                requirement.minimum_kernel(),
                "verifier_diff.nu context helper min_kernel drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                source,
                requirement.minimum_kernel_source(),
                "verifier_diff.nu context helper source drifted for {target} ctx.{field_name}"
            );
            assert_eq!(
                max_kernel, None,
                "context helper features should not have max_kernel_exclusive metadata"
            );
        }
    }

    #[test]
    fn test_verifier_diff_context_projection_metadata_matches_rust() {
        let verifier_diff = include_str!("../../../scripts/verifier_diff.nu");
        let table_body = verifier_diff_const_body(
            verifier_diff,
            "CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS",
            '[',
        );

        for line in table_body.lines() {
            let Some(target) = verifier_diff_quoted_field(line, "target") else {
                continue;
            };
            let raw_access = verifier_diff_quoted_field(line, "raw_access").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu context projection for {target}")
            });
            let helper_name = verifier_diff_quoted_field(line, "helper").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu projection helper for {target} ctx.{raw_access}")
            });
            let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
                panic!("expected verifier_diff.nu projection feature for {target} ctx.{raw_access}")
            });
            let helper = BpfHelper::from_name(helper_name).unwrap_or_else(|| {
                panic!("projection helper {helper_name} should be modeled in Rust")
            });
            let requirement = helper.compatibility_requirement().unwrap_or_else(|| {
                panic!("projection helper {helper_name} should have compatibility metadata")
            });
            let (key, min_kernel, source, max_kernel) =
                verifier_diff_feature_record(verifier_diff, feature_const);

            assert_eq!(
                key,
                requirement.key(),
                "verifier_diff.nu projection helper key drifted for {target} ctx.{raw_access}"
            );
            assert_eq!(
                min_kernel,
                requirement.minimum_kernel(),
                "verifier_diff.nu projection helper min_kernel drifted for {target} ctx.{raw_access}"
            );
            assert_eq!(
                source,
                requirement.minimum_kernel_source(),
                "verifier_diff.nu projection helper source drifted for {target} ctx.{raw_access}"
            );
            assert_eq!(
                max_kernel, None,
                "context projection helper features should not have max_kernel_exclusive metadata"
            );
        }
    }

    #[test]
    fn test_context_field_name_entries_follow_program_resolution_precedence() {
        let xdp_entries = EbpfProgramType::Xdp.ctx_field_name_entries();
        assert_eq!(
            resolved_field_from_entries(&xdp_entries, "ifindex"),
            Some(CtxField::IngressIfindex)
        );
        assert_eq!(
            xdp_entries
                .iter()
                .filter(|entry| entry.name == "ifindex")
                .count(),
            1,
            "program-specific ctx.ifindex alias should shadow the generic name"
        );

        let netfilter_entries = EbpfProgramType::Netfilter.ctx_field_name_entries();
        assert_eq!(
            resolved_field_from_entries(&netfilter_entries, "state"),
            Some(CtxField::NetfilterState)
        );

        let tracepoint_entries = EbpfProgramType::Tracepoint.ctx_field_name_entries();
        assert_eq!(
            resolved_field_from_entries(&tracepoint_entries, "current_cgroup"),
            Some(CtxField::Cgroup)
        );
        assert_eq!(
            resolved_field_from_entries(&tracepoint_entries, "cgroup"),
            None,
            "ctx.cgroup on tracepoints is a payload field name, not the current cgroup builtin"
        );
    }

    #[test]
    fn test_context_field_name_entries_resolve_consistently() {
        for program_type in EbpfProgramType::supported_program_types() {
            let mut names = HashSet::new();
            for entry in program_type.ctx_field_name_entries() {
                assert!(
                    names.insert(entry.name),
                    "{program_type:?} surfaced ctx.{} more than once",
                    entry.name
                );
                assert_eq!(
                    program_type.resolve_ctx_field_name(entry.name),
                    Ok(entry.field.clone()),
                    "{program_type:?} surfaced ctx.{} should resolve to {:?}",
                    entry.name,
                    entry.field
                );
            }
        }
    }

    #[test]
    fn test_tracepoint_preserved_names_resolve_to_builtins() {
        for name in TRACEPOINT_PRESERVED_CTX_FIELD_NAMES {
            let field = EbpfProgramType::Tracepoint
                .resolve_tracepoint_ctx_field_name(name)
                .expect("tracepoint builtin name should resolve");

            assert!(
                !matches!(field, CtxField::TracepointField(_)),
                "tracepoint-preserved context field name '{name}' resolved to a payload field"
            );
        }
    }

    #[test]
    fn test_tracepoint_cgroup_payload_name_is_not_stolen() {
        assert_eq!(
            EbpfProgramType::Tracepoint
                .resolve_tracepoint_ctx_field_name("current_cgroup")
                .expect("current_cgroup should resolve"),
            CtxField::Cgroup
        );
        assert_eq!(
            EbpfProgramType::Tracepoint
                .resolve_tracepoint_ctx_field_name("cgroup")
                .expect("cgroup should resolve as payload"),
            CtxField::TracepointField("cgroup".to_string())
        );
    }

    #[test]
    fn test_tracepoint_task_payload_name_is_not_stolen() {
        assert_eq!(
            EbpfProgramType::Tracepoint
                .resolve_tracepoint_ctx_field_name("current_task")
                .expect("current_task should resolve"),
            CtxField::Task
        );
        assert_eq!(
            EbpfProgramType::Tracepoint
                .resolve_tracepoint_ctx_field_name("task")
                .expect("task should resolve as payload"),
            CtxField::TracepointField("task".to_string())
        );
    }

    #[test]
    fn test_iterator_task_alias_does_not_steal_current_task() {
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("task")
                .expect("iter task alias should resolve"),
            CtxField::IterTask
        );
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("iter_task")
                .expect("iter_task alias should resolve"),
            CtxField::IterTask
        );
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("current_task")
                .expect("current_task should keep current-task semantics"),
            CtxField::Task
        );
    }

    #[test]
    fn test_iterator_meta_aliases_resolve_to_iter_meta() {
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("meta")
                .expect("meta alias should resolve"),
            CtxField::IterMeta
        );
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("iter_meta")
                .expect("iter_meta alias should resolve"),
            CtxField::IterMeta
        );
    }

    #[test]
    fn test_iterator_payload_aliases_resolve_to_payload_roots() {
        for (name, expected) in [
            ("fd", CtxField::IterFd),
            ("iter_fd", CtxField::IterFd),
            ("file", CtxField::IterFile),
            ("iter_file", CtxField::IterFile),
            ("vma", CtxField::IterVma),
            ("iter_vma", CtxField::IterVma),
            ("cgroup", CtxField::IterCgroup),
            ("iter_cgroup", CtxField::IterCgroup),
            ("map", CtxField::IterMap),
            ("iter_map", CtxField::IterMap),
            ("key", CtxField::IterMapKey),
            ("iter_key", CtxField::IterMapKey),
            ("value", CtxField::IterMapValue),
            ("iter_value", CtxField::IterMapValue),
            ("prog", CtxField::IterProg),
            ("iter_prog", CtxField::IterProg),
            ("link", CtxField::IterLink),
            ("iter_link", CtxField::IterLink),
            ("sk_common", CtxField::IterSkCommon),
            ("sock_common", CtxField::IterSkCommon),
            ("iter_sk_common", CtxField::IterSkCommon),
            ("udp_sk", CtxField::IterUdpSk),
            ("iter_udp_sk", CtxField::IterUdpSk),
            ("unix_sk", CtxField::IterUnixSk),
            ("iter_unix_sk", CtxField::IterUnixSk),
            ("uid", CtxField::IterUid),
            ("iter_uid", CtxField::IterUid),
            ("bucket", CtxField::IterBucket),
            ("iter_bucket", CtxField::IterBucket),
            ("dmabuf", CtxField::IterDmabuf),
            ("iter_dmabuf", CtxField::IterDmabuf),
            ("rt", CtxField::IterIpv6Route),
            ("route", CtxField::IterIpv6Route),
            ("ipv6_route", CtxField::IterIpv6Route),
            ("iter_ipv6_route", CtxField::IterIpv6Route),
            ("cache", CtxField::IterKmemCache),
            ("kmem_cache", CtxField::IterKmemCache),
            ("iter_kmem_cache", CtxField::IterKmemCache),
            ("ksym", CtxField::IterKsym),
            ("iter_ksym", CtxField::IterKsym),
            ("netlink_sk", CtxField::IterNetlinkSk),
            ("iter_netlink_sk", CtxField::IterNetlinkSk),
            ("sk", CtxField::IterSock),
            ("sock", CtxField::IterSock),
            ("iter_sock", CtxField::IterSock),
        ] {
            assert_eq!(
                EbpfProgramType::Iter
                    .resolve_ctx_field_name(name)
                    .unwrap_or_else(|_| panic!("{name} alias should resolve")),
                expected
            );
        }
        assert_eq!(
            EbpfProgramType::Iter
                .resolve_ctx_field_name("current_cgroup")
                .expect("current_cgroup should keep current-task cgroup semantics"),
            CtxField::Cgroup
        );
    }
}
