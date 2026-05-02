use std::cmp::Ordering;
use std::fmt;

use crate::compiler::{EbpfProgramType, ctx_field_backing_helper};

use super::CtxField;

const LINUX_BPF_H_V4_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_15_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_17_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_20_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_0_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_3_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_13_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.13/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h";
const LINUX_NF_BPF_LINK_V6_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c";
const LINUX_INTERNAL_BPF_H_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/include/linux/bpf.h";
const LINUX_TASK_ITER_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c";
const LINUX_TASK_ITER_V5_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c";
const LINUX_CGROUP_ITER_V6_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/cgroup_iter.c";
const LINUX_MAP_ITER_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/map_iter.c";
const LINUX_MAP_ITER_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c";
const LINUX_BPF_SK_STORAGE_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c";
const LINUX_SOCK_MAP_V5_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c";
const LINUX_PROG_ITER_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/prog_iter.c";
const LINUX_LINK_ITER_V5_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c";
const LINUX_TCP_IPV4_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/tcp_ipv4.c";
const LINUX_UDP_V5_9_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c";
const LINUX_AF_UNIX_V5_15_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.15/net/unix/af_unix.c";
const LINUX_IPV6_ROUTE_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/net/ipv6/route.c";
const LINUX_KALLSYMS_V6_0_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.0/kernel/kallsyms.c";
const LINUX_AF_NETLINK_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/net/netlink/af_netlink.c";

/// Source-backed kernel compatibility metadata for a source-level context field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextFieldCompatibilityRequirement {
    field: CtxField,
    minimum_kernel: &'static str,
    minimum_kernel_source: &'static str,
}

impl ContextFieldCompatibilityRequirement {
    pub fn for_field(field: &CtxField) -> Option<Self> {
        Self::for_field_on_program(field, None)
    }

    pub fn for_field_on_program(
        field: &CtxField,
        prog_type: Option<EbpfProgramType>,
    ) -> Option<Self> {
        Self::for_field_on_program_target(field, prog_type, None)
    }

    pub fn for_field_on_program_target(
        field: &CtxField,
        prog_type: Option<EbpfProgramType>,
        target: Option<&str>,
    ) -> Option<Self> {
        let (minimum_kernel, minimum_kernel_source) =
            context_field_kernel_floor(field, prog_type, target)?;
        Some(Self {
            field: field.clone(),
            minimum_kernel,
            minimum_kernel_source,
        })
    }

    pub fn field(&self) -> &CtxField {
        &self.field
    }

    pub fn key(&self) -> String {
        format!("ctx:{}", self.field.display_name())
    }

    pub fn category(&self) -> &'static str {
        "context-field"
    }

    pub fn minimum_kernel(&self) -> &'static str {
        self.minimum_kernel
    }

    pub fn minimum_kernel_source(&self) -> &'static str {
        self.minimum_kernel_source
    }

    pub fn effective_minimum_kernel(requirements: &[Self]) -> Option<&'static str> {
        let mut minimum = None;
        for requirement in requirements {
            let candidate = requirement.minimum_kernel();
            let should_replace = match minimum {
                Some(current) => Self::kernel_version_cmp(candidate, current).is_gt(),
                None => true,
            };
            if should_replace {
                minimum = Some(candidate);
            }
        }
        minimum
    }

    pub fn kernel_version_at_least(current: &str, minimum: &str) -> bool {
        !Self::kernel_version_cmp(current, minimum).is_lt()
    }

    fn kernel_version_cmp(left: &str, right: &str) -> Ordering {
        let mut left_parts = left.split(['.', '-']);
        let mut right_parts = right.split(['.', '-']);
        let left_version = [
            Self::kernel_version_part(left_parts.next()),
            Self::kernel_version_part(left_parts.next()),
            Self::kernel_version_part(left_parts.next()),
        ];
        let right_version = [
            Self::kernel_version_part(right_parts.next()),
            Self::kernel_version_part(right_parts.next()),
            Self::kernel_version_part(right_parts.next()),
        ];

        left_version.cmp(&right_version)
    }

    fn kernel_version_part(part: Option<&str>) -> u32 {
        part.unwrap_or("0").parse().unwrap_or(0)
    }
}

impl fmt::Display for ContextFieldCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

fn direct_context_field_kernel_floor(
    field: &CtxField,
    prog_type: Option<EbpfProgramType>,
) -> Option<(&'static str, &'static str)> {
    Some(match field {
        CtxField::PacketLen if prog_type == Some(EbpfProgramType::SockOps) => {
            ("5.10", LINUX_BPF_H_V5_10_SOURCE)
        }
        CtxField::Data | CtxField::DataEnd if prog_type == Some(EbpfProgramType::SockOps) => {
            ("5.10", LINUX_BPF_H_V5_10_SOURCE)
        }
        CtxField::SockOp if prog_type == Some(EbpfProgramType::SockOps) => {
            ("4.14", LINUX_BPF_H_V4_14_SOURCE)
        }
        CtxField::SockOpsArgs
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
            if prog_type == Some(EbpfProgramType::SockOps) =>
        {
            ("4.16", LINUX_BPF_H_V4_16_SOURCE)
        }
        CtxField::Socket if prog_type == Some(EbpfProgramType::SockOps) => {
            ("5.3", LINUX_BPF_H_V5_3_SOURCE)
        }
        CtxField::Socket if prog_type == Some(EbpfProgramType::CgroupSock) => {
            ("4.10", LINUX_BPF_H_V4_10_SOURCE)
        }
        CtxField::Socket
            if matches!(
                prog_type,
                Some(EbpfProgramType::CgroupSockAddr | EbpfProgramType::CgroupSockopt)
            ) =>
        {
            ("5.3", LINUX_BPF_H_V5_3_SOURCE)
        }
        CtxField::Data | CtxField::DataEnd if prog_type == Some(EbpfProgramType::SkMsg) => {
            ("4.17", LINUX_BPF_H_V4_17_SOURCE)
        }
        CtxField::Family
        | CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort
            if prog_type == Some(EbpfProgramType::SkMsg) =>
        {
            ("4.18", LINUX_BPF_H_V4_18_SOURCE)
        }
        CtxField::PacketLen if prog_type == Some(EbpfProgramType::SkMsg) => {
            ("5.0", LINUX_BPF_H_V5_0_SOURCE)
        }
        CtxField::Socket if prog_type == Some(EbpfProgramType::SkMsg) => {
            ("5.8", LINUX_BPF_H_V5_8_SOURCE)
        }
        CtxField::BoundDevIf | CtxField::Family | CtxField::SockType | CtxField::Protocol
            if prog_type == Some(EbpfProgramType::CgroupSock) =>
        {
            ("4.10", LINUX_BPF_H_V4_10_SOURCE)
        }
        CtxField::SockMark | CtxField::SockPriority
            if prog_type == Some(EbpfProgramType::CgroupSock) =>
        {
            ("4.14", LINUX_BPF_H_V4_14_SOURCE)
        }
        CtxField::LocalIp4 | CtxField::LocalIp6 | CtxField::LocalPort
            if prog_type == Some(EbpfProgramType::CgroupSock) =>
        {
            ("4.17", LINUX_BPF_H_V4_17_SOURCE)
        }
        CtxField::RemoteIp4 | CtxField::RemoteIp6 | CtxField::RemotePort | CtxField::SockState
            if prog_type == Some(EbpfProgramType::CgroupSock) =>
        {
            ("5.1", LINUX_BPF_H_V5_1_SOURCE)
        }
        CtxField::Socket
            if matches!(
                prog_type,
                Some(
                    EbpfProgramType::SocketFilter
                        | EbpfProgramType::Tc
                        | EbpfProgramType::Tcx
                        | EbpfProgramType::Netkit
                        | EbpfProgramType::TcAction
                        | EbpfProgramType::CgroupSkb
                        | EbpfProgramType::SkSkb
                        | EbpfProgramType::SkSkbParser
                )
            ) =>
        {
            ("5.1", LINUX_BPF_H_V5_1_SOURCE)
        }
        CtxField::SockRxQueueMapping if prog_type == Some(EbpfProgramType::CgroupSock) => {
            ("5.8", LINUX_BPF_H_V5_8_SOURCE)
        }
        CtxField::Family
        | CtxField::Protocol
        | CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort
            if prog_type == Some(EbpfProgramType::SkLookup) =>
        {
            ("5.9", LINUX_BPF_H_V5_9_SOURCE)
        }
        CtxField::LookupCookie if prog_type == Some(EbpfProgramType::SkLookup) => {
            ("5.13", LINUX_BPF_H_V5_13_SOURCE)
        }
        CtxField::Socket if prog_type == Some(EbpfProgramType::SkLookup) => {
            ("5.9", LINUX_BPF_H_V5_9_SOURCE)
        }
        CtxField::PacketLen
        | CtxField::Data
        | CtxField::DataEnd
        | CtxField::EthProtocol
        | CtxField::Protocol
        | CtxField::BindInany
        | CtxField::SkbHash
            if prog_type == Some(EbpfProgramType::SkReuseport) =>
        {
            ("4.19", LINUX_BPF_H_V4_19_SOURCE)
        }
        CtxField::Socket | CtxField::MigratingSocket
            if prog_type == Some(EbpfProgramType::SkReuseport) =>
        {
            ("5.14", LINUX_BPF_H_V5_14_SOURCE)
        }
        CtxField::Family
        | CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort
        | CtxField::SockType
        | CtxField::Protocol
            if prog_type == Some(EbpfProgramType::CgroupSockAddr) =>
        {
            ("4.17", LINUX_BPF_H_V4_17_SOURCE)
        }
        CtxField::PacketLen
        | CtxField::PktType
        | CtxField::QueueMapping
        | CtxField::EthProtocol
        | CtxField::VlanPresent
        | CtxField::VlanTci
        | CtxField::VlanProto
        | CtxField::SockMark
        | CtxField::SockPriority => ("4.1", LINUX_BPF_H_V4_1_SOURCE),
        CtxField::IngressIfindex
        | CtxField::Ifindex
        | CtxField::TcIndex
        | CtxField::SkbHash
        | CtxField::SkbCb
        | CtxField::TcClassid
        | CtxField::Data
        | CtxField::DataEnd => ("4.7", LINUX_BPF_H_V4_7_SOURCE),
        CtxField::NapiId
        | CtxField::Family
        | CtxField::RemoteIp4
        | CtxField::RemoteIp6
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalIp6
        | CtxField::LocalPort => ("4.14", LINUX_BPF_H_V4_14_SOURCE),
        CtxField::DataMeta => ("4.15", LINUX_BPF_H_V4_15_SOURCE),
        CtxField::DeviceAccessType
        | CtxField::DeviceAccess
        | CtxField::DeviceType
        | CtxField::DeviceMajor
        | CtxField::DeviceMinor => ("4.15", LINUX_BPF_H_V4_15_SOURCE),
        CtxField::RxQueueIndex => ("4.17", LINUX_BPF_H_V4_17_SOURCE),
        CtxField::FlowKeys => ("4.20", LINUX_BPF_H_V4_20_SOURCE),
        CtxField::Tstamp | CtxField::WireLen => ("5.0", LINUX_BPF_H_V5_0_SOURCE),
        CtxField::GsoSegs => ("5.1", LINUX_BPF_H_V5_1_SOURCE),
        CtxField::SysctlWrite | CtxField::SysctlFilePos => ("5.2", LINUX_BPF_H_V5_2_SOURCE),
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptOptval
        | CtxField::SockoptOptvalEnd
        | CtxField::SockoptRetval => ("5.3", LINUX_BPF_H_V5_3_SOURCE),
        CtxField::GsoSize => ("5.7", LINUX_BPF_H_V5_7_SOURCE),
        CtxField::EgressIfindex => ("5.8", LINUX_BPF_H_V5_8_SOURCE),
        CtxField::SockOpsSkbLen | CtxField::SockOpsSkbTcpFlags => {
            ("5.10", LINUX_BPF_H_V5_10_SOURCE)
        }
        CtxField::UserFamily | CtxField::UserIp4 | CtxField::UserIp6 | CtxField::UserPort => {
            ("4.17", LINUX_BPF_H_V4_17_SOURCE)
        }
        CtxField::MsgSrcIp4 | CtxField::MsgSrcIp6 => ("4.18", LINUX_BPF_H_V4_18_SOURCE),
        CtxField::Hwtstamp => ("5.16", LINUX_BPF_H_V5_16_SOURCE),
        CtxField::TstampType => ("5.18", LINUX_BPF_H_V5_18_SOURCE),
        CtxField::SockOpsSkbHwtstamp => ("6.2", LINUX_BPF_H_V6_2_SOURCE),
        CtxField::NetfilterState
        | CtxField::NetfilterSkb
        | CtxField::NetfilterHook
        | CtxField::NetfilterProtocolFamily => ("6.4", LINUX_NF_BPF_LINK_V6_4_SOURCE),
        CtxField::IterMeta if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.8", LINUX_INTERNAL_BPF_H_V5_8_SOURCE)
        }
        CtxField::IterTask | CtxField::IterFd | CtxField::IterFile
            if prog_type == Some(EbpfProgramType::Iter) =>
        {
            ("5.8", LINUX_TASK_ITER_V5_8_SOURCE)
        }
        CtxField::IterVma if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.12", LINUX_TASK_ITER_V5_12_SOURCE)
        }
        CtxField::IterCgroup if prog_type == Some(EbpfProgramType::Iter) => {
            ("6.1", LINUX_CGROUP_ITER_V6_1_SOURCE)
        }
        CtxField::IterMap if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.8", LINUX_MAP_ITER_V5_8_SOURCE)
        }
        CtxField::IterMapKey | CtxField::IterMapValue
            if prog_type == Some(EbpfProgramType::Iter) =>
        {
            ("5.9", LINUX_MAP_ITER_V5_9_SOURCE)
        }
        CtxField::IterSock if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.9", LINUX_BPF_SK_STORAGE_V5_9_SOURCE)
        }
        CtxField::IterProg if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.9", LINUX_PROG_ITER_V5_9_SOURCE)
        }
        CtxField::IterLink if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.19", LINUX_LINK_ITER_V5_19_SOURCE)
        }
        CtxField::IterSkCommon | CtxField::IterUid if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.9", LINUX_TCP_IPV4_V5_9_SOURCE)
        }
        CtxField::IterUdpSk | CtxField::IterBucket if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.9", LINUX_UDP_V5_9_SOURCE)
        }
        CtxField::IterUnixSk if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.15", LINUX_AF_UNIX_V5_15_SOURCE)
        }
        CtxField::IterIpv6Route if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.8", LINUX_IPV6_ROUTE_V5_8_SOURCE)
        }
        CtxField::IterKsym if prog_type == Some(EbpfProgramType::Iter) => {
            ("6.0", LINUX_KALLSYMS_V6_0_SOURCE)
        }
        CtxField::IterNetlinkSk if prog_type == Some(EbpfProgramType::Iter) => {
            ("5.8", LINUX_AF_NETLINK_V5_8_SOURCE)
        }
        _ => return None,
    })
}

fn target_context_field_kernel_floor(
    field: &CtxField,
    prog_type: Option<EbpfProgramType>,
    target: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    if prog_type != Some(EbpfProgramType::Iter) {
        return None;
    }

    Some(match (field, target?) {
        (CtxField::IterTask, "task_vma") => ("5.12", LINUX_TASK_ITER_V5_12_SOURCE),
        (CtxField::IterMap, "bpf_map_elem") => ("5.9", LINUX_MAP_ITER_V5_9_SOURCE),
        (CtxField::IterMap, "bpf_sk_storage_map") => ("5.9", LINUX_BPF_SK_STORAGE_V5_9_SOURCE),
        (CtxField::IterMap, "sockmap") => ("5.10", LINUX_SOCK_MAP_V5_10_SOURCE),
        (CtxField::IterMapKey, "sockmap") => ("5.10", LINUX_SOCK_MAP_V5_10_SOURCE),
        (CtxField::IterMapValue, "bpf_sk_storage_map") => ("5.9", LINUX_BPF_SK_STORAGE_V5_9_SOURCE),
        (CtxField::IterSock, "sockmap") => ("5.10", LINUX_SOCK_MAP_V5_10_SOURCE),
        (CtxField::IterUid, "udp") => ("5.9", LINUX_UDP_V5_9_SOURCE),
        (CtxField::IterUid, "unix") => ("5.15", LINUX_AF_UNIX_V5_15_SOURCE),
        _ => return None,
    })
}

fn context_field_kernel_floor(
    field: &CtxField,
    prog_type: Option<EbpfProgramType>,
    target: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    target_context_field_kernel_floor(field, prog_type, target)
        .or_else(|| direct_context_field_kernel_floor(field, prog_type))
        .or_else(|| {
            let helper = ctx_field_backing_helper(field)?;
            Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?))
        })
}
