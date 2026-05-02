use std::cmp::Ordering;
use std::fmt;

use crate::compiler::{EbpfProgramType, ctx_field_backing_helper};

use super::CtxField;

const LINUX_BPF_H_V4_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_15_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_17_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_20_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_0_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h";
const LINUX_NF_BPF_LINK_V6_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c";

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
        let (minimum_kernel, minimum_kernel_source) = context_field_kernel_floor(field, prog_type)?;
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
        CtxField::GsoSize => ("5.7", LINUX_BPF_H_V5_7_SOURCE),
        CtxField::EgressIfindex => ("5.8", LINUX_BPF_H_V5_8_SOURCE),
        CtxField::SockOpsSkbLen | CtxField::SockOpsSkbTcpFlags => {
            ("5.10", LINUX_BPF_H_V5_10_SOURCE)
        }
        CtxField::Hwtstamp => ("5.16", LINUX_BPF_H_V5_16_SOURCE),
        CtxField::TstampType => ("5.18", LINUX_BPF_H_V5_18_SOURCE),
        CtxField::SockOpsSkbHwtstamp => ("6.2", LINUX_BPF_H_V6_2_SOURCE),
        CtxField::NetfilterState
        | CtxField::NetfilterSkb
        | CtxField::NetfilterHook
        | CtxField::NetfilterProtocolFamily => ("6.4", LINUX_NF_BPF_LINK_V6_4_SOURCE),
        _ => return None,
    })
}

fn context_field_kernel_floor(
    field: &CtxField,
    prog_type: Option<EbpfProgramType>,
) -> Option<(&'static str, &'static str)> {
    direct_context_field_kernel_floor(field, prog_type).or_else(|| {
        let helper = ctx_field_backing_helper(field)?;
        Some((helper.minimum_kernel()?, helper.minimum_kernel_source()?))
    })
}
