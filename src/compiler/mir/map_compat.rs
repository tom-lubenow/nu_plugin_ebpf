use std::cmp::Ordering;
use std::fmt;

use super::MapKind;

const LINUX_BPF_H_V3_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_3_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_11_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_15_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_20_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_11_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.9/include/uapi/linux/bpf.h";
const LINUX_INTERNAL_BPF_H_V6_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.10/include/linux/bpf.h";

/// Source-backed kernel compatibility metadata for a BPF map type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapCompatibilityRequirement {
    kind: MapKind,
}

impl MapCompatibilityRequirement {
    pub fn for_kind(kind: MapKind) -> Self {
        Self { kind }
    }

    pub fn kind(self) -> MapKind {
        self.kind
    }

    pub fn key(self) -> &'static str {
        self.kind.compatibility_feature_key()
    }

    pub fn category(self) -> &'static str {
        "map-kind"
    }

    pub fn minimum_kernel(self) -> &'static str {
        self.kind.minimum_kernel()
    }

    pub fn minimum_kernel_source(self) -> &'static str {
        self.kind.minimum_kernel_source()
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

impl fmt::Display for MapCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// Source-backed kernel compatibility metadata for typed BTF map-value fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapValueCompatibilityRequirement {
    BpfWorkqueue,
}

impl MapValueCompatibilityRequirement {
    pub fn key(self) -> &'static str {
        match self {
            Self::BpfWorkqueue => "map-value:bpf_wq",
        }
    }

    pub fn category(self) -> &'static str {
        "map-value-field"
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::BpfWorkqueue => "BPF map-value workqueue field support",
        }
    }

    pub fn minimum_kernel(self) -> &'static str {
        match self {
            Self::BpfWorkqueue => "6.10",
        }
    }

    pub fn minimum_kernel_source(self) -> &'static str {
        match self {
            Self::BpfWorkqueue => LINUX_INTERNAL_BPF_H_V6_10_SOURCE,
        }
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

impl fmt::Display for MapValueCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

impl MapKind {
    pub fn compatibility_requirement(self) -> MapCompatibilityRequirement {
        MapCompatibilityRequirement::for_kind(self)
    }

    pub fn compatibility_feature_key(self) -> &'static str {
        match self {
            Self::Hash => "map:BPF_MAP_TYPE_HASH",
            Self::Array => "map:BPF_MAP_TYPE_ARRAY",
            Self::CgroupArray => "map:BPF_MAP_TYPE_CGROUP_ARRAY",
            Self::LpmTrie => "map:BPF_MAP_TYPE_LPM_TRIE",
            Self::LruHash => "map:BPF_MAP_TYPE_LRU_HASH",
            Self::PerCpuHash => "map:BPF_MAP_TYPE_PERCPU_HASH",
            Self::PerCpuArray => "map:BPF_MAP_TYPE_PERCPU_ARRAY",
            Self::LruPerCpuHash => "map:BPF_MAP_TYPE_LRU_PERCPU_HASH",
            Self::PerfEventArray => "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            Self::ArrayOfMaps => "map:BPF_MAP_TYPE_ARRAY_OF_MAPS",
            Self::HashOfMaps => "map:BPF_MAP_TYPE_HASH_OF_MAPS",
            Self::DeprecatedCgroupStorage => "map:BPF_MAP_TYPE_CGROUP_STORAGE",
            Self::DeprecatedPerCpuCgroupStorage => "map:BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
            Self::Queue => "map:BPF_MAP_TYPE_QUEUE",
            Self::Stack => "map:BPF_MAP_TYPE_STACK",
            Self::BloomFilter => "map:BPF_MAP_TYPE_BLOOM_FILTER",
            Self::RingBuf => "map:BPF_MAP_TYPE_RINGBUF",
            Self::StructOps => "map:BPF_MAP_TYPE_STRUCT_OPS",
            Self::UserRingBuf => "map:BPF_MAP_TYPE_USER_RINGBUF",
            Self::Arena => "map:BPF_MAP_TYPE_ARENA",
            Self::StackTrace => "map:BPF_MAP_TYPE_STACK_TRACE",
            Self::DevMap => "map:BPF_MAP_TYPE_DEVMAP",
            Self::DevMapHash => "map:BPF_MAP_TYPE_DEVMAP_HASH",
            Self::CpuMap => "map:BPF_MAP_TYPE_CPUMAP",
            Self::XskMap => "map:BPF_MAP_TYPE_XSKMAP",
            Self::SockMap => "map:BPF_MAP_TYPE_SOCKMAP",
            Self::SockHash => "map:BPF_MAP_TYPE_SOCKHASH",
            Self::ReuseportSockArray => "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
            Self::SkStorage => "map:BPF_MAP_TYPE_SK_STORAGE",
            Self::InodeStorage => "map:BPF_MAP_TYPE_INODE_STORAGE",
            Self::TaskStorage => "map:BPF_MAP_TYPE_TASK_STORAGE",
            Self::CgrpStorage => "map:BPF_MAP_TYPE_CGRP_STORAGE",
            Self::ProgArray => "map:BPF_MAP_TYPE_PROG_ARRAY",
        }
    }

    pub fn kernel_map_type_name(self) -> &'static str {
        match self {
            Self::Hash => "BPF_MAP_TYPE_HASH",
            Self::Array => "BPF_MAP_TYPE_ARRAY",
            Self::CgroupArray => "BPF_MAP_TYPE_CGROUP_ARRAY",
            Self::LpmTrie => "BPF_MAP_TYPE_LPM_TRIE",
            Self::LruHash => "BPF_MAP_TYPE_LRU_HASH",
            Self::PerCpuHash => "BPF_MAP_TYPE_PERCPU_HASH",
            Self::PerCpuArray => "BPF_MAP_TYPE_PERCPU_ARRAY",
            Self::LruPerCpuHash => "BPF_MAP_TYPE_LRU_PERCPU_HASH",
            Self::PerfEventArray => "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            Self::ArrayOfMaps => "BPF_MAP_TYPE_ARRAY_OF_MAPS",
            Self::HashOfMaps => "BPF_MAP_TYPE_HASH_OF_MAPS",
            Self::DeprecatedCgroupStorage => "BPF_MAP_TYPE_CGROUP_STORAGE",
            Self::DeprecatedPerCpuCgroupStorage => "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
            Self::Queue => "BPF_MAP_TYPE_QUEUE",
            Self::Stack => "BPF_MAP_TYPE_STACK",
            Self::BloomFilter => "BPF_MAP_TYPE_BLOOM_FILTER",
            Self::RingBuf => "BPF_MAP_TYPE_RINGBUF",
            Self::StructOps => "BPF_MAP_TYPE_STRUCT_OPS",
            Self::UserRingBuf => "BPF_MAP_TYPE_USER_RINGBUF",
            Self::Arena => "BPF_MAP_TYPE_ARENA",
            Self::StackTrace => "BPF_MAP_TYPE_STACK_TRACE",
            Self::DevMap => "BPF_MAP_TYPE_DEVMAP",
            Self::DevMapHash => "BPF_MAP_TYPE_DEVMAP_HASH",
            Self::CpuMap => "BPF_MAP_TYPE_CPUMAP",
            Self::XskMap => "BPF_MAP_TYPE_XSKMAP",
            Self::SockMap => "BPF_MAP_TYPE_SOCKMAP",
            Self::SockHash => "BPF_MAP_TYPE_SOCKHASH",
            Self::ReuseportSockArray => "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
            Self::SkStorage => "BPF_MAP_TYPE_SK_STORAGE",
            Self::InodeStorage => "BPF_MAP_TYPE_INODE_STORAGE",
            Self::TaskStorage => "BPF_MAP_TYPE_TASK_STORAGE",
            Self::CgrpStorage => "BPF_MAP_TYPE_CGRP_STORAGE",
            Self::ProgArray => "BPF_MAP_TYPE_PROG_ARRAY",
        }
    }

    pub fn minimum_kernel(self) -> &'static str {
        match self {
            Self::Hash | Self::Array => "3.19",
            Self::ProgArray => "4.2",
            Self::PerfEventArray => "4.3",
            Self::PerCpuHash | Self::PerCpuArray | Self::StackTrace => "4.6",
            Self::CgroupArray => "4.8",
            Self::LruHash | Self::LruPerCpuHash => "4.10",
            Self::LpmTrie => "4.11",
            Self::ArrayOfMaps | Self::HashOfMaps => "4.12",
            Self::DevMap | Self::SockMap => "4.14",
            Self::CpuMap => "4.15",
            Self::XskMap | Self::SockHash => "4.18",
            Self::DeprecatedCgroupStorage | Self::ReuseportSockArray => "4.19",
            Self::DeprecatedPerCpuCgroupStorage | Self::Queue | Self::Stack => "4.20",
            Self::SkStorage => "5.2",
            Self::DevMapHash => "5.4",
            Self::StructOps => "5.6",
            Self::RingBuf => "5.8",
            Self::InodeStorage => "5.10",
            Self::TaskStorage => "5.11",
            Self::BloomFilter => "5.16",
            Self::UserRingBuf => "6.1",
            Self::CgrpStorage => "6.2",
            Self::Arena => "6.9",
        }
    }

    pub fn minimum_kernel_source(self) -> &'static str {
        match self {
            Self::Hash | Self::Array => LINUX_BPF_H_V3_19_SOURCE,
            Self::ProgArray => LINUX_BPF_H_V4_2_SOURCE,
            Self::PerfEventArray => LINUX_BPF_H_V4_3_SOURCE,
            Self::PerCpuHash | Self::PerCpuArray | Self::StackTrace => LINUX_BPF_H_V4_6_SOURCE,
            Self::CgroupArray => LINUX_BPF_H_V4_8_SOURCE,
            Self::LruHash | Self::LruPerCpuHash => LINUX_BPF_H_V4_10_SOURCE,
            Self::LpmTrie => LINUX_BPF_H_V4_11_SOURCE,
            Self::ArrayOfMaps | Self::HashOfMaps => LINUX_BPF_H_V4_12_SOURCE,
            Self::DevMap | Self::SockMap => LINUX_BPF_H_V4_14_SOURCE,
            Self::CpuMap => LINUX_BPF_H_V4_15_SOURCE,
            Self::XskMap | Self::SockHash => LINUX_BPF_H_V4_18_SOURCE,
            Self::DeprecatedCgroupStorage | Self::ReuseportSockArray => LINUX_BPF_H_V4_19_SOURCE,
            Self::DeprecatedPerCpuCgroupStorage | Self::Queue | Self::Stack => {
                LINUX_BPF_H_V4_20_SOURCE
            }
            Self::SkStorage => LINUX_BPF_H_V5_2_SOURCE,
            Self::DevMapHash => LINUX_BPF_H_V5_4_SOURCE,
            Self::StructOps => LINUX_BPF_H_V5_6_SOURCE,
            Self::RingBuf => LINUX_BPF_H_V5_8_SOURCE,
            Self::InodeStorage => LINUX_BPF_H_V5_10_SOURCE,
            Self::TaskStorage => LINUX_BPF_H_V5_11_SOURCE,
            Self::BloomFilter => LINUX_BPF_H_V5_16_SOURCE,
            Self::UserRingBuf => LINUX_BPF_H_V6_1_SOURCE,
            Self::CgrpStorage => LINUX_BPF_H_V6_2_SOURCE,
            Self::Arena => LINUX_BPF_H_V6_9_SOURCE,
        }
    }
}
