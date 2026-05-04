//! Minimal ELF generation for eBPF programs
//!
//! This module creates ELF object files that can be loaded by Aya or libbpf.
//! The ELF format includes:
//! - A section with the eBPF bytecode (named for the program type, e.g., "kprobe/func")
//! - A "license" section containing the license string (required for most helpers)
//! - Optional ".maps" section for BPF map definitions

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;

use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionFlags, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

use super::CompileError;
use super::btf::BtfBuilder;
use super::instruction::EbpfBuilder;
use super::instruction::{
    BpfHelper, HelperCompatibilityRequirement, KfuncCompatibilityRequirement, opcode,
};
use super::mir::ContextFieldCompatibilityRequirement;
use super::mir::CtxStoreTarget;
use super::mir::{
    BYTES_COUNTER_MAP_NAME, BitfieldInfo, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapCompatibilityRequirement, MapKind, MapRef,
    MapValueCompatibilityRequirement, MirType, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME,
    TIMESTAMP_MAP_NAME, USTACK_MAP_NAME,
};
use crate::program_spec::{
    ProgramSpec, struct_ops_callback_is_sleepable as program_spec_struct_ops_callback_is_sleepable,
};

mod probe_context;
mod program_ctx_access;
mod program_ctx_names;
mod program_ctx_schema;
mod program_ctx_writes;
mod program_helper_policy;
mod program_impl;
mod program_kfunc_policy;
mod program_return_policy;
mod program_types;

use program_types::*;
pub use program_types::{ProgramContextFamily, ProgramTypeInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GetSocketCookieArgPolicy {
    Context,
    ContextOrSocket,
    Socket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketAdjustMode {
    Head,
    Meta,
    Tail,
    Pull,
    Room,
}

impl PacketAdjustMode {
    pub(crate) fn flag_name(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Meta => "meta",
            Self::Tail => "tail",
            Self::Pull => "pull",
            Self::Room => "room",
        }
    }

    pub(crate) fn value_name(self) -> &'static str {
        match self {
            Self::Head | Self::Meta | Self::Tail => "delta",
            Self::Pull => "len",
            Self::Room => "len-diff",
        }
    }

    pub(crate) fn supported_programs_label(self) -> &'static str {
        match self {
            Self::Head | Self::Tail => {
                "xdp, lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser"
            }
            Self::Meta => "xdp",
            Self::Pull => "lwt_*, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser",
            Self::Room => "tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageAdjustMode {
    Apply,
    Cork,
    Pull,
    Push,
    Pop,
}

impl MessageAdjustMode {
    pub(crate) fn flag_name(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Cork => "cork",
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Pop => "pop",
        }
    }

    pub(crate) fn first_value_name(self) -> &'static str {
        match self {
            Self::Apply | Self::Cork => "bytes",
            Self::Pull | Self::Push | Self::Pop => "start",
        }
    }

    pub(crate) fn second_value_name(self) -> Option<&'static str> {
        match self {
            Self::Apply | Self::Cork => None,
            Self::Pull => Some("end"),
            Self::Push | Self::Pop => Some("len"),
        }
    }

    pub(crate) fn supported_programs_label(self) -> &'static str {
        "sk_msg"
    }
}

impl GetSocketCookieArgPolicy {
    pub(crate) fn error_message(self, helper: BpfHelper, program_type: EbpfProgramType) -> String {
        match self {
            Self::Context => format!(
                "helper '{}' arg0 expects raw ctx pointer in {} programs",
                helper.name(),
                program_type.canonical_prefix()
            ),
            Self::ContextOrSocket => format!(
                "helper '{}' arg0 expects raw ctx pointer or socket pointer in {} programs",
                helper.name(),
                program_type.canonical_prefix()
            ),
            Self::Socket => format!(
                "helper '{}' arg0 expects socket pointer in {} programs",
                helper.name(),
                program_type.canonical_prefix()
            ),
        }
    }

    pub(crate) fn allows_maybe_null(self) -> bool {
        matches!(self, Self::Socket)
    }
}

/// BPF map types (subset of types we might use)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[allow(dead_code)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PerCpuHash = 5,
    PerCpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPerCpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    DevMap = 14,
    SockMap = 15,
    CpuMap = 16,
    XskMap = 17,
    SockHash = 18,
    CgroupStorage = 19,
    ReuseportSockArray = 20,
    PerCpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevMapHash = 25,
    StructOps = 26,
    RingBuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingBuf = 31,
    CgrpStorage = 32,
    Arena = 33,
}

impl BpfMapType {
    pub(crate) fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            x if x == Self::Hash as u32 => Some(Self::Hash),
            x if x == Self::Array as u32 => Some(Self::Array),
            x if x == Self::ProgArray as u32 => Some(Self::ProgArray),
            x if x == Self::PerfEventArray as u32 => Some(Self::PerfEventArray),
            x if x == Self::PerCpuHash as u32 => Some(Self::PerCpuHash),
            x if x == Self::PerCpuArray as u32 => Some(Self::PerCpuArray),
            x if x == Self::StackTrace as u32 => Some(Self::StackTrace),
            x if x == Self::CgroupArray as u32 => Some(Self::CgroupArray),
            x if x == Self::LruHash as u32 => Some(Self::LruHash),
            x if x == Self::LruPerCpuHash as u32 => Some(Self::LruPerCpuHash),
            x if x == Self::LpmTrie as u32 => Some(Self::LpmTrie),
            x if x == Self::ArrayOfMaps as u32 => Some(Self::ArrayOfMaps),
            x if x == Self::HashOfMaps as u32 => Some(Self::HashOfMaps),
            x if x == Self::DevMap as u32 => Some(Self::DevMap),
            x if x == Self::SockMap as u32 => Some(Self::SockMap),
            x if x == Self::CpuMap as u32 => Some(Self::CpuMap),
            x if x == Self::XskMap as u32 => Some(Self::XskMap),
            x if x == Self::SockHash as u32 => Some(Self::SockHash),
            x if x == Self::CgroupStorage as u32 => Some(Self::CgroupStorage),
            x if x == Self::ReuseportSockArray as u32 => Some(Self::ReuseportSockArray),
            x if x == Self::PerCpuCgroupStorage as u32 => Some(Self::PerCpuCgroupStorage),
            x if x == Self::Queue as u32 => Some(Self::Queue),
            x if x == Self::Stack as u32 => Some(Self::Stack),
            x if x == Self::SkStorage as u32 => Some(Self::SkStorage),
            x if x == Self::DevMapHash as u32 => Some(Self::DevMapHash),
            x if x == Self::StructOps as u32 => Some(Self::StructOps),
            x if x == Self::RingBuf as u32 => Some(Self::RingBuf),
            x if x == Self::InodeStorage as u32 => Some(Self::InodeStorage),
            x if x == Self::TaskStorage as u32 => Some(Self::TaskStorage),
            x if x == Self::BloomFilter as u32 => Some(Self::BloomFilter),
            x if x == Self::UserRingBuf as u32 => Some(Self::UserRingBuf),
            x if x == Self::CgrpStorage as u32 => Some(Self::CgrpStorage),
            x if x == Self::Arena as u32 => Some(Self::Arena),
            _ => None,
        }
    }

    pub(crate) fn name_for_raw(raw: u32) -> &'static str {
        Self::from_raw(raw).map(Self::name).unwrap_or("Unknown")
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Hash => "Hash",
            Self::Array => "Array",
            Self::ProgArray => "ProgArray",
            Self::PerfEventArray => "PerfEventArray",
            Self::PerCpuHash => "PerCpuHash",
            Self::PerCpuArray => "PerCpuArray",
            Self::StackTrace => "StackTrace",
            Self::CgroupArray => "CgroupArray",
            Self::LruHash => "LruHash",
            Self::LruPerCpuHash => "LruPerCpuHash",
            Self::LpmTrie => "LpmTrie",
            Self::ArrayOfMaps => "ArrayOfMaps",
            Self::HashOfMaps => "HashOfMaps",
            Self::DevMap => "DevMap",
            Self::SockMap => "SockMap",
            Self::CpuMap => "CpuMap",
            Self::XskMap => "XskMap",
            Self::SockHash => "SockHash",
            Self::CgroupStorage => "CgroupStorage",
            Self::ReuseportSockArray => "ReuseportSockArray",
            Self::PerCpuCgroupStorage => "PerCpuCgroupStorage",
            Self::Queue => "Queue",
            Self::Stack => "Stack",
            Self::SkStorage => "SkStorage",
            Self::DevMapHash => "DevMapHash",
            Self::StructOps => "StructOps",
            Self::RingBuf => "RingBuf",
            Self::InodeStorage => "InodeStorage",
            Self::TaskStorage => "TaskStorage",
            Self::BloomFilter => "BloomFilter",
            Self::UserRingBuf => "UserRingBuf",
            Self::CgrpStorage => "CgrpStorage",
            Self::Arena => "Arena",
        }
    }

    #[allow(dead_code)]
    pub(crate) fn map_kind(self) -> MapKind {
        match self {
            Self::Hash => MapKind::Hash,
            Self::Array => MapKind::Array,
            Self::ProgArray => MapKind::ProgArray,
            Self::PerfEventArray => MapKind::PerfEventArray,
            Self::PerCpuHash => MapKind::PerCpuHash,
            Self::PerCpuArray => MapKind::PerCpuArray,
            Self::StackTrace => MapKind::StackTrace,
            Self::CgroupArray => MapKind::CgroupArray,
            Self::LruHash => MapKind::LruHash,
            Self::LruPerCpuHash => MapKind::LruPerCpuHash,
            Self::LpmTrie => MapKind::LpmTrie,
            Self::ArrayOfMaps => MapKind::ArrayOfMaps,
            Self::HashOfMaps => MapKind::HashOfMaps,
            Self::DevMap => MapKind::DevMap,
            Self::SockMap => MapKind::SockMap,
            Self::CpuMap => MapKind::CpuMap,
            Self::XskMap => MapKind::XskMap,
            Self::SockHash => MapKind::SockHash,
            Self::CgroupStorage => MapKind::DeprecatedCgroupStorage,
            Self::ReuseportSockArray => MapKind::ReuseportSockArray,
            Self::PerCpuCgroupStorage => MapKind::DeprecatedPerCpuCgroupStorage,
            Self::Queue => MapKind::Queue,
            Self::Stack => MapKind::Stack,
            Self::SkStorage => MapKind::SkStorage,
            Self::DevMapHash => MapKind::DevMapHash,
            Self::StructOps => MapKind::StructOps,
            Self::RingBuf => MapKind::RingBuf,
            Self::InodeStorage => MapKind::InodeStorage,
            Self::TaskStorage => MapKind::TaskStorage,
            Self::BloomFilter => MapKind::BloomFilter,
            Self::UserRingBuf => MapKind::UserRingBuf,
            Self::CgrpStorage => MapKind::CgrpStorage,
            Self::Arena => MapKind::Arena,
        }
    }
}

/// Pinning type for BPF maps (libbpf convention)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfPinningType {
    /// No pinning - map is private to this program
    None = 0,
    /// Pin by name - maps with same name share data across programs
    ByName = 1,
}

/// Definition of a BPF map (legacy format for libbpf/Aya compatibility)
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct BpfMapDef {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    /// Pinning type - set to ByName for shared maps between programs
    pub pinning: BpfPinningType,
}

impl BpfMapDef {
    #[allow(dead_code)]
    pub(crate) fn map_kind(&self) -> Option<MapKind> {
        BpfMapType::from_raw(self.map_type).map(BpfMapType::map_kind)
    }

    pub(crate) fn map_type_name(&self) -> &'static str {
        BpfMapType::name_for_raw(self.map_type)
    }

    fn require_field(
        &self,
        map_name: &str,
        field_name: &str,
        actual: u32,
        expected: u32,
    ) -> Result<(), CompileError> {
        if actual == expected {
            return Ok(());
        }
        Err(CompileError::InvalidProgram(format!(
            "runtime map '{}' ({}) must have {} {}, got {}",
            map_name,
            self.map_type_name(),
            field_name,
            expected,
            actual
        )))
    }

    fn require_nonzero_field(
        &self,
        map_name: &str,
        field_name: &str,
        actual: u32,
    ) -> Result<(), CompileError> {
        if actual != 0 {
            return Ok(());
        }
        Err(CompileError::InvalidProgram(format!(
            "runtime map '{}' ({}) must have non-zero {}",
            map_name,
            self.map_type_name(),
            field_name
        )))
    }

    pub(crate) fn validate_common_shape(&self, map_name: &str) -> Result<(), CompileError> {
        let Some(map_type) = BpfMapType::from_raw(self.map_type) else {
            return Err(CompileError::InvalidProgram(format!(
                "runtime map '{}' uses unsupported map type {}",
                map_name, self.map_type
            )));
        };

        match map_type {
            BpfMapType::ArrayOfMaps | BpfMapType::HashOfMaps => {
                return Err(CompileError::InvalidProgram(format!(
                    "runtime map '{}' ({}) requires inner-map metadata, which is not modeled by this compiler yet",
                    map_name,
                    self.map_type_name()
                )));
            }
            BpfMapType::CgroupStorage | BpfMapType::PerCpuCgroupStorage => {
                return Err(CompileError::InvalidProgram(format!(
                    "runtime map '{}' ({}) uses a deprecated cgroup-storage map type; use cgrp-storage local-storage maps instead",
                    map_name,
                    self.map_type_name()
                )));
            }
            BpfMapType::StructOps => {
                return Err(CompileError::InvalidProgram(format!(
                    "runtime map '{}' (StructOps) is reserved for struct_ops objects; use struct_ops attach syntax instead of generic runtime maps",
                    map_name
                )));
            }
            BpfMapType::Arena => {
                return Err(CompileError::InvalidProgram(format!(
                    "runtime map '{}' (Arena) is not supported yet; arena map_extra/mmap support is not modeled",
                    map_name
                )));
            }
            BpfMapType::Hash
            | BpfMapType::LruHash
            | BpfMapType::PerCpuHash
            | BpfMapType::LruPerCpuHash
            | BpfMapType::LpmTrie => {
                self.require_nonzero_field(map_name, "key_size", self.key_size)?;
                self.require_nonzero_field(map_name, "value_size", self.value_size)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::Array | BpfMapType::PerCpuArray => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_nonzero_field(map_name, "value_size", self.value_size)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::CgroupArray
            | BpfMapType::ProgArray
            | BpfMapType::SockMap
            | BpfMapType::ReuseportSockArray
            | BpfMapType::XskMap => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_field(map_name, "value_size", self.value_size, 4)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::PerfEventArray => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_field(map_name, "value_size", self.value_size, 4)?;
            }
            BpfMapType::StackTrace => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_nonzero_field(map_name, "value_size", self.value_size)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::DevMap | BpfMapType::CpuMap => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_field(map_name, "value_size", self.value_size, 8)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::DevMapHash => {
                self.require_nonzero_field(map_name, "key_size", self.key_size)?;
                self.require_field(map_name, "value_size", self.value_size, 8)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::SockHash => {
                self.require_nonzero_field(map_name, "key_size", self.key_size)?;
                self.require_field(map_name, "value_size", self.value_size, 4)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::Queue | BpfMapType::Stack | BpfMapType::BloomFilter => {
                self.require_field(map_name, "key_size", self.key_size, 0)?;
                self.require_nonzero_field(map_name, "value_size", self.value_size)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::RingBuf | BpfMapType::UserRingBuf => {
                self.require_field(map_name, "key_size", self.key_size, 0)?;
                self.require_field(map_name, "value_size", self.value_size, 0)?;
                self.require_nonzero_field(map_name, "max_entries", self.max_entries)?;
            }
            BpfMapType::SkStorage
            | BpfMapType::InodeStorage
            | BpfMapType::TaskStorage
            | BpfMapType::CgrpStorage => {
                self.require_field(map_name, "key_size", self.key_size, 4)?;
                self.require_nonzero_field(map_name, "value_size", self.value_size)?;
                self.require_field(map_name, "max_entries", self.max_entries, 0)?;
            }
        }

        Ok(())
    }

    /// Create a generic hash map definition.
    pub fn hash(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::Hash as u32,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic array map definition.
    pub fn array(value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::Array as u32,
            key_size: 4, // u32 index
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a cgroup array map definition.
    pub fn cgroup_array(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::CgroupArray as u32,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic LPM trie map definition.
    pub fn lpm_trie(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::LpmTrie as u32,
            key_size,
            value_size,
            max_entries,
            map_flags: 1, // BPF_F_NO_PREALLOC
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic per-CPU hash map definition.
    pub fn per_cpu_hash(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::PerCpuHash as u32,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic per-CPU array map definition.
    pub fn per_cpu_array(value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::PerCpuArray as u32,
            key_size: 4, // u32 index
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic LRU hash map definition.
    pub fn lru_hash(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::LruHash as u32,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic LRU per-CPU hash map definition.
    pub fn lru_per_cpu_hash(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::LruPerCpuHash as u32,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic sockmap definition.
    pub fn sock_map(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::SockMap as u32,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic sockhash definition.
    pub fn sock_hash(key_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::SockHash as u32,
            key_size,
            value_size: 4,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a reuseport socket array map definition.
    pub fn reuseport_sockarray(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::ReuseportSockArray as u32,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    fn local_storage(map_type: BpfMapType, value_size: u32) -> Self {
        Self {
            map_type: map_type as u32,
            key_size: 4,
            value_size,
            max_entries: 0,
            map_flags: 1, // BPF_F_NO_PREALLOC
            pinning: BpfPinningType::None,
        }
    }

    /// Create a socket-local storage map definition.
    pub fn sk_storage(value_size: u32) -> Self {
        Self::local_storage(BpfMapType::SkStorage, value_size)
    }

    /// Create an inode-local storage map definition.
    pub fn inode_storage(value_size: u32) -> Self {
        Self::local_storage(BpfMapType::InodeStorage, value_size)
    }

    /// Create a task-local storage map definition.
    pub fn task_storage(value_size: u32) -> Self {
        Self::local_storage(BpfMapType::TaskStorage, value_size)
    }

    /// Create a cgroup-local storage map definition.
    pub fn cgrp_storage(value_size: u32) -> Self {
        Self::local_storage(BpfMapType::CgrpStorage, value_size)
    }

    /// Create a generic devmap definition.
    pub fn dev_map(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::DevMap as u32,
            key_size: 4,
            value_size: 8,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic devmap hash definition.
    pub fn dev_map_hash(key_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::DevMapHash as u32,
            key_size,
            value_size: 8,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic cpumap definition.
    pub fn cpu_map(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::CpuMap as u32,
            key_size: 4,
            value_size: 8,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic xskmap definition.
    pub fn xsk_map(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::XskMap as u32,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic queue map definition.
    pub fn queue(value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::Queue as u32,
            key_size: 0,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic stack map definition.
    pub fn stack(value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::Stack as u32,
            key_size: 0,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a generic bloom filter map definition.
    pub fn bloom_filter(value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::BloomFilter as u32,
            key_size: 0,
            value_size,
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a perf event array map (for outputting events to userspace)
    pub fn perf_event_array() -> Self {
        Self {
            map_type: BpfMapType::PerfEventArray as u32,
            key_size: 4,    // sizeof(u32) - CPU index
            value_size: 4,  // sizeof(u32) - perf event fd
            max_entries: 0, // Will be set to num_cpus by loader
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a hash map for counting (key: i64, value: i64)
    pub fn counter_hash() -> Self {
        Self::hash(8, 8, 10240)
    }

    /// Create a hash map for counting with string keys (key: 16 bytes comm, value: i64)
    ///
    /// Used when counting by process name ($ctx.comm) instead of numeric keys.
    pub fn string_counter_hash() -> Self {
        Self::hash(16, 8, 10240)
    }

    /// Create a hash map for storing timestamps (key: i64 TID, value: i64 timestamp)
    pub fn timestamp_hash() -> Self {
        Self::hash(8, 8, 10240)
    }

    /// Create a hash map for histogram buckets (key: i64 bucket, value: i64 count)
    pub fn histogram_hash() -> Self {
        Self::hash(8, 8, 64)
    }

    /// Create a stack trace map for storing stack traces
    pub fn stack_trace_map() -> Self {
        Self {
            map_type: BpfMapType::StackTrace as u32,
            key_size: 4,         // sizeof(u32) - stack ID
            value_size: 127 * 8, // PERF_MAX_STACK_DEPTH frames * sizeof(u64)
            max_entries: 1024,   // Maximum number of unique stack traces
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a ring buffer map for efficient event output
    ///
    /// Ring buffers are more efficient than perf event arrays:
    /// - Single shared buffer instead of per-CPU buffers
    /// - Lower overhead for event submission
    /// - Variable-length records supported naturally
    pub fn ring_buffer(size_bytes: u32) -> Self {
        Self {
            map_type: BpfMapType::RingBuf as u32,
            key_size: 0,             // Not used for ring buffers
            value_size: 0,           // Not used for ring buffers
            max_entries: size_bytes, // Buffer size in bytes (must be power of 2)
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a user ring buffer map for userspace-to-kernel event transfer.
    pub fn user_ring_buffer(size_bytes: u32) -> Self {
        Self {
            map_type: BpfMapType::UserRingBuf as u32,
            key_size: 0,
            value_size: 0,
            max_entries: size_bytes,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a program array map for BPF tail calls
    pub fn prog_array(max_entries: u32) -> Self {
        Self {
            map_type: BpfMapType::ProgArray as u32,
            key_size: 4,   // u32 index
            value_size: 4, // u32 program FD
            max_entries,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Enable pinning for this map (allows sharing between programs)
    pub fn with_pinning(mut self) -> Self {
        self.pinning = BpfPinningType::ByName;
        self
    }

    /// Serialize to bytes (little-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.map_type.to_le_bytes());
        bytes.extend_from_slice(&self.key_size.to_le_bytes());
        bytes.extend_from_slice(&self.value_size.to_le_bytes());
        bytes.extend_from_slice(&self.max_entries.to_le_bytes());
        bytes.extend_from_slice(&self.map_flags.to_le_bytes());
        bytes.extend_from_slice(&(self.pinning as u32).to_le_bytes());
        bytes
    }
}

/// A map to be included in the program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfMap {
    pub name: String,
    pub def: BpfMapDef,
}

/// A read-only global byte blob emitted into the program's `.rodata` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadonlyGlobal {
    pub name: String,
    pub data: Vec<u8>,
}

/// A writable initialized global byte blob emitted into the program's `.data` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGlobal {
    pub name: String,
    pub data: Vec<u8>,
}

/// A writable zero-initialized global emitted into the program's `.bss` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BssGlobal {
    pub name: String,
    pub size: usize,
}

/// Location in bytecode that needs a symbol reference resolved by the ELF loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRelocation {
    /// Offset in bytecode (in bytes) where the relocation applies.
    pub insn_offset: usize,
    /// Name of the referenced ELF symbol.
    pub symbol_name: String,
}

/// Relocation within an object-local data symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDataRelocation {
    /// Offset in bytes within the symbol's data blob where the relocation applies.
    pub offset: usize,
    /// Optional named field within the data symbol that this relocation targets.
    ///
    /// Used for `.struct_ops` value symbols, where libbpf expects local BTF members
    /// to line up with callback relocation offsets by name.
    pub field_name: Option<String>,
    /// Name of the referenced ELF symbol.
    pub symbol_name: String,
}

/// Extra object-local data symbol emitted into a custom ELF section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDataSymbol {
    /// ELF section name, for example `.struct_ops`.
    pub section_name: String,
    /// Symbol name within the section.
    pub name: String,
    /// Raw bytes for the symbol payload.
    pub data: Vec<u8>,
    /// Alignment in bytes.
    pub align: u64,
    /// Whether the section should be writable.
    pub writable: bool,
    /// Relocations within this symbol's data payload.
    pub relocations: Vec<ObjectDataRelocation>,
}

/// Function symbol metadata for BPF-to-BPF subfunctions.
#[derive(Debug, Clone)]
pub struct SubfunctionSymbol {
    pub name: String,
    /// Offset in bytecode (in bytes) where the subfunction starts
    pub offset: usize,
    /// Size in bytes of the subfunction
    pub size: usize,
}

/// Field type for structured events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfFieldType {
    /// Integer-like scalar with an explicit encoded width
    Int { size: usize, signed: bool },
    /// Short string from bpf-comm (16 bytes, TASK_COMM_LEN)
    Comm,
    /// Long string from bpf-read-str (128 bytes max)
    String,
    /// Opaque bytes with an explicit size
    Bytes(usize),
}

impl BpfFieldType {
    /// Get the size in bytes for this field type
    pub fn size(&self) -> usize {
        match self {
            BpfFieldType::Int { size, .. } => *size,
            BpfFieldType::Comm => 16,
            BpfFieldType::String => 128,
            BpfFieldType::Bytes(size) => *size,
        }
    }
}

/// A field in a structured event schema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: BpfFieldType,
    /// Optional recursive schema for nested arrays/records carried in this field
    pub value_schema: Option<CounterKeySchema>,
    /// Byte offset within the event struct
    pub offset: usize,
    /// Optional bitfield extraction metadata relative to this field's storage.
    pub bitfield: Option<BitfieldInfo>,
}

/// Schema describing the structure of events emitted by an eBPF program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSchema {
    /// Fields in the event, in order
    pub fields: Vec<SchemaField>,
    /// Total size of the event struct in bytes
    pub total_size: usize,
}

/// One field in a structured `bytes_counters` key schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterKeySchemaField {
    /// Field name
    pub name: String,
    /// Recursive field schema
    pub schema: CounterKeySchema,
    /// Byte offset within the enclosing record
    pub offset: usize,
    /// Optional bitfield extraction metadata relative to this field's storage.
    pub bitfield: Option<BitfieldInfo>,
}

/// Recursive schema describing a `bytes_counters` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterKeySchema {
    /// Integer-like scalar (including pointer-sized scalars)
    Int { size: usize, signed: bool },
    /// Null-terminated byte string stored in a fixed-size array
    String { size: usize },
    /// Opaque bytes when we only know the layout size, not the field shape
    Bytes { size: usize },
    /// Fixed-size homogeneous array
    Array {
        elem: Box<CounterKeySchema>,
        len: usize,
    },
    /// Struct/record with explicit field offsets
    Record {
        name: Option<String>,
        fields: Vec<CounterKeySchemaField>,
        total_size: usize,
    },
}

impl CounterKeySchema {
    /// Size in bytes of the encoded key.
    pub fn size(&self) -> usize {
        match self {
            CounterKeySchema::Int { size, .. }
            | CounterKeySchema::String { size }
            | CounterKeySchema::Bytes { size } => *size,
            CounterKeySchema::Array { elem, len } => elem.size() * len,
            CounterKeySchema::Record { total_size, .. } => *total_size,
        }
    }

    /// Derive a counter-key schema from a MIR type.
    pub fn from_mir_type(ty: &MirType) -> Self {
        match ty {
            MirType::I8 => CounterKeySchema::Int {
                size: 1,
                signed: true,
            },
            MirType::I16 => CounterKeySchema::Int {
                size: 2,
                signed: true,
            },
            MirType::I32 => CounterKeySchema::Int {
                size: 4,
                signed: true,
            },
            MirType::I64 => CounterKeySchema::Int {
                size: 8,
                signed: true,
            },
            MirType::U8 | MirType::Bool => CounterKeySchema::Int {
                size: 1,
                signed: false,
            },
            MirType::U16 => CounterKeySchema::Int {
                size: 2,
                signed: false,
            },
            MirType::U32 => CounterKeySchema::Int {
                size: 4,
                signed: false,
            },
            MirType::U64
            | MirType::Ptr { .. }
            | MirType::MapRef { .. }
            | MirType::Subprogram { .. }
            | MirType::Unknown => CounterKeySchema::Int {
                size: ty.size().max(1),
                signed: false,
            },
            ty if ty.byte_array_len().is_some() => CounterKeySchema::String {
                size: ty
                    .byte_array_len()
                    .expect("byte-array length must exist after guard"),
            },
            MirType::Array { elem, len } => CounterKeySchema::Array {
                elem: Box::new(Self::from_mir_type(elem)),
                len: *len,
            },
            MirType::Struct { name, fields, .. } => {
                if fields.len() == 1
                    && fields[0].name == "__opaque"
                    && fields[0].offset == 0
                    && fields[0].ty.byte_array_len().is_some()
                {
                    return CounterKeySchema::Bytes {
                        size: fields[0].ty.size().max(1),
                    };
                }

                let schema_fields: Vec<CounterKeySchemaField> = fields
                    .iter()
                    .filter(|field| !field.synthetic)
                    .map(|field| CounterKeySchemaField {
                        name: field.name.clone(),
                        schema: Self::from_mir_type(&field.ty),
                        offset: field.offset,
                        bitfield: field.bitfield,
                    })
                    .collect();

                CounterKeySchema::Record {
                    name: name.clone(),
                    fields: schema_fields,
                    total_size: ty.size(),
                }
            }
        }
    }
}

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfProgramType {
    /// Kernel probe (kprobe)
    Kprobe,
    /// Kernel return probe (kretprobe)
    Kretprobe,
    /// Kernel multi-probe (`kprobe.multi`)
    KprobeMulti,
    /// Kernel multi-return probe (`kretprobe.multi`)
    KretprobeMulti,
    /// Kernel syscall probe (`ksyscall`)
    Ksyscall,
    /// Kernel syscall return probe (`kretsyscall`)
    KretSyscall,
    /// BTF function entry probe (fentry)
    Fentry,
    /// BTF function exit probe (fexit)
    Fexit,
    /// BTF modify-return probe (`fmod_ret`)
    FmodRet,
    /// BTF-enabled raw tracepoint (`tp_btf`)
    TpBtf,
    /// Tracepoint
    Tracepoint,
    /// Raw tracepoint
    RawTracepoint,
    /// Writable raw tracepoint
    RawTracepointWritable,
    /// User-space probe (uprobe)
    Uprobe,
    /// User-space return probe (uretprobe)
    Uretprobe,
    /// User-space multi-probe (`uprobe.multi`)
    UprobeMulti,
    /// User-space multi-return probe (`uretprobe.multi`)
    UretprobeMulti,
    /// Linux security module hook program
    Lsm,
    /// Cgroup-scoped Linux security module hook program (`lsm_cgroup`)
    LsmCgroup,
    /// Extension program replacing a global function in another loaded BPF program (`freplace`)
    Extension,
    /// Syscall-capable BPF program (`BPF_PROG_TYPE_SYSCALL`)
    Syscall,
    /// BPF iterator program (`iter/*` section)
    Iter,
    /// XDP program attached to a network interface
    Xdp,
    /// Perf event program attached to software or hardware perf counters
    PerfEvent,
    /// Socket filter program attached to a socket
    SocketFilter,
    /// Cgroup device program attached to a cgroup device hook
    CgroupDevice,
    /// Socket lookup program attached to a network namespace
    SkLookup,
    /// Flow dissector program attached to a network namespace
    FlowDissector,
    /// Netfilter hook program attached to a network namespace netfilter hook
    Netfilter,
    /// Lightweight tunnel input program
    LwtIn,
    /// Lightweight tunnel output program
    LwtOut,
    /// Lightweight tunnel transmit program
    LwtXmit,
    /// Lightweight tunnel Segment Routing local action program
    LwtSeg6Local,
    /// Socket reuseport selector/migration program
    SkReuseport,
    /// Socket message verdict program attached to a pinned sockmap or sockhash
    SkMsg,
    /// Socket-to-socket-buffer stream verdict program attached to a pinned sockmap or sockhash
    SkSkb,
    /// Socket-to-socket-buffer stream parser program attached to a pinned sockmap or sockhash
    SkSkbParser,
    /// Sock-ops program attached to a cgroup
    SockOps,
    /// Traffic-control classifier attached to an interface ingress/egress hook
    Tc,
    /// TCX classifier attached to an interface ingress/egress hook
    Tcx,
    /// Netkit classifier attached to a netkit primary/peer device hook
    Netkit,
    /// Traffic-control action program
    TcAction,
    /// Cgroup socket-buffer program attached to a cgroup ingress/egress hook
    CgroupSkb,
    /// Cgroup socket program attached to socket lifecycle hooks
    CgroupSock,
    /// Cgroup sysctl program attached to a cgroup sysctl hook
    CgroupSysctl,
    /// Cgroup socket-option program attached to getsockopt/setsockopt hooks
    CgroupSockopt,
    /// Cgroup socket-address program attached to a cgroup socket-address hook
    CgroupSockAddr,
    /// LIRC mode2 decoder program attached to a lirc device
    LircMode2,
    /// Struct-ops callback program emitted into a `struct_ops/*` section.
    StructOps,
}

impl EbpfProgramType {
    pub fn info(&self) -> &'static ProgramTypeInfo {
        match self {
            EbpfProgramType::Kprobe => &KPROBE_INFO,
            EbpfProgramType::Kretprobe => &KRETPROBE_INFO,
            EbpfProgramType::KprobeMulti => &KPROBE_MULTI_INFO,
            EbpfProgramType::KretprobeMulti => &KRETPROBE_MULTI_INFO,
            EbpfProgramType::Ksyscall => &KSYSCALL_INFO,
            EbpfProgramType::KretSyscall => &KRET_SYSCALL_INFO,
            EbpfProgramType::Fentry => &FENTRY_INFO,
            EbpfProgramType::Fexit => &FEXIT_INFO,
            EbpfProgramType::FmodRet => &FMOD_RET_INFO,
            EbpfProgramType::TpBtf => &TP_BTF_INFO,
            EbpfProgramType::Tracepoint => &TRACEPOINT_INFO,
            EbpfProgramType::RawTracepoint => &RAW_TRACEPOINT_INFO,
            EbpfProgramType::RawTracepointWritable => &RAW_TRACEPOINT_WRITABLE_INFO,
            EbpfProgramType::Uprobe => &UPROBE_INFO,
            EbpfProgramType::Uretprobe => &URETPROBE_INFO,
            EbpfProgramType::UprobeMulti => &UPROBE_MULTI_INFO,
            EbpfProgramType::UretprobeMulti => &URETPROBE_MULTI_INFO,
            EbpfProgramType::Lsm => &LSM_INFO,
            EbpfProgramType::LsmCgroup => &LSM_CGROUP_INFO,
            EbpfProgramType::Extension => &EXTENSION_INFO,
            EbpfProgramType::Syscall => &SYSCALL_INFO,
            EbpfProgramType::Iter => &ITER_INFO,
            EbpfProgramType::Xdp => &XDP_INFO,
            EbpfProgramType::PerfEvent => &PERF_EVENT_INFO,
            EbpfProgramType::SocketFilter => &SOCKET_FILTER_INFO,
            EbpfProgramType::CgroupDevice => &CGROUP_DEVICE_INFO,
            EbpfProgramType::SkLookup => &SK_LOOKUP_INFO,
            EbpfProgramType::FlowDissector => &FLOW_DISSECTOR_INFO,
            EbpfProgramType::Netfilter => &NETFILTER_INFO,
            EbpfProgramType::LwtIn => &LWT_IN_INFO,
            EbpfProgramType::LwtOut => &LWT_OUT_INFO,
            EbpfProgramType::LwtXmit => &LWT_XMIT_INFO,
            EbpfProgramType::LwtSeg6Local => &LWT_SEG6LOCAL_INFO,
            EbpfProgramType::SkReuseport => &SK_REUSEPORT_INFO,
            EbpfProgramType::SkMsg => &SK_MSG_INFO,
            EbpfProgramType::SkSkb => &SK_SKB_INFO,
            EbpfProgramType::SkSkbParser => &SK_SKB_PARSER_INFO,
            EbpfProgramType::SockOps => &SOCK_OPS_INFO,
            EbpfProgramType::Tc => &TC_INFO,
            EbpfProgramType::Tcx => &TCX_INFO,
            EbpfProgramType::Netkit => &NETKIT_INFO,
            EbpfProgramType::TcAction => &TC_ACTION_INFO,
            EbpfProgramType::CgroupSkb => &CGROUP_SKB_INFO,
            EbpfProgramType::CgroupSock => &CGROUP_SOCK_INFO,
            EbpfProgramType::CgroupSysctl => &CGROUP_SYSCTL_INFO,
            EbpfProgramType::CgroupSockopt => &CGROUP_SOCKOPT_INFO,
            EbpfProgramType::CgroupSockAddr => &CGROUP_SOCK_ADDR_INFO,
            EbpfProgramType::LircMode2 => &LIRC_MODE2_INFO,
            EbpfProgramType::StructOps => &STRUCT_OPS_INFO,
        }
    }

    pub fn supported_spec_prefixes() -> &'static [&'static str] {
        PROGRAM_SPEC_PREFIXES
    }

    pub fn supported_program_types() -> &'static [EbpfProgramType] {
        ALL_PROGRAM_TYPES
    }

    pub fn from_spec_prefix(prefix: &str) -> Option<Self> {
        ALL_PROGRAM_TYPES
            .iter()
            .copied()
            .find(|program_type| program_type.info().spec_aliases.contains(&prefix))
    }

    pub fn canonical_prefix(&self) -> &'static str {
        self.info().canonical_prefix
    }

    pub fn spec_aliases(&self) -> &'static [&'static str] {
        self.info().spec_aliases
    }

    /// Get the underlying kernel UAPI `BPF_PROG_TYPE_*` enum name.
    pub fn kernel_prog_type(&self) -> &'static str {
        self.info().kernel_prog_type
    }

    /// Get the ELF section name prefix for this program type
    pub fn section_prefix(&self) -> &'static str {
        self.info().section_prefix
    }

    pub fn section_uses_target(&self) -> bool {
        self.info().section_uses_target
    }

    pub fn attach_kind(&self) -> ProgramAttachKind {
        self.info().attach_kind
    }

    pub fn context_family(&self) -> ProgramContextFamily {
        self.info().context_family
    }

    pub fn target_kind(&self) -> ProgramTargetKind {
        self.info().target_kind
    }

    pub fn kernel_target_validation(&self) -> Option<KernelTargetValidationKind> {
        self.info().kernel_target_validation
    }

    pub fn supports_intrinsic(&self, intrinsic: ProgramIntrinsic) -> bool {
        if !self.supports_capability(intrinsic.required_capability()) {
            return false;
        }

        match intrinsic {
            ProgramIntrinsic::AdjustPacket => [
                PacketAdjustMode::Head,
                PacketAdjustMode::Meta,
                PacketAdjustMode::Tail,
                PacketAdjustMode::Pull,
                PacketAdjustMode::Room,
            ]
            .into_iter()
            .any(|mode| self.packet_adjust_helper(mode).is_some()),
            ProgramIntrinsic::AdjustMessage => [
                MessageAdjustMode::Apply,
                MessageAdjustMode::Cork,
                MessageAdjustMode::Pull,
                MessageAdjustMode::Push,
                MessageAdjustMode::Pop,
            ]
            .into_iter()
            .any(|mode| self.message_adjust_helper(mode).is_some()),
            ProgramIntrinsic::Redirect => {
                self.packet_redirect_helper().is_some()
                    || self.packet_redirect_peer_helper().is_some()
                    || self.packet_redirect_neigh_helper().is_some()
            }
            ProgramIntrinsic::RedirectMap => {
                self.helper_call_error(BpfHelper::RedirectMap).is_none()
            }
            ProgramIntrinsic::RedirectSocket => {
                self.socket_redirect_helper(MapKind::SockMap).is_some()
                    || self.socket_redirect_helper(MapKind::SockHash).is_some()
                    || self
                        .socket_redirect_helper(MapKind::ReuseportSockArray)
                        .is_some()
            }
            ProgramIntrinsic::AssignSocket => self.helper_call_error(BpfHelper::SkAssign).is_none(),
            _ => true,
        }
    }

    pub fn supported_capabilities(&self) -> &'static [ProgramCapability] {
        self.info().supported_capabilities
    }

    pub fn supports_capability(&self, capability: ProgramCapability) -> bool {
        self.supported_capabilities().contains(&capability)
    }

    pub fn arg_access(&self) -> ProgramValueAccess {
        self.info().arg_access
    }

    pub fn retval_access(&self) -> ProgramValueAccess {
        self.info().retval_access
    }

    pub fn compatibility_requirements(&self) -> &'static [ProgramCompatibilityRequirement] {
        program_types::compatibility_requirements_for(*self)
    }

    pub fn requires_compatibility_feature(
        &self,
        requirement: ProgramCompatibilityRequirement,
    ) -> bool {
        self.compatibility_requirements().contains(&requirement)
    }

    pub fn uses_btf_trampoline(&self) -> bool {
        self.arg_access().is_trampoline() || self.retval_access().is_trampoline()
    }

    pub fn btf_callable_surface(&self) -> Option<ProgramBtfCallableSurface> {
        program_types::btf_callable_surface_for(*self)
    }

    pub fn uses_raw_tracepoint_args(&self) -> bool {
        self.arg_access().is_raw_tracepoint()
    }

    /// Returns true if this runs at function return time.
    pub fn is_return_probe(&self) -> bool {
        self.retval_access().exposes_value()
    }

    /// Returns true if this is a userspace probe (uprobe or uretprobe)
    pub fn is_userspace(&self) -> bool {
        self.target_kind().is_userspace_function()
    }

    /// Returns true if this program type exposes function arguments via ctx.argN.
    pub fn supports_ctx_args(&self) -> bool {
        self.arg_access().exposes_value()
    }

    /// Returns true if this program type exposes ctx.retval.
    pub fn supports_ctx_retval(&self) -> bool {
        self.retval_access().exposes_value()
    }
}

impl fmt::Display for EbpfProgramType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_prefix())
    }
}

/// Context about the probe being compiled
///
/// This provides the compiler with information about where the eBPF program
/// will be attached, enabling:
/// - Automatic selection of kernel vs userspace memory reads
/// - Compile-time validation (e.g., retval only on return probes)
/// - Different context struct layouts for tracepoints vs kprobes
#[derive(Debug, Clone)]
pub struct ProbeContext {
    /// The type of probe (kprobe, uprobe, tracepoint, etc.)
    probe_type: EbpfProgramType,
    /// The target function or tracepoint name
    target: String,
    /// Parsed program model for attach-kind-sensitive policies.
    program_spec: Option<ProgramSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramAttachKind {
    Kprobe,
    Kretprobe,
    KprobeMulti,
    KretprobeMulti,
    Ksyscall,
    KretSyscall,
    Fentry,
    Fexit,
    FmodRet,
    TpBtf,
    Tracepoint,
    RawTracepoint,
    RawTracepointWritable,
    Uprobe,
    Uretprobe,
    UprobeMulti,
    UretprobeMulti,
    Lsm,
    LsmCgroup,
    Extension,
    Syscall,
    Iter,
    Xdp,
    PerfEvent,
    SocketFilter,
    CgroupDevice,
    SkLookup,
    FlowDissector,
    Netfilter,
    Lwt,
    SkReuseport,
    SkMsg,
    SkSkb,
    SkSkbParser,
    SockOps,
    Tc,
    Tcx,
    Netkit,
    TcAction,
    CgroupSkb,
    CgroupSock,
    CgroupSysctl,
    CgroupSockopt,
    CgroupSockAddr,
    LircMode2,
    StructOps,
}

impl ProgramAttachKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::Kprobe => "kprobe",
            Self::Kretprobe => "kretprobe",
            Self::KprobeMulti => "kprobe-multi",
            Self::KretprobeMulti => "kretprobe-multi",
            Self::Ksyscall => "ksyscall",
            Self::KretSyscall => "kret-syscall",
            Self::Fentry => "fentry",
            Self::Fexit => "fexit",
            Self::FmodRet => "fmod-ret",
            Self::TpBtf => "tp-btf",
            Self::Tracepoint => "tracepoint",
            Self::RawTracepoint => "raw-tracepoint",
            Self::RawTracepointWritable => "raw-tracepoint-writable",
            Self::Uprobe => "uprobe",
            Self::Uretprobe => "uretprobe",
            Self::UprobeMulti => "uprobe-multi",
            Self::UretprobeMulti => "uretprobe-multi",
            Self::Lsm => "lsm",
            Self::LsmCgroup => "lsm-cgroup",
            Self::Extension => "extension",
            Self::Syscall => "syscall",
            Self::Iter => "iter",
            Self::Xdp => "xdp",
            Self::PerfEvent => "perf-event",
            Self::SocketFilter => "socket-filter",
            Self::CgroupDevice => "cgroup-device",
            Self::SkLookup => "sk-lookup",
            Self::FlowDissector => "flow-dissector",
            Self::Netfilter => "netfilter",
            Self::Lwt => "lwt",
            Self::SkReuseport => "sk-reuseport",
            Self::SkMsg => "sk-msg",
            Self::SkSkb => "sk-skb",
            Self::SkSkbParser => "sk-skb-parser",
            Self::SockOps => "sock-ops",
            Self::Tc => "tc",
            Self::Tcx => "tcx",
            Self::Netkit => "netkit",
            Self::TcAction => "tc-action",
            Self::CgroupSkb => "cgroup-skb",
            Self::CgroupSock => "cgroup-sock",
            Self::CgroupSysctl => "cgroup-sysctl",
            Self::CgroupSockopt => "cgroup-sockopt",
            Self::CgroupSockAddr => "cgroup-sock-addr",
            Self::LircMode2 => "lirc-mode2",
            Self::StructOps => "struct-ops",
        }
    }

    pub fn loader_supports_live_attach(self) -> bool {
        self.unsupported_live_attach_detail().is_none()
    }

    pub fn unsupported_live_attach_detail(self) -> Option<&'static str> {
        Some(match self {
            Self::RawTracepointWritable => {
                "the current object loader does not preserve writable raw-tracepoint sections, and rewriting them as raw_tracepoint would change verifier semantics"
            }
            Self::FmodRet => {
                "the current Aya loader surface does not expose BPF_MODIFY_RETURN/fmod_ret loading and attach support"
            }
            Self::LsmCgroup => {
                "cgroup-scoped LSM attach requires cgroup-aware BPF link setup, not plain LSM attach"
            }
            Self::Netkit => {
                "the current Aya loader surface does not expose a netkit attach wrapper"
            }
            Self::TcAction => {
                "the current Aya loader surface does not expose a tc_action attach wrapper"
            }
            Self::SkReuseport => {
                "the current Aya loader surface does not expose a sk_reuseport attach wrapper"
            }
            Self::FlowDissector => {
                "the current Aya loader surface does not expose a flow-dissector attach wrapper"
            }
            Self::Netfilter => "the loader still needs BPF-link netfilter attach support",
            Self::Lwt => "the loader still needs route LWT attach support",
            Self::Extension => {
                "extension/freplace live attach requires a loaded target program and BTF/function pairing, not only a target function name"
            }
            Self::Syscall => {
                "BPF_PROG_TYPE_SYSCALL is load/test-run oriented and has no ordinary hook attach in this loader"
            }
            Self::Iter => "the loader still needs BPF iterator link/seq-file attach support",
            _ => return None,
        })
    }
}

impl fmt::Display for ProgramAttachKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramCompatibilityRequirement {
    SocketFilterProgram,
    KprobeProgram,
    TracepointProgram,
    RawTracepointProgram,
    PerfEventProgram,
    XdpProgram,
    XdpSkbAttachMode,
    XdpDrvAttachMode,
    XdpHwAttachMode,
    XdpDevmapAttach,
    XdpCpumapAttach,
    TcProgram,
    SkLookupProgram,
    TracingProgram,
    LsmProgram,
    KernelBtf,
    BpfTrampoline,
    SleepableProgram,
    KprobeMulti,
    UprobeMulti,
    RawTracepointWritable,
    CgroupLsm,
    ExtensionProgram,
    SyscallProgram,
    BpfIterator,
    BpfIteratorTaskTarget,
    BpfIteratorTaskFileTarget,
    BpfIteratorTaskVmaTarget,
    BpfIteratorBpfMapTarget,
    BpfIteratorCgroupTarget,
    BpfIteratorBpfMapElemTarget,
    BpfIteratorBpfSkStorageMapTarget,
    BpfIteratorSockmapTarget,
    BpfIteratorBpfProgTarget,
    BpfIteratorBpfLinkTarget,
    BpfIteratorTcpTarget,
    BpfIteratorUdpTarget,
    BpfIteratorUnixTarget,
    BpfIteratorIpv6RouteTarget,
    BpfIteratorKsymTarget,
    BpfIteratorNetlinkTarget,
    BpfIteratorKmemCacheTarget,
    BpfIteratorDmabufTarget,
    XdpMultiBuffer,
    FlowDissector,
    Tcx,
    Netkit,
    NetfilterLink,
    NetfilterDefrag,
    RouteLwt,
    RouteLwtSeg6Local,
    SockMapAttach,
    SkMsgSockMapAttach,
    SkSkbSockMapAttach,
    SkReuseportAttach,
    SkReuseportMigration,
    TcActionProgram,
    CgroupSkbProgram,
    CgroupSockProgram,
    CgroupDeviceProgram,
    CgroupSockAddrProgram,
    CgroupSysctlProgram,
    CgroupSockoptProgram,
    SockOpsProgram,
    CgroupV2,
    LircMode2,
    StructOps,
    TcpCongestionOps,
    HidBpfOps,
    SchedExt,
    QdiscOps,
    CgroupUnixSockAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramCompatibilityTestLane {
    HostSafe,
    HostGated,
    DryRun,
    VmOnly,
}

impl ProgramCompatibilityTestLane {
    pub fn key(self) -> &'static str {
        match self {
            Self::HostSafe => "host-safe",
            Self::HostGated => "host-gated",
            Self::DryRun => "dry-run",
            Self::VmOnly => "vm-only",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::HostSafe => "safe for default host integration-test lanes",
            Self::HostGated => {
                "requires explicit host resources, elevated privileges, or host-specific setup"
            }
            Self::DryRun => "compile/dry-run coverage only; live attach is not modeled as safe",
            Self::VmOnly => "behavior-changing or high-risk coverage should run in an isolated VM",
        }
    }
}

const BPF_DIRECT_MAP_VALUE_SOURCE: &str =
    "https://github.com/torvalds/linux/commit/d8eca5bbb2be9bc7546f9e733786fa2f1a594c67";
const LINUX_BPF_H_V3_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_1_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h";
const LINUX_IF_LINK_H_V4_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/if_link.h";
const LINUX_IF_LINK_H_V4_13_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/if_link.h";
const LINUX_BPF_H_V4_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_15_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_17_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_19_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V4_20_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_3_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_5_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_9_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_10_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_14_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V5_18_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_0_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.0/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.4/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/bpf.h";
const LINUX_BPF_H_V6_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/bpf.h";
const LINUX_BPF_TRAMPOLINE_V5_5_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.5/kernel/bpf/trampoline.c";
const LINUX_LINK_VMLINUX_V5_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.2/scripts/link-vmlinux.sh";
const LINUX_BPF_TCP_CA_V5_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.6/net/ipv4/bpf_tcp_ca.c";
const LINUX_HID_BPF_STRUCT_OPS_V6_11_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.11/drivers/hid/bpf/hid_bpf_struct_ops.c";
const LINUX_SCHED_EXT_V6_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c";
const LINUX_BPF_QDISC_V6_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.16/net/sched/bpf_qdisc.c";
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
const LINUX_NETLINK_V5_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.8/net/netlink/af_netlink.c";
const LINUX_KMEM_CACHE_ITER_V6_13_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/kmem_cache_iter.c";
const LINUX_DMABUF_ITER_V6_16_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/dmabuf_iter.c";

impl ProgramCompatibilityRequirement {
    pub fn all() -> &'static [ProgramCompatibilityRequirement] {
        PROGRAM_COMPATIBILITY_REQUIREMENTS
    }

    pub fn key(&self) -> &'static str {
        match self {
            Self::SocketFilterProgram => "socket-filter-program",
            Self::KprobeProgram => "kprobe-program",
            Self::TracepointProgram => "tracepoint-program",
            Self::RawTracepointProgram => "raw-tracepoint-program",
            Self::PerfEventProgram => "perf-event-program",
            Self::XdpProgram => "xdp-program",
            Self::XdpSkbAttachMode => "xdp-attach-skb",
            Self::XdpDrvAttachMode => "xdp-attach-drv",
            Self::XdpHwAttachMode => "xdp-attach-hw",
            Self::XdpDevmapAttach => "xdp-attach-devmap",
            Self::XdpCpumapAttach => "xdp-attach-cpumap",
            Self::TcProgram => "tc-program",
            Self::SkLookupProgram => "sk-lookup-program",
            Self::TracingProgram => "tracing-program",
            Self::LsmProgram => "lsm-program",
            Self::KernelBtf => "kernel-btf",
            Self::BpfTrampoline => "bpf-trampoline",
            Self::SleepableProgram => "sleepable-program",
            Self::KprobeMulti => "kprobe-multi",
            Self::UprobeMulti => "uprobe-multi",
            Self::RawTracepointWritable => "raw-tracepoint-writable",
            Self::CgroupLsm => "cgroup-lsm",
            Self::ExtensionProgram => "extension-program",
            Self::SyscallProgram => "syscall-program",
            Self::BpfIterator => "bpf-iterator",
            Self::BpfIteratorTaskTarget => "bpf-iterator-target-task",
            Self::BpfIteratorTaskFileTarget => "bpf-iterator-target-task-file",
            Self::BpfIteratorTaskVmaTarget => "bpf-iterator-target-task-vma",
            Self::BpfIteratorBpfMapTarget => "bpf-iterator-target-bpf-map",
            Self::BpfIteratorCgroupTarget => "bpf-iterator-target-cgroup",
            Self::BpfIteratorBpfMapElemTarget => "bpf-iterator-target-bpf-map-elem",
            Self::BpfIteratorBpfSkStorageMapTarget => "bpf-iterator-target-bpf-sk-storage-map",
            Self::BpfIteratorSockmapTarget => "bpf-iterator-target-sockmap",
            Self::BpfIteratorBpfProgTarget => "bpf-iterator-target-bpf-prog",
            Self::BpfIteratorBpfLinkTarget => "bpf-iterator-target-bpf-link",
            Self::BpfIteratorTcpTarget => "bpf-iterator-target-tcp",
            Self::BpfIteratorUdpTarget => "bpf-iterator-target-udp",
            Self::BpfIteratorUnixTarget => "bpf-iterator-target-unix",
            Self::BpfIteratorIpv6RouteTarget => "bpf-iterator-target-ipv6-route",
            Self::BpfIteratorKsymTarget => "bpf-iterator-target-ksym",
            Self::BpfIteratorNetlinkTarget => "bpf-iterator-target-netlink",
            Self::BpfIteratorKmemCacheTarget => "bpf-iterator-target-kmem-cache",
            Self::BpfIteratorDmabufTarget => "bpf-iterator-target-dmabuf",
            Self::XdpMultiBuffer => "xdp-multi-buffer",
            Self::FlowDissector => "flow-dissector",
            Self::Tcx => "tcx",
            Self::Netkit => "netkit",
            Self::NetfilterLink => "netfilter-link",
            Self::NetfilterDefrag => "netfilter-defrag",
            Self::RouteLwt => "route-lwt",
            Self::RouteLwtSeg6Local => "route-lwt-seg6local",
            Self::SockMapAttach => "sockmap-attach",
            Self::SkMsgSockMapAttach => "sk-msg-sockmap-attach",
            Self::SkSkbSockMapAttach => "sk-skb-sockmap-attach",
            Self::SkReuseportAttach => "sk-reuseport-attach",
            Self::SkReuseportMigration => "sk-reuseport-migration",
            Self::TcActionProgram => "tc-action-program",
            Self::CgroupSkbProgram => "cgroup-skb-program",
            Self::CgroupSockProgram => "cgroup-sock-program",
            Self::CgroupDeviceProgram => "cgroup-device-program",
            Self::CgroupSockAddrProgram => "cgroup-sock-addr-program",
            Self::CgroupSysctlProgram => "cgroup-sysctl-program",
            Self::CgroupSockoptProgram => "cgroup-sockopt-program",
            Self::SockOpsProgram => "sock-ops-program",
            Self::CgroupV2 => "cgroup-v2",
            Self::LircMode2 => "lirc-mode2",
            Self::StructOps => "struct-ops",
            Self::TcpCongestionOps => "tcp-congestion-ops",
            Self::HidBpfOps => "hid-bpf-ops",
            Self::SchedExt => "sched-ext",
            Self::QdiscOps => "qdisc-ops",
            Self::CgroupUnixSockAddr => "cgroup-unix-sock-addr",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SocketFilterProgram => "socket-filter BPF program support",
            Self::KprobeProgram => "kprobe/uprobe BPF program support",
            Self::TracepointProgram => "tracepoint BPF program support",
            Self::RawTracepointProgram => "raw-tracepoint BPF program support",
            Self::PerfEventProgram => "perf-event BPF program support",
            Self::XdpProgram => "XDP BPF program support",
            Self::XdpSkbAttachMode => "XDP generic/SKB attach mode flag support",
            Self::XdpDrvAttachMode => "XDP native/driver attach mode flag support",
            Self::XdpHwAttachMode => "XDP hardware-offload attach mode flag support",
            Self::XdpDevmapAttach => "XDP devmap secondary program attach support",
            Self::XdpCpumapAttach => "XDP cpumap secondary program attach support",
            Self::TcProgram => "traffic-control classifier BPF program support",
            Self::SkLookupProgram => "socket lookup BPF program support",
            Self::TracingProgram => "BPF tracing program support",
            Self::LsmProgram => "BPF LSM program support",
            Self::KernelBtf => "kernel BTF for typed BTF-backed program targets",
            Self::BpfTrampoline => "BPF trampoline target support",
            Self::SleepableProgram => "sleepable BPF program section support",
            Self::KprobeMulti => "multi-kprobe attach support",
            Self::UprobeMulti => "multi-uprobe attach support",
            Self::RawTracepointWritable => "writable raw-tracepoint program support",
            Self::CgroupLsm => "cgroup-scoped LSM attach support",
            Self::ExtensionProgram => "BPF extension/freplace target compatibility",
            Self::SyscallProgram => "BPF syscall program support",
            Self::BpfIterator => "BPF iterator target support",
            Self::BpfIteratorTaskTarget => "BPF task iterator target support",
            Self::BpfIteratorTaskFileTarget => "BPF task_file iterator target support",
            Self::BpfIteratorTaskVmaTarget => "BPF task_vma iterator target support",
            Self::BpfIteratorBpfMapTarget => "BPF bpf_map iterator target support",
            Self::BpfIteratorCgroupTarget => "BPF cgroup iterator target support",
            Self::BpfIteratorBpfMapElemTarget => "BPF bpf_map_elem iterator target support",
            Self::BpfIteratorBpfSkStorageMapTarget => {
                "BPF bpf_sk_storage_map iterator target support"
            }
            Self::BpfIteratorSockmapTarget => "BPF sockmap iterator target support",
            Self::BpfIteratorBpfProgTarget => "BPF bpf_prog iterator target support",
            Self::BpfIteratorBpfLinkTarget => "BPF bpf_link iterator target support",
            Self::BpfIteratorTcpTarget => "BPF TCP iterator target support",
            Self::BpfIteratorUdpTarget => "BPF UDP iterator target support",
            Self::BpfIteratorUnixTarget => "BPF UNIX iterator target support",
            Self::BpfIteratorIpv6RouteTarget => "BPF IPv6 route iterator target support",
            Self::BpfIteratorKsymTarget => "BPF ksymbol iterator target support",
            Self::BpfIteratorNetlinkTarget => "BPF netlink iterator target support",
            Self::BpfIteratorKmemCacheTarget => "BPF kmem_cache iterator target support",
            Self::BpfIteratorDmabufTarget => "BPF dma-buf iterator target support",
            Self::XdpMultiBuffer => "XDP multi-buffer section support",
            Self::FlowDissector => "BPF flow-dissector attach support",
            Self::Tcx => "TCX attach support",
            Self::Netkit => "netkit attach support",
            Self::NetfilterLink => "BPF-link netfilter attach support",
            Self::NetfilterDefrag => "BPF-link netfilter IP defragmentation flag support",
            Self::RouteLwt => "route lightweight-tunnel BPF attach support",
            Self::RouteLwtSeg6Local => "SEG6 local lightweight-tunnel BPF program support",
            Self::SockMapAttach => "sockmap or sockhash attach support",
            Self::SkMsgSockMapAttach => "sk_msg sockmap or sockhash attach support",
            Self::SkSkbSockMapAttach => "sk_skb sockmap or sockhash attach support",
            Self::SkReuseportAttach => "SO_REUSEPORT BPF attach support",
            Self::SkReuseportMigration => "SO_REUSEPORT socket migration program support",
            Self::TcActionProgram => "traffic-control action BPF program support",
            Self::CgroupSkbProgram => "cgroup SKB BPF program support",
            Self::CgroupSockProgram => "cgroup socket BPF program support",
            Self::CgroupDeviceProgram => "cgroup device BPF program support",
            Self::CgroupSockAddrProgram => "cgroup socket-address BPF program support",
            Self::CgroupSysctlProgram => "cgroup sysctl BPF program support",
            Self::CgroupSockoptProgram => "cgroup sockopt BPF program support",
            Self::SockOpsProgram => "sock_ops BPF program support",
            Self::CgroupV2 => "cgroup v2 attach hierarchy",
            Self::LircMode2 => "LIRC mode2 device attach support",
            Self::StructOps => "BPF struct_ops object support",
            Self::TcpCongestionOps => "TCP congestion-control struct_ops support",
            Self::HidBpfOps => "HID-BPF struct_ops support",
            Self::SchedExt => "sched_ext struct_ops support",
            Self::QdiscOps => "BPF Qdisc struct_ops support",
            Self::CgroupUnixSockAddr => "cgroup UNIX socket-address hook support",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::KernelBtf => "kernel-metadata",
            Self::CgroupV2 | Self::LircMode2 => "attach-resource",
            Self::TcpCongestionOps | Self::HidBpfOps | Self::SchedExt | Self::QdiscOps => {
                "struct-ops-family"
            }
            Self::NetfilterDefrag
            | Self::XdpSkbAttachMode
            | Self::XdpDrvAttachMode
            | Self::XdpHwAttachMode
            | Self::XdpDevmapAttach
            | Self::XdpCpumapAttach
            | Self::SkReuseportMigration
            | Self::CgroupUnixSockAddr => "attach-mode",
            Self::SleepableProgram | Self::XdpMultiBuffer => "section-feature",
            Self::BpfIteratorTaskTarget
            | Self::BpfIteratorTaskFileTarget
            | Self::BpfIteratorBpfMapTarget
            | Self::BpfIteratorTaskVmaTarget
            | Self::BpfIteratorCgroupTarget
            | Self::BpfIteratorBpfMapElemTarget
            | Self::BpfIteratorBpfSkStorageMapTarget
            | Self::BpfIteratorSockmapTarget
            | Self::BpfIteratorBpfProgTarget
            | Self::BpfIteratorBpfLinkTarget
            | Self::BpfIteratorTcpTarget
            | Self::BpfIteratorUdpTarget
            | Self::BpfIteratorUnixTarget
            | Self::BpfIteratorIpv6RouteTarget
            | Self::BpfIteratorKsymTarget
            | Self::BpfIteratorNetlinkTarget
            | Self::BpfIteratorKmemCacheTarget
            | Self::BpfIteratorDmabufTarget => "iterator-target",
            Self::StructOps => "object-loader",
            _ => "program-feature",
        }
    }

    pub fn test_lane(&self) -> ProgramCompatibilityTestLane {
        match self {
            Self::ExtensionProgram | Self::SyscallProgram => ProgramCompatibilityTestLane::DryRun,
            Self::NetfilterLink
            | Self::RouteLwt
            | Self::StructOps
            | Self::TcpCongestionOps
            | Self::HidBpfOps
            | Self::SchedExt
            | Self::QdiscOps => ProgramCompatibilityTestLane::VmOnly,
            Self::RawTracepointWritable
            | Self::SocketFilterProgram
            | Self::XdpProgram
            | Self::TcProgram
            | Self::SkLookupProgram
            | Self::CgroupLsm
            | Self::XdpMultiBuffer
            | Self::FlowDissector
            | Self::Tcx
            | Self::Netkit
            | Self::NetfilterDefrag
            | Self::XdpSkbAttachMode
            | Self::XdpDrvAttachMode
            | Self::XdpHwAttachMode
            | Self::XdpDevmapAttach
            | Self::XdpCpumapAttach
            | Self::RouteLwtSeg6Local
            | Self::SockMapAttach
            | Self::SkMsgSockMapAttach
            | Self::SkSkbSockMapAttach
            | Self::SkReuseportAttach
            | Self::SkReuseportMigration
            | Self::TcActionProgram
            | Self::CgroupSkbProgram
            | Self::CgroupSockProgram
            | Self::CgroupDeviceProgram
            | Self::CgroupSockAddrProgram
            | Self::CgroupSysctlProgram
            | Self::CgroupSockoptProgram
            | Self::SockOpsProgram
            | Self::CgroupV2
            | Self::LircMode2
            | Self::CgroupUnixSockAddr => ProgramCompatibilityTestLane::HostGated,
            Self::KernelBtf
            | Self::KprobeProgram
            | Self::TracepointProgram
            | Self::RawTracepointProgram
            | Self::PerfEventProgram
            | Self::TracingProgram
            | Self::LsmProgram
            | Self::BpfTrampoline
            | Self::SleepableProgram
            | Self::KprobeMulti
            | Self::UprobeMulti
            | Self::BpfIterator
            | Self::BpfIteratorTaskTarget
            | Self::BpfIteratorTaskFileTarget
            | Self::BpfIteratorBpfMapTarget
            | Self::BpfIteratorTaskVmaTarget
            | Self::BpfIteratorCgroupTarget
            | Self::BpfIteratorBpfMapElemTarget
            | Self::BpfIteratorBpfSkStorageMapTarget
            | Self::BpfIteratorSockmapTarget
            | Self::BpfIteratorBpfProgTarget
            | Self::BpfIteratorBpfLinkTarget
            | Self::BpfIteratorTcpTarget
            | Self::BpfIteratorUdpTarget
            | Self::BpfIteratorUnixTarget
            | Self::BpfIteratorIpv6RouteTarget
            | Self::BpfIteratorKsymTarget
            | Self::BpfIteratorNetlinkTarget
            | Self::BpfIteratorKmemCacheTarget
            | Self::BpfIteratorDmabufTarget => ProgramCompatibilityTestLane::HostSafe,
        }
    }

    pub fn default_test_lane(&self) -> &'static str {
        self.test_lane().key()
    }

    pub fn effective_test_lane(
        requirements: &[ProgramCompatibilityRequirement],
    ) -> ProgramCompatibilityTestLane {
        requirements
            .iter()
            .map(ProgramCompatibilityRequirement::test_lane)
            .max()
            .unwrap_or(ProgramCompatibilityTestLane::HostSafe)
    }

    pub fn effective_default_test_lane(
        requirements: &[ProgramCompatibilityRequirement],
    ) -> &'static str {
        Self::effective_test_lane(requirements).key()
    }

    pub fn minimum_kernel(&self) -> Option<&'static str> {
        match self {
            Self::SocketFilterProgram => Some("3.19"),
            Self::KprobeProgram | Self::TcProgram => Some("4.1"),
            Self::TracepointProgram => Some("4.7"),
            Self::XdpProgram => Some("4.8"),
            Self::XdpSkbAttachMode | Self::XdpDrvAttachMode => Some("4.12"),
            Self::XdpHwAttachMode => Some("4.13"),
            Self::XdpDevmapAttach => Some("5.8"),
            Self::XdpCpumapAttach => Some("5.9"),
            Self::PerfEventProgram => Some("4.9"),
            Self::RawTracepointProgram => Some("4.17"),
            Self::SkLookupProgram => Some("5.9"),
            Self::TracingProgram => Some("5.5"),
            Self::LsmProgram => Some("5.7"),
            Self::KernelBtf => Some("5.2"),
            Self::BpfTrampoline => Some("5.5"),
            Self::SleepableProgram => Some("5.10"),
            Self::KprobeMulti => Some("5.18"),
            Self::UprobeMulti => Some("6.6"),
            Self::RawTracepointWritable => Some("5.2"),
            Self::CgroupLsm => Some("6.0"),
            Self::ExtensionProgram => Some("5.6"),
            Self::SyscallProgram => Some("5.14"),
            Self::BpfIterator => Some("5.8"),
            Self::BpfIteratorTaskTarget => Some("5.8"),
            Self::BpfIteratorTaskFileTarget => Some("5.8"),
            Self::BpfIteratorTaskVmaTarget => Some("5.12"),
            Self::BpfIteratorBpfMapTarget => Some("5.8"),
            Self::BpfIteratorCgroupTarget => Some("6.1"),
            Self::BpfIteratorBpfMapElemTarget => Some("5.9"),
            Self::BpfIteratorBpfSkStorageMapTarget => Some("5.9"),
            Self::BpfIteratorSockmapTarget => Some("5.10"),
            Self::BpfIteratorBpfProgTarget => Some("5.9"),
            Self::BpfIteratorBpfLinkTarget => Some("5.19"),
            Self::BpfIteratorTcpTarget => Some("5.9"),
            Self::BpfIteratorUdpTarget => Some("5.9"),
            Self::BpfIteratorUnixTarget => Some("5.15"),
            Self::BpfIteratorIpv6RouteTarget => Some("5.8"),
            Self::BpfIteratorKsymTarget => Some("6.0"),
            Self::BpfIteratorNetlinkTarget => Some("5.8"),
            Self::BpfIteratorKmemCacheTarget => Some("6.13"),
            Self::BpfIteratorDmabufTarget => Some("6.16"),
            Self::XdpMultiBuffer => Some("5.18"),
            Self::FlowDissector => Some("4.20"),
            Self::Tcx => Some("6.6"),
            Self::Netkit => Some("6.7"),
            Self::NetfilterLink => Some("6.4"),
            Self::NetfilterDefrag => Some("6.6"),
            Self::RouteLwt => Some("4.10"),
            Self::RouteLwtSeg6Local => Some("4.18"),
            Self::SkMsgSockMapAttach => Some("4.17"),
            Self::SkSkbSockMapAttach => Some("4.14"),
            Self::SkReuseportAttach => Some("4.19"),
            Self::SkReuseportMigration => Some("5.14"),
            Self::TcActionProgram => Some("4.1"),
            Self::CgroupSkbProgram | Self::CgroupSockProgram => Some("4.10"),
            Self::CgroupDeviceProgram => Some("4.15"),
            Self::CgroupSockAddrProgram => Some("4.17"),
            Self::CgroupSysctlProgram => Some("5.2"),
            Self::CgroupSockoptProgram => Some("5.3"),
            Self::SockOpsProgram => Some("4.14"),
            Self::LircMode2 => Some("4.18"),
            Self::StructOps => Some("5.6"),
            Self::TcpCongestionOps => Some("5.6"),
            Self::HidBpfOps => Some("6.11"),
            Self::SchedExt => Some("6.12"),
            Self::QdiscOps => Some("6.16"),
            Self::CgroupUnixSockAddr => Some("6.7"),
            Self::SockMapAttach | Self::CgroupV2 => None,
        }
    }

    pub fn minimum_kernel_source(&self) -> Option<&'static str> {
        self.minimum_kernel()?;
        Some(match self {
            Self::KernelBtf => LINUX_LINK_VMLINUX_V5_2_SOURCE,
            Self::BpfTrampoline => LINUX_BPF_TRAMPOLINE_V5_5_SOURCE,
            Self::SleepableProgram => LINUX_BPF_H_V5_10_SOURCE,
            Self::KprobeMulti | Self::XdpMultiBuffer => LINUX_BPF_H_V5_18_SOURCE,
            Self::RawTracepointWritable => LINUX_BPF_H_V5_2_SOURCE,
            Self::CgroupLsm => LINUX_BPF_H_V6_0_SOURCE,
            Self::ExtensionProgram | Self::StructOps => LINUX_BPF_H_V5_6_SOURCE,
            Self::TcpCongestionOps => LINUX_BPF_TCP_CA_V5_6_SOURCE,
            Self::HidBpfOps => LINUX_HID_BPF_STRUCT_OPS_V6_11_SOURCE,
            Self::SyscallProgram | Self::SkReuseportMigration => LINUX_BPF_H_V5_14_SOURCE,
            Self::BpfIterator => LINUX_BPF_H_V5_8_SOURCE,
            Self::BpfIteratorTaskTarget | Self::BpfIteratorTaskFileTarget => {
                LINUX_TASK_ITER_V5_8_SOURCE
            }
            Self::FlowDissector => LINUX_BPF_H_V4_20_SOURCE,
            Self::Tcx => LINUX_BPF_H_V6_6_SOURCE,
            Self::Netkit => LINUX_BPF_H_V6_7_SOURCE,
            Self::NetfilterLink => LINUX_BPF_H_V6_4_SOURCE,
            Self::NetfilterDefrag => LINUX_BPF_H_V6_6_SOURCE,
            Self::RouteLwt => LINUX_BPF_H_V4_10_SOURCE,
            Self::RouteLwtSeg6Local | Self::LircMode2 => LINUX_BPF_H_V4_18_SOURCE,
            Self::SkMsgSockMapAttach => LINUX_BPF_H_V4_17_SOURCE,
            Self::SkSkbSockMapAttach => LINUX_BPF_H_V4_14_SOURCE,
            Self::SkReuseportAttach => LINUX_BPF_H_V4_19_SOURCE,
            Self::SchedExt => LINUX_SCHED_EXT_V6_12_SOURCE,
            Self::QdiscOps => LINUX_BPF_QDISC_V6_16_SOURCE,
            Self::SocketFilterProgram => LINUX_BPF_H_V3_19_SOURCE,
            Self::KprobeProgram | Self::TcProgram | Self::TcActionProgram => {
                LINUX_BPF_H_V4_1_SOURCE
            }
            Self::TracepointProgram => LINUX_BPF_H_V4_7_SOURCE,
            Self::XdpProgram => LINUX_BPF_H_V4_8_SOURCE,
            Self::XdpSkbAttachMode | Self::XdpDrvAttachMode => LINUX_IF_LINK_H_V4_12_SOURCE,
            Self::XdpHwAttachMode => LINUX_IF_LINK_H_V4_13_SOURCE,
            Self::XdpDevmapAttach => LINUX_BPF_H_V5_8_SOURCE,
            Self::XdpCpumapAttach => LINUX_BPF_H_V5_9_SOURCE,
            Self::PerfEventProgram => LINUX_BPF_H_V4_9_SOURCE,
            Self::RawTracepointProgram => LINUX_BPF_H_V4_17_SOURCE,
            Self::SkLookupProgram => LINUX_BPF_H_V5_9_SOURCE,
            Self::TracingProgram => LINUX_BPF_H_V5_5_SOURCE,
            Self::LsmProgram => LINUX_BPF_H_V5_7_SOURCE,
            Self::UprobeMulti => LINUX_BPF_H_V6_6_SOURCE,
            Self::CgroupSkbProgram | Self::CgroupSockProgram => LINUX_BPF_H_V4_10_SOURCE,
            Self::CgroupDeviceProgram => LINUX_BPF_H_V4_15_SOURCE,
            Self::CgroupSockAddrProgram => LINUX_BPF_H_V4_17_SOURCE,
            Self::CgroupSysctlProgram => LINUX_BPF_H_V5_2_SOURCE,
            Self::CgroupSockoptProgram => LINUX_BPF_H_V5_3_SOURCE,
            Self::SockOpsProgram => LINUX_BPF_H_V4_14_SOURCE,
            Self::CgroupUnixSockAddr => LINUX_BPF_H_V6_7_SOURCE,
            Self::BpfIteratorTaskVmaTarget => LINUX_TASK_ITER_V5_12_SOURCE,
            Self::BpfIteratorBpfMapTarget => LINUX_MAP_ITER_V5_8_SOURCE,
            Self::BpfIteratorCgroupTarget => LINUX_CGROUP_ITER_V6_1_SOURCE,
            Self::BpfIteratorBpfMapElemTarget => LINUX_MAP_ITER_V5_9_SOURCE,
            Self::BpfIteratorBpfSkStorageMapTarget => LINUX_BPF_SK_STORAGE_V5_9_SOURCE,
            Self::BpfIteratorSockmapTarget => LINUX_SOCK_MAP_V5_10_SOURCE,
            Self::BpfIteratorBpfProgTarget => LINUX_PROG_ITER_V5_9_SOURCE,
            Self::BpfIteratorBpfLinkTarget => LINUX_LINK_ITER_V5_19_SOURCE,
            Self::BpfIteratorTcpTarget => LINUX_TCP_IPV4_V5_9_SOURCE,
            Self::BpfIteratorUdpTarget => LINUX_UDP_V5_9_SOURCE,
            Self::BpfIteratorUnixTarget => LINUX_AF_UNIX_V5_15_SOURCE,
            Self::BpfIteratorIpv6RouteTarget => LINUX_IPV6_ROUTE_V5_8_SOURCE,
            Self::BpfIteratorKsymTarget => LINUX_KALLSYMS_V6_0_SOURCE,
            Self::BpfIteratorNetlinkTarget => LINUX_NETLINK_V5_8_SOURCE,
            Self::BpfIteratorKmemCacheTarget => LINUX_KMEM_CACHE_ITER_V6_13_SOURCE,
            Self::BpfIteratorDmabufTarget => LINUX_DMABUF_ITER_V6_16_SOURCE,
            Self::SockMapAttach | Self::CgroupV2 => {
                unreachable!("requirements without a minimum kernel have no source")
            }
        })
    }

    pub fn effective_minimum_kernel(
        requirements: &[ProgramCompatibilityRequirement],
    ) -> Option<&'static str> {
        let mut minimum = None;
        for requirement in requirements {
            let Some(candidate) = requirement.minimum_kernel() else {
                continue;
            };
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

impl fmt::Display for ProgramCompatibilityTestLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

impl fmt::Display for ProgramCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// Source-backed kernel compatibility metadata for emitted global data sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GlobalCompatibilityRequirement {
    BpfDataSections,
}

impl GlobalCompatibilityRequirement {
    pub fn key(self) -> &'static str {
        match self {
            Self::BpfDataSections => "global:bpf-data-sections",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::BpfDataSections => "BPF global data-section support",
        }
    }

    pub fn category(self) -> &'static str {
        "globals"
    }

    pub fn minimum_kernel(self) -> &'static str {
        match self {
            Self::BpfDataSections => "5.2",
        }
    }

    pub fn minimum_kernel_source(self) -> &'static str {
        match self {
            Self::BpfDataSections => BPF_DIRECT_MAP_VALUE_SOURCE,
        }
    }

    pub fn effective_minimum_kernel(requirements: &[Self]) -> Option<&'static str> {
        let mut minimum = None;
        for requirement in requirements {
            let candidate = requirement.minimum_kernel();
            let should_replace = match minimum {
                Some(current) => !Self::kernel_version_at_least(current, candidate),
                None => true,
            };
            if should_replace {
                minimum = Some(candidate);
            }
        }
        minimum
    }

    pub fn kernel_version_at_least(current: &str, minimum: &str) -> bool {
        ProgramCompatibilityRequirement::kernel_version_at_least(current, minimum)
    }
}

impl fmt::Display for GlobalCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramTargetKind {
    KernelFunction,
    KernelFunctionPattern,
    KernelSyscall,
    BtfTracepoint,
    LsmHook,
    ExtensionFunction,
    SyscallProgram,
    BpfIteratorTarget,
    Tracepoint,
    RawTracepoint,
    UserFunction,
    UserFunctionPattern,
    NetworkInterface,
    XdpSecondaryProgram,
    PerfEventTarget,
    SocketFilterTarget,
    NetworkNamespacePath,
    NetfilterHook,
    LightweightTunnelRoute,
    SocketReuseportMode,
    PinnedSockMapPath,
    TrafficControlInterface,
    TrafficControlAction,
    CgroupPathAttachType,
    CgroupPathSockAttachType,
    CgroupPath,
    CgroupPathSockoptAttachType,
    CgroupPathSockAddrAttachType,
    LircDevicePath,
    StructOpsValueType,
    StructOpsCallback,
}

impl ProgramTargetKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::KernelFunction => "kernel-function",
            Self::KernelFunctionPattern => "kernel-function-pattern",
            Self::KernelSyscall => "kernel-syscall",
            Self::BtfTracepoint => "btf-tracepoint",
            Self::LsmHook => "lsm-hook",
            Self::ExtensionFunction => "extension-function",
            Self::SyscallProgram => "syscall-program",
            Self::BpfIteratorTarget => "bpf-iterator-target",
            Self::Tracepoint => "tracepoint",
            Self::RawTracepoint => "raw-tracepoint",
            Self::UserFunction => "user-function",
            Self::UserFunctionPattern => "user-function-pattern",
            Self::NetworkInterface => "network-interface",
            Self::XdpSecondaryProgram => "xdp-secondary-program",
            Self::PerfEventTarget => "perf-event-target",
            Self::SocketFilterTarget => "socket-filter-target",
            Self::NetworkNamespacePath => "network-namespace-path",
            Self::NetfilterHook => "netfilter-hook",
            Self::LightweightTunnelRoute => "lightweight-tunnel-route",
            Self::SocketReuseportMode => "socket-reuseport-mode",
            Self::PinnedSockMapPath => "pinned-sock-map-path",
            Self::TrafficControlInterface => "traffic-control-interface",
            Self::TrafficControlAction => "traffic-control-action",
            Self::CgroupPathAttachType => "cgroup-path-attach-type",
            Self::CgroupPathSockAttachType => "cgroup-path-sock-attach-type",
            Self::CgroupPath => "cgroup-path",
            Self::CgroupPathSockoptAttachType => "cgroup-path-sockopt-attach-type",
            Self::CgroupPathSockAddrAttachType => "cgroup-path-sock-addr-attach-type",
            Self::LircDevicePath => "lirc-device-path",
            Self::StructOpsValueType => "struct-ops-value-type",
            Self::StructOpsCallback => "struct-ops-callback",
        }
    }

    pub fn is_userspace_function(self) -> bool {
        matches!(self, Self::UserFunction | Self::UserFunctionPattern)
    }

    pub fn is_tracepoint(self) -> bool {
        matches!(self, Self::Tracepoint)
    }
}

impl fmt::Display for ProgramTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramBtfCallableSurface {
    FunctionTrampoline,
    TpBtf,
    LsmHook,
    StructOpsCallback,
}

impl ProgramBtfCallableSurface {
    pub fn key(self) -> &'static str {
        match self {
            Self::FunctionTrampoline => "function-trampoline",
            Self::TpBtf => "tp-btf",
            Self::LsmHook => "lsm-hook",
            Self::StructOpsCallback => "struct-ops-callback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketContextKind {
    XdpMd,
    SkBuff,
    SkReuseport,
    SkMsg,
    SockOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelTargetValidationKind {
    SymbolOnly,
    FentryTrampoline,
    FexitTrampoline,
    FmodRetTrampoline,
    LsmHook,
}

impl KernelTargetValidationKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::SymbolOnly => "symbol-only",
            Self::FentryTrampoline => "fentry-trampoline",
            Self::FexitTrampoline => "fexit-trampoline",
            Self::FmodRetTrampoline => "fmod-ret-trampoline",
            Self::LsmHook => "lsm-hook",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramValueAccess {
    None,
    PtRegs,
    RawTracepoint,
    Trampoline,
}

impl ProgramValueAccess {
    pub fn key(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PtRegs => "pt-regs",
            Self::RawTracepoint => "raw-tracepoint",
            Self::Trampoline => "trampoline",
        }
    }

    pub fn exposes_value(self) -> bool {
        !matches!(self, ProgramValueAccess::None)
    }

    pub fn is_pt_regs(self) -> bool {
        matches!(self, ProgramValueAccess::PtRegs)
    }

    pub fn is_raw_tracepoint(self) -> bool {
        matches!(self, ProgramValueAccess::RawTracepoint)
    }

    pub fn is_trampoline(self) -> bool {
        matches!(self, ProgramValueAccess::Trampoline)
    }
}

impl fmt::Display for ProgramValueAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProgramReturnAlias {
    Const(i64),
    PacketLen,
}

impl ProgramReturnAlias {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Const(_) => "const",
            Self::PacketLen => "packet-len",
        }
    }

    pub(crate) fn const_value(self) -> Option<i64> {
        match self {
            Self::Const(value) => Some(value),
            Self::PacketLen => None,
        }
    }
}

impl fmt::Display for ProgramReturnAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CtxWriteTarget {
    StoreField(CtxStoreTarget),
    SysctlNewValue,
    SockoptOptvalByte(usize),
    AssignSocket,
    CgroupSockAddrSunPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SocketContextLayout {
    SockAddr,
    CgroupSock,
    CgroupSockopt,
    SkLookup,
    SkReuseport,
    SkMsg,
    SkBuff,
    SockOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IngressIfindexContextLayout {
    XdpMd,
    SkBuff,
    SkLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramIntrinsic {
    Emit,
    Count,
    Histogram,
    StartTimer,
    StopTimer,
    ReadStr,
    ReadKernelStr,
    AdjustPacket,
    AdjustMessage,
    Redirect,
    RedirectMap,
    RedirectSocket,
    AssignSocket,
    HelperCall,
    KfuncCall,
    TailCall,
    GlobalDefine,
    GlobalGet,
    GlobalSet,
    MapDefine,
    MapGet,
    MapPut,
    MapDelete,
    MapContains,
    MapPush,
    MapPeek,
    MapPop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ProgramIntrinsicVariant {
    selector: &'static str,
    value: &'static str,
    helper: BpfHelper,
}

impl ProgramIntrinsicVariant {
    pub(crate) const fn new(
        selector: &'static str,
        value: &'static str,
        helper: BpfHelper,
    ) -> Self {
        Self {
            selector,
            value,
            helper,
        }
    }

    pub(crate) fn selector(self) -> &'static str {
        self.selector
    }

    pub(crate) fn value(self) -> &'static str {
        self.value
    }

    pub(crate) fn helper(self) -> BpfHelper {
        self.helper
    }
}

impl ProgramIntrinsic {
    pub fn all() -> &'static [ProgramIntrinsic] {
        PROGRAM_INTRINSICS
    }

    pub fn command_name(&self) -> &'static str {
        match self {
            ProgramIntrinsic::Emit => "emit",
            ProgramIntrinsic::Count => "count",
            ProgramIntrinsic::Histogram => "histogram",
            ProgramIntrinsic::StartTimer => "start-timer",
            ProgramIntrinsic::StopTimer => "stop-timer",
            ProgramIntrinsic::ReadStr => "read-str",
            ProgramIntrinsic::ReadKernelStr => "read-kernel-str",
            ProgramIntrinsic::AdjustPacket => "adjust-packet",
            ProgramIntrinsic::AdjustMessage => "adjust-message",
            ProgramIntrinsic::Redirect => "redirect",
            ProgramIntrinsic::RedirectMap => "redirect-map",
            ProgramIntrinsic::RedirectSocket => "redirect-socket",
            ProgramIntrinsic::AssignSocket => "assign-socket",
            ProgramIntrinsic::HelperCall => "helper-call",
            ProgramIntrinsic::KfuncCall => "kfunc-call",
            ProgramIntrinsic::TailCall => "tail-call",
            ProgramIntrinsic::GlobalDefine => "global-define",
            ProgramIntrinsic::GlobalGet => "global-get",
            ProgramIntrinsic::GlobalSet => "global-set",
            ProgramIntrinsic::MapDefine => "map-define",
            ProgramIntrinsic::MapGet => "map-get",
            ProgramIntrinsic::MapPut => "map-put",
            ProgramIntrinsic::MapDelete => "map-delete",
            ProgramIntrinsic::MapContains => "map-contains",
            ProgramIntrinsic::MapPush => "map-push",
            ProgramIntrinsic::MapPeek => "map-peek",
            ProgramIntrinsic::MapPop => "map-pop",
        }
    }

    pub fn from_command_name(name: &str) -> Option<Self> {
        match name {
            "emit" => Some(ProgramIntrinsic::Emit),
            "count" => Some(ProgramIntrinsic::Count),
            "histogram" => Some(ProgramIntrinsic::Histogram),
            "start-timer" => Some(ProgramIntrinsic::StartTimer),
            "stop-timer" => Some(ProgramIntrinsic::StopTimer),
            "read-str" => Some(ProgramIntrinsic::ReadStr),
            "read-kernel-str" => Some(ProgramIntrinsic::ReadKernelStr),
            "adjust-packet" => Some(ProgramIntrinsic::AdjustPacket),
            "adjust-message" => Some(ProgramIntrinsic::AdjustMessage),
            "redirect" => Some(ProgramIntrinsic::Redirect),
            "redirect-map" => Some(ProgramIntrinsic::RedirectMap),
            "redirect-socket" => Some(ProgramIntrinsic::RedirectSocket),
            "assign-socket" => Some(ProgramIntrinsic::AssignSocket),
            "helper-call" => Some(ProgramIntrinsic::HelperCall),
            "kfunc-call" => Some(ProgramIntrinsic::KfuncCall),
            "tail-call" => Some(ProgramIntrinsic::TailCall),
            "global-define" => Some(ProgramIntrinsic::GlobalDefine),
            "global-get" => Some(ProgramIntrinsic::GlobalGet),
            "global-set" => Some(ProgramIntrinsic::GlobalSet),
            "map-define" => Some(ProgramIntrinsic::MapDefine),
            "map-get" => Some(ProgramIntrinsic::MapGet),
            "map-put" => Some(ProgramIntrinsic::MapPut),
            "map-delete" => Some(ProgramIntrinsic::MapDelete),
            "map-contains" => Some(ProgramIntrinsic::MapContains),
            "map-push" => Some(ProgramIntrinsic::MapPush),
            "map-peek" => Some(ProgramIntrinsic::MapPeek),
            "map-pop" => Some(ProgramIntrinsic::MapPop),
            _ => None,
        }
    }

    pub fn required_capability(&self) -> ProgramCapability {
        match self {
            ProgramIntrinsic::Emit => ProgramCapability::Emit,
            ProgramIntrinsic::Count => ProgramCapability::Counters,
            ProgramIntrinsic::Histogram => ProgramCapability::Histograms,
            ProgramIntrinsic::StartTimer | ProgramIntrinsic::StopTimer => ProgramCapability::Timers,
            ProgramIntrinsic::ReadStr => ProgramCapability::ReadUserString,
            ProgramIntrinsic::ReadKernelStr => ProgramCapability::ReadKernelString,
            ProgramIntrinsic::AdjustPacket
            | ProgramIntrinsic::AdjustMessage
            | ProgramIntrinsic::Redirect
            | ProgramIntrinsic::RedirectMap
            | ProgramIntrinsic::RedirectSocket
            | ProgramIntrinsic::AssignSocket
            | ProgramIntrinsic::HelperCall => ProgramCapability::HelperCalls,
            ProgramIntrinsic::KfuncCall => ProgramCapability::KfuncCalls,
            ProgramIntrinsic::TailCall => ProgramCapability::TailCalls,
            ProgramIntrinsic::GlobalDefine
            | ProgramIntrinsic::GlobalGet
            | ProgramIntrinsic::GlobalSet => ProgramCapability::Globals,
            ProgramIntrinsic::MapGet
            | ProgramIntrinsic::MapDefine
            | ProgramIntrinsic::MapPut
            | ProgramIntrinsic::MapDelete
            | ProgramIntrinsic::MapContains
            | ProgramIntrinsic::MapPush
            | ProgramIntrinsic::MapPeek
            | ProgramIntrinsic::MapPop => ProgramCapability::GenericMaps,
        }
    }

    pub fn command_names() -> Vec<&'static str> {
        Self::all()
            .iter()
            .map(ProgramIntrinsic::command_name)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramCapability {
    Emit,
    Counters,
    Histograms,
    Timers,
    StackTraces,
    ReadUserString,
    ReadKernelString,
    HelperCalls,
    KfuncCalls,
    Globals,
    GenericMaps,
    TailCalls,
}

impl ProgramCapability {
    pub fn all() -> &'static [ProgramCapability] {
        PROGRAM_CAPABILITIES
    }

    pub fn key(&self) -> &'static str {
        match self {
            ProgramCapability::Emit => "emit",
            ProgramCapability::Counters => "counters",
            ProgramCapability::Histograms => "histograms",
            ProgramCapability::Timers => "timers",
            ProgramCapability::StackTraces => "stack-traces",
            ProgramCapability::ReadUserString => "read-user-string",
            ProgramCapability::ReadKernelString => "read-kernel-string",
            ProgramCapability::HelperCalls => "helper-calls",
            ProgramCapability::KfuncCalls => "kfunc-calls",
            ProgramCapability::Globals => "globals",
            ProgramCapability::GenericMaps => "generic-maps",
            ProgramCapability::TailCalls => "tail-calls",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ProgramCapability::Emit => "event emission",
            ProgramCapability::Counters => "counter aggregations",
            ProgramCapability::Histograms => "histogram aggregations",
            ProgramCapability::Timers => "timer aggregations",
            ProgramCapability::StackTraces => "stack trace collection",
            ProgramCapability::ReadUserString => "userspace string reads",
            ProgramCapability::ReadKernelString => "kernel string reads",
            ProgramCapability::HelperCalls => "helper calls",
            ProgramCapability::KfuncCalls => "kfunc calls",
            ProgramCapability::Globals => "program globals",
            ProgramCapability::GenericMaps => "generic map operations",
            ProgramCapability::TailCalls => "tail calls",
        }
    }
}

impl fmt::Display for ProgramCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// One program section within an eBPF ELF object.
#[derive(Debug, Clone)]
pub struct EbpfProgramSection {
    /// Optional explicit ELF section name. When absent, derive from `prog_type` and `target`.
    pub section_name_override: Option<String>,
    /// The program type
    pub prog_type: EbpfProgramType,
    /// The target function/tracepoint name
    pub target: String,
    /// Parsed program model for target-sensitive section naming and attach policy.
    pub program_spec: Option<ProgramSpec>,
    /// The program name (used as symbol name)
    pub name: String,
    /// The raw bytecode
    pub bytecode: Vec<u8>,
    /// Size of the main function in bytes
    pub main_size: usize,
    /// Relocations for symbol references emitted by this program section.
    pub relocations: Vec<SymbolRelocation>,
    /// Subfunction symbols for BPF-to-BPF calls
    pub subfunctions: Vec<SubfunctionSymbol>,
    /// Source-level kfunc names used by this program section when available.
    pub used_kfuncs: HashSet<String>,
    /// Context fields used by this program section when available.
    pub used_ctx_fields: HashSet<CtxField>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
    /// Optional schema for runtime decoding of `bytes_counters` keys
    pub bytes_counter_key_schema: Option<CounterKeySchema>,
    /// Optional typed generic map key schemas keyed by map identity
    pub generic_map_key_types: HashMap<MapRef, MirType>,
    /// Optional generic map capacity declarations keyed by map identity
    pub generic_map_max_entries: HashMap<MapRef, u32>,
    /// Optional typed generic map value schemas keyed by map identity
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    /// Optional logical semantics for generic map values with richer layouts
    pub generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
}

/// A complete eBPF ELF object with shared maps/globals and one or more program sections.
#[derive(Debug, Clone)]
pub struct EbpfObject {
    /// The object kind, which determines how the loader should interpret it.
    pub kind: EbpfObjectKind,
    /// License string (must be GPL-compatible for most helpers)
    pub license: String,
    /// Maps used by this object
    pub maps: Vec<EbpfMap>,
    /// Read-only globals emitted into `.rodata`
    pub readonly_globals: Vec<ReadonlyGlobal>,
    /// Writable initialized globals emitted into `.data`
    pub data_globals: Vec<DataGlobal>,
    /// Writable zero-initialized globals emitted into `.bss`
    pub bss_globals: Vec<BssGlobal>,
    /// Extra object-local data symbols emitted into custom sections.
    pub extra_data_symbols: Vec<ObjectDataSymbol>,
    /// Programs emitted into this object
    pub programs: Vec<EbpfProgramSection>,
}

/// Builder for `struct_ops` ELF objects.
#[derive(Debug, Clone)]
pub struct StructOpsObjectBuilder {
    pub(crate) object: EbpfObject,
    pub(crate) callback_slots: HashMap<String, usize>,
}

/// Named callback slot within a `struct_ops` value blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructOpsCallbackSlot {
    pub name: String,
    pub offset: usize,
}

/// Callback program bound to a named `struct_ops` value slot.
#[derive(Debug, Clone)]
pub struct StructOpsCallbackSpec {
    pub slot_name: String,
    pub callback_name: String,
    pub program: EbpfProgram,
}

/// Already-compiled callback program bound to a named `struct_ops` value slot.
#[derive(Debug, Clone)]
pub struct CompiledStructOpsCallback {
    pub slot_name: String,
    pub callback_name: String,
    pub program: EbpfProgram,
}

pub fn struct_ops_callback_is_sleepable(value_type_name: &str, callback_name: &str) -> bool {
    program_spec_struct_ops_callback_is_sleepable(value_type_name, callback_name)
}

pub fn struct_ops_callback_section_name(
    value_type_name: &str,
    callback_slot_name: &str,
    callback_program_name: &str,
) -> String {
    if struct_ops_callback_is_sleepable(value_type_name, callback_slot_name) {
        format!("struct_ops.s/{callback_program_name}")
    } else {
        format!("struct_ops/{callback_program_name}")
    }
}

/// Constant initializer for a top-level `struct_ops` value field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructOpsValueField {
    Int(i64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    IntList(Vec<i64>),
}

/// Compiler-facing specification for a `struct_ops` object.
#[derive(Debug, Clone)]
pub struct StructOpsObjectSpec {
    pub name: String,
    pub value_type_name: String,
    pub license: String,
    pub value_data: Vec<u8>,
    pub maps: Vec<EbpfMap>,
    pub readonly_globals: Vec<ReadonlyGlobal>,
    pub data_globals: Vec<DataGlobal>,
    pub bss_globals: Vec<BssGlobal>,
    pub callback_slots: Vec<StructOpsCallbackSlot>,
    pub callbacks: Vec<StructOpsCallbackSpec>,
}

/// High-level kind of ELF object being emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EbpfObjectKind {
    /// Ordinary attachable program object with a single primary program.
    Program,
    /// Struct_ops object with callback programs plus registration data.
    StructOps {
        /// User-facing object name.
        name: String,
        /// Kernel BTF value type name, for example `sched_ext_ops`.
        value_type_name: String,
    },
}

/// A complete eBPF program ready for loading
#[derive(Debug, Clone)]
pub struct EbpfProgram {
    /// The program type
    pub prog_type: EbpfProgramType,
    /// The target function/tracepoint name
    pub target: String,
    /// Parsed program model for target-sensitive section naming and attach policy.
    pub program_spec: Option<ProgramSpec>,
    /// The program name (used as symbol name)
    pub name: String,
    /// The raw bytecode
    pub bytecode: Vec<u8>,
    /// Size of the main function in bytes
    pub main_size: usize,
    /// License string (must be GPL-compatible for most helpers)
    pub license: String,
    /// Maps used by this program
    pub maps: Vec<EbpfMap>,
    /// Read-only globals emitted into `.rodata`
    pub readonly_globals: Vec<ReadonlyGlobal>,
    /// Writable initialized globals emitted into `.data`
    pub data_globals: Vec<DataGlobal>,
    /// Writable zero-initialized globals emitted into `.bss`
    pub bss_globals: Vec<BssGlobal>,
    /// Relocations for symbol references emitted by this program.
    pub relocations: Vec<SymbolRelocation>,
    /// Subfunction symbols for BPF-to-BPF calls
    pub subfunctions: Vec<SubfunctionSymbol>,
    /// Source-level kfunc names used by this program when available.
    pub used_kfuncs: HashSet<String>,
    /// Context fields used by this program when available.
    pub used_ctx_fields: HashSet<CtxField>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
    /// Optional schema for runtime decoding of `bytes_counters` keys
    pub bytes_counter_key_schema: Option<CounterKeySchema>,
    /// Optional typed generic map key schemas keyed by map identity
    pub generic_map_key_types: HashMap<MapRef, MirType>,
    /// Optional generic map capacity declarations keyed by map identity
    pub generic_map_max_entries: HashMap<MapRef, u32>,
    /// Optional typed generic map value schemas keyed by map identity
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    /// Optional logical semantics for generic map values with richer layouts
    pub generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
}

#[cfg(test)]
mod tests;
