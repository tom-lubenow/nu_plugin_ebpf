//! Mid-Level Intermediate Representation (MIR) for eBPF compilation
//!
//! MIR sits between Nushell IR and eBPF bytecode, providing:
//! - Virtual registers (unlimited, unlike eBPF's 10)
//! - Explicit basic blocks with terminators
//! - Type information for verification
//! - A target for optimization passes

use std::collections::{HashMap, HashSet};
use std::fmt;

mod ctx_field_compat;
mod function_impl;
mod inst_impl;
mod map_compat;

pub use ctx_field_compat::ContextFieldCompatibilityRequirement;
pub use map_compat::{MapCompatibilityRequirement, MapValueCompatibilityRequirement};

/// Virtual register ID - unlimited, will be allocated to physical registers later
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VReg(pub u32);

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Basic block identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Stack slot identifier for explicit stack allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackSlotId(pub u32);

/// Subfunction identifier for BPF-to-BPF calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubfunctionId(pub u32);

impl fmt::Display for SubfunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subfn{}", self.0)
    }
}

/// Map reference for BPF map operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MapRef {
    pub name: String,
    pub kind: MapKind,
}

/// Types of BPF maps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapKind {
    Hash,
    Array,
    CgroupArray,
    LpmTrie,
    LruHash,
    PerCpuHash,
    PerCpuArray,
    LruPerCpuHash,
    PerfEventArray,
    ArrayOfMaps,
    HashOfMaps,
    DeprecatedCgroupStorage,
    DeprecatedPerCpuCgroupStorage,
    Queue,
    Stack,
    BloomFilter,
    RingBuf,
    StructOps,
    UserRingBuf,
    Arena,
    StackTrace,
    DevMap,
    DevMapHash,
    CpuMap,
    XskMap,
    SockMap,
    SockHash,
    ReuseportSockArray,
    SkStorage,
    InodeStorage,
    TaskStorage,
    CgrpStorage,
    ProgArray,
}

const ALL_MAP_KINDS: &[MapKind] = &[
    MapKind::Hash,
    MapKind::Array,
    MapKind::CgroupArray,
    MapKind::LpmTrie,
    MapKind::LruHash,
    MapKind::PerCpuHash,
    MapKind::PerCpuArray,
    MapKind::LruPerCpuHash,
    MapKind::PerfEventArray,
    MapKind::ArrayOfMaps,
    MapKind::HashOfMaps,
    MapKind::DeprecatedCgroupStorage,
    MapKind::DeprecatedPerCpuCgroupStorage,
    MapKind::Queue,
    MapKind::Stack,
    MapKind::BloomFilter,
    MapKind::RingBuf,
    MapKind::StructOps,
    MapKind::UserRingBuf,
    MapKind::Arena,
    MapKind::StackTrace,
    MapKind::DevMap,
    MapKind::DevMapHash,
    MapKind::CpuMap,
    MapKind::XskMap,
    MapKind::SockMap,
    MapKind::SockHash,
    MapKind::ReuseportSockArray,
    MapKind::SkStorage,
    MapKind::InodeStorage,
    MapKind::TaskStorage,
    MapKind::CgrpStorage,
    MapKind::ProgArray,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapOpKind {
    Lookup,
    Update,
    Delete,
    Push,
}

impl MapKind {
    pub fn all() -> &'static [Self] {
        ALL_MAP_KINDS
    }

    pub fn key(self) -> &'static str {
        match self {
            MapKind::Hash => "hash",
            MapKind::Array => "array",
            MapKind::CgroupArray => "cgroup-array",
            MapKind::LpmTrie => "lpm-trie",
            MapKind::LruHash => "lru-hash",
            MapKind::PerCpuHash => "per-cpu-hash",
            MapKind::PerCpuArray => "per-cpu-array",
            MapKind::LruPerCpuHash => "lru-per-cpu-hash",
            MapKind::PerfEventArray => "perf-event-array",
            MapKind::ArrayOfMaps => "array-of-maps",
            MapKind::HashOfMaps => "hash-of-maps",
            MapKind::DeprecatedCgroupStorage => "deprecated-cgroup-storage",
            MapKind::DeprecatedPerCpuCgroupStorage => "per-cpu-cgroup-storage",
            MapKind::Queue => "queue",
            MapKind::Stack => "stack",
            MapKind::BloomFilter => "bloom-filter",
            MapKind::RingBuf => "ringbuf",
            MapKind::StructOps => "struct-ops",
            MapKind::UserRingBuf => "user-ringbuf",
            MapKind::Arena => "arena",
            MapKind::StackTrace => "stack-trace",
            MapKind::DevMap => "devmap",
            MapKind::DevMapHash => "devmap-hash",
            MapKind::CpuMap => "cpumap",
            MapKind::XskMap => "xskmap",
            MapKind::SockMap => "sockmap",
            MapKind::SockHash => "sockhash",
            MapKind::ReuseportSockArray => "reuseport-sockarray",
            MapKind::SkStorage => "sk-storage",
            MapKind::InodeStorage => "inode-storage",
            MapKind::TaskStorage => "task-storage",
            MapKind::CgrpStorage => "cgrp-storage",
            MapKind::ProgArray => "prog-array",
        }
    }

    pub fn aliases(self) -> &'static [&'static str] {
        match self {
            MapKind::Hash => &["hash"],
            MapKind::Array => &["array"],
            MapKind::CgroupArray => &["cgroup-array", "cgroup_array", "cgrouparray"],
            MapKind::LpmTrie => &["lpm-trie", "lpm_trie", "lpmtrie"],
            MapKind::LruHash => &["lru-hash", "lru_hash", "lruhash"],
            MapKind::PerCpuHash => &["per-cpu-hash", "percpu-hash", "per_cpu_hash"],
            MapKind::PerCpuArray => &["per-cpu-array", "percpu-array", "per_cpu_array"],
            MapKind::LruPerCpuHash => &[
                "lru-per-cpu-hash",
                "lru-percpu-hash",
                "lru_per_cpu_hash",
                "lrupercpuhash",
            ],
            MapKind::PerfEventArray => &[
                "perf-event-array",
                "perf_event_array",
                "perfeventarray",
                "perf-event",
                "perf_event",
            ],
            MapKind::ArrayOfMaps => &[
                "array-of-maps",
                "array_of_maps",
                "arrayofmaps",
                "map-array",
                "map_array",
            ],
            MapKind::HashOfMaps => &[
                "hash-of-maps",
                "hash_of_maps",
                "hashofmaps",
                "map-hash",
                "map_hash",
            ],
            MapKind::DeprecatedCgroupStorage => &[
                "deprecated-cgroup-storage",
                "deprecated_cgroup_storage",
                "cgroup-storage-deprecated",
                "cgroup_storage_deprecated",
            ],
            MapKind::DeprecatedPerCpuCgroupStorage => &[
                "per-cpu-cgroup-storage",
                "percpu-cgroup-storage",
                "per_cpu_cgroup_storage",
                "percpucgroupstorage",
            ],
            MapKind::Queue => &["queue"],
            MapKind::Stack => &["stack"],
            MapKind::BloomFilter => &["bloom-filter", "bloom_filter", "bloomfilter"],
            MapKind::RingBuf => &[
                "ringbuf",
                "ring-buf",
                "ring_buf",
                "ring-buffer",
                "ring_buffer",
            ],
            MapKind::StructOps => &["struct-ops", "struct_ops", "structops"],
            MapKind::UserRingBuf => &[
                "user-ringbuf",
                "user_ringbuf",
                "userringbuf",
                "user-ring-buffer",
                "user_ring_buffer",
            ],
            MapKind::Arena => &["arena"],
            MapKind::StackTrace => &["stack-trace", "stack_trace", "stacktrace"],
            MapKind::DevMap => &["devmap", "dev-map", "dev_map"],
            MapKind::DevMapHash => &[
                "devmap-hash",
                "devmap_hash",
                "devmaphash",
                "dev-map-hash",
                "dev_map_hash",
            ],
            MapKind::CpuMap => &["cpumap", "cpu-map", "cpu_map"],
            MapKind::XskMap => &["xskmap", "xsk-map", "xsk_map"],
            MapKind::SockMap => &["sockmap", "sock-map", "sock_map"],
            MapKind::SockHash => &["sockhash", "sock-hash", "sock_hash"],
            MapKind::ReuseportSockArray => &[
                "reuseport-sockarray",
                "reuseport_sockarray",
                "reuseportsockarray",
                "reuseport-sock-array",
                "reuseport_sock_array",
            ],
            MapKind::SkStorage => &["sk-storage", "sk_storage", "skstorage"],
            MapKind::InodeStorage => &["inode-storage", "inode_storage", "inodestorage"],
            MapKind::TaskStorage => &["task-storage", "task_storage", "taskstorage"],
            MapKind::CgrpStorage => &[
                "cgrp-storage",
                "cgrp_storage",
                "cgrpstorage",
                "cgroup-storage",
                "cgroup_storage",
                "cgroupstorage",
            ],
            MapKind::ProgArray => &[
                "prog-array",
                "prog_array",
                "progarray",
                "program-array",
                "program_array",
                "programarray",
            ],
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|kind| kind.aliases().contains(&name))
    }

    pub fn is_queue_or_stack(self) -> bool {
        matches!(self, MapKind::Queue | MapKind::Stack)
    }

    pub fn is_socket_map(self) -> bool {
        matches!(self, MapKind::SockMap | MapKind::SockHash)
    }

    pub fn is_local_storage(self) -> bool {
        matches!(
            self,
            MapKind::SkStorage
                | MapKind::InodeStorage
                | MapKind::TaskStorage
                | MapKind::CgrpStorage
        )
    }

    pub fn is_redirect_map(self) -> bool {
        matches!(
            self,
            MapKind::DevMap | MapKind::DevMapHash | MapKind::CpuMap | MapKind::XskMap
        )
    }

    pub fn supports_builtin_counter_map(self) -> bool {
        matches!(self, MapKind::Hash | MapKind::PerCpuHash)
    }

    pub fn is_array_index_map(self) -> bool {
        matches!(self, MapKind::Array | MapKind::PerCpuArray)
    }

    pub fn is_keyless_map(self) -> bool {
        matches!(
            self,
            MapKind::Queue
                | MapKind::Stack
                | MapKind::BloomFilter
                | MapKind::RingBuf
                | MapKind::UserRingBuf
        )
    }

    pub fn supports_map_fd_materialization(self) -> bool {
        !matches!(
            self,
            MapKind::ArrayOfMaps
                | MapKind::HashOfMaps
                | MapKind::DeprecatedCgroupStorage
                | MapKind::DeprecatedPerCpuCgroupStorage
                | MapKind::StructOps
                | MapKind::Arena
        )
    }

    pub fn map_fd_materialization_error(self, map_name: &str) -> String {
        match self {
            MapKind::ArrayOfMaps | MapKind::HashOfMaps => format!(
                "map '{}' uses {}, which requires inner-map metadata not modeled by this compiler yet",
                map_name, self
            ),
            MapKind::DeprecatedCgroupStorage | MapKind::DeprecatedPerCpuCgroupStorage => format!(
                "map '{}' uses deprecated {}; use cgrp-storage local-storage maps instead",
                map_name, self
            ),
            MapKind::StructOps => format!(
                "map '{}' uses struct-ops; struct_ops maps are emitted through struct_ops object support, not generic map materialization",
                map_name
            ),
            MapKind::Arena => format!(
                "map '{}' uses arena, but arena map_extra/mmap support is not modeled yet",
                map_name
            ),
            _ => format!("map '{}' uses unsupported map kind {}", map_name, self),
        }
    }

    pub fn supports_any_generic_map_op(self) -> bool {
        matches!(
            self,
            MapKind::Hash
                | MapKind::Array
                | MapKind::LpmTrie
                | MapKind::LruHash
                | MapKind::PerCpuHash
                | MapKind::PerCpuArray
                | MapKind::LruPerCpuHash
                | MapKind::Queue
                | MapKind::Stack
                | MapKind::BloomFilter
        )
    }

    pub fn supports_generic_map_op(self, op: MapOpKind) -> bool {
        match op {
            MapOpKind::Lookup | MapOpKind::Update => matches!(
                self,
                MapKind::Hash
                    | MapKind::Array
                    | MapKind::LpmTrie
                    | MapKind::LruHash
                    | MapKind::PerCpuHash
                    | MapKind::PerCpuArray
                    | MapKind::LruPerCpuHash
            ),
            MapOpKind::Delete => matches!(
                self,
                MapKind::Hash
                    | MapKind::LpmTrie
                    | MapKind::LruHash
                    | MapKind::PerCpuHash
                    | MapKind::LruPerCpuHash
            ),
            MapOpKind::Push => {
                matches!(self, MapKind::Queue | MapKind::Stack | MapKind::BloomFilter)
            }
        }
    }

    pub fn generic_map_op_error(self, op: MapOpKind, map_name: &str) -> String {
        if !self.supports_any_generic_map_op() {
            return format!(
                "map operations do not support map kind {} for '{}'",
                self, map_name
            );
        }

        match (op, self) {
            (MapOpKind::Lookup, MapKind::BloomFilter) => {
                format!("map lookup is not supported for bloom-filter map '{map_name}'")
            }
            (MapOpKind::Update, MapKind::BloomFilter) => {
                format!(
                    "map update is not supported for bloom-filter map '{map_name}'; use map-push"
                )
            }
            (MapOpKind::Delete, MapKind::BloomFilter) => {
                format!("map delete is not supported for bloom-filter map '{map_name}'")
            }
            (MapOpKind::Delete, MapKind::Array | MapKind::PerCpuArray) => format!(
                "map delete is not supported for array map kind {} ('{}')",
                self, map_name
            ),
            (MapOpKind::Push, _) => format!(
                "map-push requires queue, stack, or bloom-filter map kind, got {} for '{}'",
                self, map_name
            ),
            (MapOpKind::Lookup, _) => format!(
                "map lookup is not supported for map kind {} ('{}')",
                self, map_name
            ),
            (MapOpKind::Update, _) => format!(
                "map update is not supported for map kind {} ('{}')",
                self, map_name
            ),
            (MapOpKind::Delete, _) => format!(
                "map delete is not supported for map kind {} ('{}')",
                self, map_name
            ),
        }
    }
}

impl fmt::Display for MapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

pub const RINGBUF_MAP_NAME: &str = "events";
pub const COUNTER_MAP_NAME: &str = "counters";
pub const STRING_COUNTER_MAP_NAME: &str = "str_counters";
pub const BYTES_COUNTER_MAP_NAME: &str = "bytes_counters";
pub const HISTOGRAM_MAP_NAME: &str = "histogram";
pub const TIMESTAMP_MAP_NAME: &str = "timestamps";
pub const KSTACK_MAP_NAME: &str = "kstacks";
pub const USTACK_MAP_NAME: &str = "ustacks";
const BPF_KPTR_SLOT_STRUCT_PREFIX: &str = "__nu_bpf_kptr_";
const BPF_GRAPH_ROOT_STRUCT_PREFIX: &str = "__nu_bpf_graph_root:";

/// Verifier-managed graph root kind embedded in a BPF map value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfGraphRootKind {
    ListHead,
    RbRoot,
}

impl BpfGraphRootKind {
    pub fn root_struct_name(self) -> &'static str {
        match self {
            Self::ListHead => "bpf_list_head",
            Self::RbRoot => "bpf_rb_root",
        }
    }

    pub fn node_struct_name(self) -> &'static str {
        match self {
            Self::ListHead => "bpf_list_node",
            Self::RbRoot => "bpf_rb_node",
        }
    }

    pub fn root_size(self) -> usize {
        16
    }

    pub fn node_size(self) -> usize {
        match self {
            Self::ListHead => 16,
            Self::RbRoot => 24,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::ListHead => "list_head",
            Self::RbRoot => "rb_root",
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        match key {
            "list_head" => Some(Self::ListHead),
            "rb_root" => Some(Self::RbRoot),
            _ => None,
        }
    }
}

/// `contains:TYPE:FIELD` metadata for a graph root map-value field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfGraphRootInfo<'a> {
    pub kind: BpfGraphRootKind,
    pub value_type: &'a str,
    pub node_field: &'a str,
}

/// Bitfield extraction metadata for a logical struct field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitfieldInfo {
    pub bit_offset: u32,
    pub bit_size: u32,
}

/// Type of value being appended in StringAppend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringAppendType {
    /// Append a literal string (bytes embedded in MIR)
    Literal { bytes: Vec<u8> },
    /// Append from a string slot on the stack
    StringSlot { slot: StackSlotId, max_len: usize },
    /// Append an integer converted to decimal
    Integer,
}

/// MIR type system - internal, inferred from context
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MirType {
    // Primitives
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Bool,

    // Pointers with address space (for verifier)
    Ptr {
        pointee: Box<MirType>,
        address_space: AddressSpace,
    },

    // Fixed-size array
    Array {
        elem: Box<MirType>,
        len: usize,
    },

    // Struct with named fields
    Struct {
        name: Option<String>,
        kernel_btf_type_id: Option<u32>,
        fields: Vec<StructField>,
    },

    // BPF-specific
    MapRef {
        key_ty: Box<MirType>,
        val_ty: Box<MirType>,
    },

    // Reference to a local BPF subprogram used as a helper callback target
    Subprogram {
        args: Vec<MirType>,
        ret: Box<MirType>,
    },

    // Unknown type (before inference)
    Unknown,
}

impl MirType {
    /// Size in bytes
    pub fn size(&self) -> usize {
        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 => 8,
            MirType::Ptr { .. } => 8,
            MirType::Array { elem, len } => elem.size() * len,
            MirType::Struct { fields, .. } => fields
                .iter()
                .filter_map(|field| field.offset.checked_add(field.ty.size()))
                .max()
                .unwrap_or(0),
            MirType::MapRef { .. } => 8, // Map FD
            MirType::Subprogram { .. } => 8,
            MirType::Unknown => 8, // Default to 64-bit
        }
    }

    /// Length for a fixed-size byte array (`[i8; N]` or `[u8; N]`).
    pub fn byte_array_len(&self) -> Option<usize> {
        match self {
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::I8 | MirType::U8) => {
                Some(*len)
            }
            _ => None,
        }
    }

    pub fn is_raw_kernel_u8_ptr(&self) -> bool {
        matches!(
            self,
            MirType::Ptr {
                address_space: AddressSpace::Kernel,
                pointee,
            } if matches!(pointee.as_ref(), MirType::U8)
        )
    }

    pub fn opaque_named_struct(name: &str) -> Self {
        Self::opaque_named_struct_with_size(name, 1)
    }

    pub fn opaque_named_struct_with_size(name: &str, size: usize) -> Self {
        MirType::Struct {
            name: Some(name.to_string()),
            kernel_btf_type_id: None,
            fields: vec![StructField {
                name: "__opaque".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: size.max(1),
                },
                offset: 0,
                synthetic: false,
                bitfield: None,
            }],
        }
    }

    pub fn bpf_timer_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_timer", 16)
    }

    pub fn bpf_spin_lock_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_spin_lock", 4)
    }

    pub fn bpf_wq_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_wq", 16)
    }

    pub fn bpf_refcount_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_refcount", 4)
    }

    pub fn bpf_dynptr_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_dynptr", 16)
    }

    pub fn bpf_list_head_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_list_head", 16)
    }

    pub fn bpf_list_node_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_list_node", 16)
    }

    pub fn bpf_rb_root_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_rb_root", 16)
    }

    pub fn bpf_rb_node_struct() -> Self {
        Self::opaque_named_struct_with_size("bpf_rb_node", 24)
    }

    pub fn bpf_list_head_root_struct(value_type: &str, node_field: &str) -> Self {
        Self::bpf_graph_root_struct(BpfGraphRootKind::ListHead, value_type, node_field)
    }

    pub fn bpf_rb_root_struct_with_contains(value_type: &str, node_field: &str) -> Self {
        Self::bpf_graph_root_struct(BpfGraphRootKind::RbRoot, value_type, node_field)
    }

    fn bpf_graph_root_struct(kind: BpfGraphRootKind, value_type: &str, node_field: &str) -> Self {
        Self::opaque_named_struct_with_size(
            &format!(
                "{BPF_GRAPH_ROOT_STRUCT_PREFIX}{}:{value_type}:{node_field}",
                kind.key()
            ),
            kind.root_size(),
        )
    }

    pub fn bpf_kptr_slot_struct(pointee_name: &str) -> Self {
        Self::opaque_named_struct_with_size(
            &format!("{BPF_KPTR_SLOT_STRUCT_PREFIX}{pointee_name}"),
            8,
        )
    }

    pub fn is_bpf_timer_struct(&self) -> bool {
        self.has_struct_name(&["bpf_timer"])
    }

    pub fn is_bpf_spin_lock_struct(&self) -> bool {
        self.has_struct_name(&["bpf_spin_lock"])
    }

    pub fn is_bpf_wq_struct(&self) -> bool {
        self.has_struct_name(&["bpf_wq"])
    }

    pub fn is_bpf_refcount_struct(&self) -> bool {
        self.has_struct_name(&["bpf_refcount"])
    }

    pub fn is_bpf_dynptr_struct(&self) -> bool {
        self.has_struct_name(&["bpf_dynptr", "bpf_dynptr_kern"])
    }

    pub fn is_bpf_list_head_struct(&self) -> bool {
        self.has_struct_name(&["bpf_list_head"])
            || self
                .bpf_graph_root_info()
                .is_some_and(|root| root.kind == BpfGraphRootKind::ListHead)
    }

    pub fn is_bpf_list_node_struct(&self) -> bool {
        self.has_struct_name(&["bpf_list_node"])
    }

    pub fn is_bpf_rb_root_struct(&self) -> bool {
        self.has_struct_name(&["bpf_rb_root"])
            || self
                .bpf_graph_root_info()
                .is_some_and(|root| root.kind == BpfGraphRootKind::RbRoot)
    }

    pub fn is_bpf_rb_node_struct(&self) -> bool {
        self.has_struct_name(&["bpf_rb_node"])
    }

    pub fn field_type_at_offset(&self, offset: usize) -> Option<&MirType> {
        let MirType::Struct { fields, .. } = self else {
            return None;
        };
        fields
            .iter()
            .find(|field| !field.synthetic && field.offset == offset)
            .map(|field| &field.ty)
    }

    pub fn bpf_graph_root_info(&self) -> Option<BpfGraphRootInfo<'_>> {
        let MirType::Struct {
            name: Some(name), ..
        } = self
        else {
            return None;
        };
        let rest = name.strip_prefix(BPF_GRAPH_ROOT_STRUCT_PREFIX)?;
        let mut parts = rest.splitn(3, ':');
        let kind = BpfGraphRootKind::from_key(parts.next()?)?;
        let value_type = parts.next()?;
        let node_field = parts.next()?;
        if value_type.is_empty() || node_field.is_empty() {
            return None;
        }
        Some(BpfGraphRootInfo {
            kind,
            value_type,
            node_field,
        })
    }

    pub fn bpf_kptr_pointee_name(&self) -> Option<&str> {
        let MirType::Struct {
            name: Some(name),
            fields,
            ..
        } = self
        else {
            return None;
        };
        if self.size() != 8 {
            return None;
        }
        if fields.len() != 1 || fields[0].name != "__opaque" {
            return None;
        }
        name.strip_prefix(BPF_KPTR_SLOT_STRUCT_PREFIX)
    }

    pub fn is_bpf_kptr_slot_struct(&self) -> bool {
        self.bpf_kptr_pointee_name().is_some()
    }

    pub fn map_pointer_kptr_slot_pointee_name(&self) -> Option<&str> {
        let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        } = self
        else {
            return None;
        };
        pointee.bpf_kptr_pointee_name().or_else(|| {
            let MirType::Struct { fields, .. } = pointee.as_ref() else {
                return None;
            };
            fields
                .iter()
                .find(|field| !field.synthetic && field.offset == 0)
                .and_then(|field| field.ty.bpf_kptr_pointee_name())
        })
    }

    pub fn kernel_struct_ptr_pointee_name(&self) -> Option<&str> {
        let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Kernel,
        } = self
        else {
            return None;
        };
        let MirType::Struct {
            name: Some(name), ..
        } = pointee.as_ref()
        else {
            return None;
        };
        Some(name)
    }

    pub fn named_kernel_struct_ptr(name: &str) -> Self {
        MirType::Ptr {
            pointee: Box::new(Self::opaque_named_struct(name)),
            address_space: AddressSpace::Kernel,
        }
    }

    pub fn is_scalar_like(&self) -> bool {
        matches!(
            self,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
        )
    }

    pub fn is_ptr_in(&self, address_space: AddressSpace) -> bool {
        matches!(self, MirType::Ptr { address_space: space, .. } if *space == address_space)
    }

    pub fn is_stack_ptr(&self) -> bool {
        self.is_ptr_in(AddressSpace::Stack)
    }

    pub fn is_map_ptr(&self) -> bool {
        self.is_ptr_in(AddressSpace::Map)
    }

    pub fn is_kernel_ptr(&self) -> bool {
        self.is_ptr_in(AddressSpace::Kernel)
    }

    pub fn is_task_struct_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["task_struct"])
    }

    pub fn is_vm_area_struct_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["vm_area_struct"])
    }

    pub fn is_file_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["file"])
    }

    pub fn is_inode_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["inode"])
    }

    pub fn is_cgroup_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["cgroup"])
    }

    pub fn is_socket_ptr(&self) -> bool {
        matches!(
            self,
            MirType::Ptr {
                address_space: AddressSpace::Kernel,
                pointee,
            } if pointee.is_socket_cookie_socket_pointee()
        )
    }

    pub fn is_socket_cookie_socket_ptr(&self) -> bool {
        self.is_socket_ptr()
    }

    pub fn is_dynptr_stack_ptr(&self) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Stack,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.is_bpf_dynptr_struct()
    }

    pub fn is_bpf_timer_map_ptr(&self) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Map,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(&["bpf_timer"]) || pointee.has_zero_offset_bpf_timer_field()
    }

    pub fn is_bpf_spin_lock_map_ptr(&self) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Map,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(&["bpf_spin_lock"]) || pointee.has_zero_offset_bpf_spin_lock_field()
    }

    pub fn is_bpf_wq_map_ptr(&self) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Map,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(&["bpf_wq"]) || pointee.has_zero_offset_bpf_wq_field()
    }

    pub fn is_bpf_refcount_map_ptr(&self) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Map,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(&["bpf_refcount"]) || pointee.has_zero_offset_bpf_refcount_field()
    }

    fn is_named_kernel_struct_ptr(&self, candidates: &[&str]) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Kernel,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(candidates)
    }

    fn has_struct_name(&self, candidates: &[&str]) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = self
        else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        candidates
            .iter()
            .any(|candidate| lower == candidate.to_ascii_lowercase())
    }

    fn has_zero_offset_bpf_timer_field(&self) -> bool {
        let MirType::Struct { fields, .. } = self else {
            return false;
        };
        fields
            .iter()
            .any(|field| field.offset == 0 && field.ty.has_struct_name(&["bpf_timer"]))
    }

    fn has_zero_offset_bpf_spin_lock_field(&self) -> bool {
        let MirType::Struct { fields, .. } = self else {
            return false;
        };
        fields
            .iter()
            .any(|field| field.offset == 0 && field.ty.has_struct_name(&["bpf_spin_lock"]))
    }

    fn has_zero_offset_bpf_wq_field(&self) -> bool {
        let MirType::Struct { fields, .. } = self else {
            return false;
        };
        fields
            .iter()
            .any(|field| field.offset == 0 && field.ty.has_struct_name(&["bpf_wq"]))
    }

    fn has_zero_offset_bpf_refcount_field(&self) -> bool {
        let MirType::Struct { fields, .. } = self else {
            return false;
        };
        fields
            .iter()
            .any(|field| field.offset == 0 && field.ty.has_struct_name(&["bpf_refcount"]))
    }

    fn is_socket_cookie_socket_pointee(&self) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = self
        else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        lower == "sock"
            || lower == "sock_common"
            || lower == "bpf_sock"
            || lower.starts_with("sock_")
            || lower.ends_with("_sock")
            || lower.contains("_sock_")
    }

    /// Inclusive scalar value bounds when they fit in the analysis range model.
    pub fn scalar_value_range(&self) -> Option<(i64, i64)> {
        match self {
            MirType::Bool => Some((0, 1)),
            MirType::I8 => Some((i8::MIN as i64, i8::MAX as i64)),
            MirType::I16 => Some((i16::MIN as i64, i16::MAX as i64)),
            MirType::I32 => Some((i32::MIN as i64, i32::MAX as i64)),
            MirType::I64 => Some((i64::MIN, i64::MAX)),
            MirType::U8 => Some((0, u8::MAX as i64)),
            MirType::U16 => Some((0, u16::MAX as i64)),
            MirType::U32 => Some((0, u32::MAX as i64)),
            MirType::U64 => None,
            _ => None,
        }
    }

    /// Return the backing kernel BTF type id for struct layouts when known.
    pub fn kernel_btf_type_id(&self) -> Option<u32> {
        match self {
            MirType::Struct {
                kernel_btf_type_id, ..
            } => *kernel_btf_type_id,
            _ => None,
        }
    }

    /// Alignment in bytes
    pub fn align(&self) -> usize {
        if self.is_bpf_timer_struct() {
            return 8;
        }
        if self.is_bpf_spin_lock_struct() {
            return 4;
        }
        if self.is_bpf_wq_struct() {
            return 8;
        }
        if self.is_bpf_refcount_struct() {
            return 4;
        }
        if self.is_bpf_dynptr_struct() {
            return 8;
        }
        if self.is_bpf_list_head_struct()
            || self.is_bpf_list_node_struct()
            || self.is_bpf_rb_root_struct()
            || self.is_bpf_rb_node_struct()
        {
            return 8;
        }
        if self.is_bpf_kptr_slot_struct() {
            return 8;
        }

        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 | MirType::Ptr { .. } => 8,
            MirType::Array { elem, .. } => elem.align(),
            MirType::Struct { fields, .. } => {
                fields.iter().map(|f| f.ty.align()).max().unwrap_or(1)
            }
            MirType::MapRef { .. } => 8,
            MirType::Subprogram { .. } => 8,
            MirType::Unknown => 8,
        }
    }
}

/// Address space for pointer provenance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressSpace {
    /// Stack-relative (R10 + offset), always valid
    Stack,
    /// Kernel memory, requires bpf_probe_read_kernel
    Kernel,
    /// User memory, requires bpf_probe_read_user
    User,
    /// XDP packet data pointer, direct-accessible after a data_end bounds check
    Packet,
    /// Trusted context-owned subobject pointer with direct loads but no map-value semantics
    Context,
    /// Map value pointer (trusted after null check)
    Map,
}

/// Field in a struct type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructField {
    pub name: String,
    pub ty: MirType,
    pub offset: usize,
    pub synthetic: bool,
    pub bitfield: Option<BitfieldInfo>,
}

/// A field in a record being emitted
#[derive(Debug, Clone)]
pub struct RecordFieldDef {
    /// Field name
    pub name: String,
    /// Virtual register holding the value
    pub value: VReg,
    /// Type of the field
    pub ty: MirType,
}

/// Stack slot for explicit stack allocation
#[derive(Debug, Clone)]
pub struct StackSlot {
    pub id: StackSlotId,
    pub size: usize,
    pub align: usize,
    pub kind: StackSlotKind,
    /// Assigned offset from R10 (negative), filled in during layout
    pub offset: Option<i16>,
}

/// Purpose of a stack slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackSlotKind {
    /// Register spill
    Spill,
    /// Local variable
    Local,
    /// Outgoing call argument
    Argument,
    /// Event buffer for ring buffer output
    EventBuffer,
    /// String comparison buffer
    StringBuffer,
    /// Record field storage
    RecordField,
    /// List buffer storage (length + elements)
    ListBuffer,
}

/// Value that can be used as an operand
#[derive(Debug, Clone, PartialEq)]
pub enum MirValue {
    /// Virtual register
    VReg(VReg),
    /// Compile-time constant
    Const(i64),
    /// Stack slot reference
    StackSlot(StackSlotId),
}

impl fmt::Display for MirValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirValue::VReg(v) => write!(f, "{}", v),
            MirValue::Const(c) => write!(f, "{}", c),
            MirValue::StackSlot(s) => write!(f, "slot{}", s.0),
        }
    }
}

impl MirValue {
    /// Visit virtual registers referenced by this value.
    pub fn visit_vregs_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut VReg),
    {
        if let MirValue::VReg(vreg) = self {
            f(vreg);
        }
    }

    /// Return a copy of this value with all referenced virtual registers rewritten.
    pub fn map_vregs<F>(&self, mut map: F) -> MirValue
    where
        F: FnMut(VReg) -> VReg,
    {
        let mut cloned = self.clone();
        cloned.visit_vregs_mut(|vreg| *vreg = map(*vreg));
        cloned
    }
}

/// Binary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    And,
    Or,
    Xor,
    Shl,
    Shr,

    // Comparison (result is 0 or 1)
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOpKind::Add => "+",
            BinOpKind::Sub => "-",
            BinOpKind::Mul => "*",
            BinOpKind::Div => "/",
            BinOpKind::Mod => "%",
            BinOpKind::And => "&",
            BinOpKind::Or => "|",
            BinOpKind::Xor => "^",
            BinOpKind::Shl => "<<",
            BinOpKind::Shr => ">>",
            BinOpKind::Eq => "==",
            BinOpKind::Ne => "!=",
            BinOpKind::Lt => "<",
            BinOpKind::Le => "<=",
            BinOpKind::Gt => ">",
            BinOpKind::Ge => ">=",
        };
        write!(f, "{}", s)
    }
}

/// Unary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    /// Logical not (0 -> 1, non-zero -> 0)
    Not,
    /// Bitwise negation
    BitNot,
    /// Arithmetic negation
    Neg,
}

/// Context field access
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CtxField {
    /// Raw program context pointer
    Context,
    /// Kernel PID / thread ID (low 32 bits of bpf_get_current_pid_tgid)
    Pid,
    /// Thread-group ID / userspace process ID (high 32 bits of bpf_get_current_pid_tgid)
    Tgid,
    /// Packed `(tgid << 32) | pid` value from bpf_get_current_pid_tgid
    PidTgid,
    /// User ID
    Uid,
    /// Group ID
    Gid,
    /// Packed `(gid << 32) | uid` value from bpf_get_current_uid_gid
    UidGid,
    /// Process name (comm)
    Comm,
    /// Current task_struct pointer
    Task,
    /// Current element task_struct pointer on iter:task programs
    IterTask,
    /// BPF iterator metadata pointer
    IterMeta,
    /// Current task_file iterator file descriptor
    IterFd,
    /// Current task_file iterator file pointer
    IterFile,
    /// Current task_vma iterator VMA pointer
    IterVma,
    /// Current cgroup iterator cgroup pointer
    IterCgroup,
    /// Current BPF map iterator map pointer
    IterMap,
    /// Current BPF map-element iterator key pointer
    IterMapKey,
    /// Current BPF map-element iterator value pointer
    IterMapValue,
    /// Current BPF program iterator program pointer
    IterProg,
    /// Current BPF link iterator link pointer
    IterLink,
    /// Current TCP iterator sock_common pointer
    IterSkCommon,
    /// Current UDP iterator udp_sock pointer
    IterUdpSk,
    /// Current UNIX iterator unix_sock pointer
    IterUnixSk,
    /// Current socket iterator owner uid
    IterUid,
    /// Current UDP iterator hash bucket
    IterBucket,
    /// Current DMA-BUF iterator dma_buf pointer
    IterDmabuf,
    /// Current IPv6 route iterator fib6_info pointer
    IterIpv6Route,
    /// Current kmem_cache iterator kmem_cache pointer
    IterKmemCache,
    /// Current ksymbol iterator kallsym_iter pointer
    IterKsym,
    /// Current netlink iterator netlink_sock pointer
    IterNetlinkSk,
    /// Current socket pointer on sockmap/socket-storage iterators
    IterSock,
    /// Current task default cgroup pointer
    Cgroup,
    /// CPU ID
    Cpu,
    /// Current NUMA node ID
    NumaNode,
    /// Pseudo-random u32 from bpf_get_prandom_u32()
    Random,
    /// Timestamp (nanoseconds)
    Timestamp,
    /// Boot-time timestamp (nanoseconds, includes suspend)
    BootTimestamp,
    /// Coarse kernel timestamp (nanoseconds)
    CoarseTimestamp,
    /// TAI timestamp (nanoseconds)
    TaiTimestamp,
    /// Kernel jiffies counter
    Jiffies,
    /// Address of the current traced function/probe target
    FuncIp,
    /// Per-attachment cookie supplied by userspace at attach/link creation time
    AttachCookie,
    /// Current task cgroup ID
    CgroupId,
    /// perf_event sample period (`bpf_perf_event_data::sample_period`)
    PerfSamplePeriod,
    /// perf_event sampled address (`bpf_perf_event_data::addr`)
    PerfAddr,
    /// perf event counter value read with `bpf_perf_prog_read_value`
    PerfCounter,
    /// perf event enabled time read with `bpf_perf_prog_read_value`
    PerfEnabled,
    /// perf event running time read with `bpf_perf_prog_read_value`
    PerfRunning,
    /// XDP packet length (`data_end - data`)
    PacketLen,
    /// Total XDP buffer length, including paged fragments
    XdpBuffLen,
    /// skb packet type (`__sk_buff.pkt_type`)
    PktType,
    /// skb queue mapping (`__sk_buff.queue_mapping`)
    QueueMapping,
    /// skb protocol / ethertype (normalized to host byte order)
    EthProtocol,
    /// skb VLAN presence flag (`__sk_buff.vlan_present`)
    VlanPresent,
    /// skb VLAN TCI (`__sk_buff.vlan_tci`)
    VlanTci,
    /// skb VLAN protocol / ethertype (normalized to host byte order)
    VlanProto,
    /// skb cb[5]
    SkbCb,
    /// skb tc_classid (`__sk_buff.tc_classid`)
    TcClassid,
    /// skb cgroup class ID from `bpf_get_cgroup_classid`
    CgroupClassid,
    /// skb route realm from `bpf_get_route_realm`
    RouteRealm,
    /// skb checksum level query from `bpf_csum_level(..., BPF_CSUM_LEVEL_QUERY)`
    CsumLevel,
    /// skb cgroup ID from `bpf_skb_cgroup_id`
    SkbCgroupId,
    /// skb napi_id (`__sk_buff.napi_id`)
    NapiId,
    /// skb wire_len (`__sk_buff.wire_len`)
    WireLen,
    /// skb gso_segs (`__sk_buff.gso_segs`)
    GsoSegs,
    /// skb gso_size (`__sk_buff.gso_size`)
    GsoSize,
    /// skb timestamp (`__sk_buff.tstamp`)
    Tstamp,
    /// skb timestamp type (`__sk_buff.tstamp_type`)
    TstampType,
    /// skb hwtstamp (`__sk_buff.hwtstamp`)
    Hwtstamp,
    /// XDP packet data pointer
    Data,
    /// XDP packet metadata pointer
    DataMeta,
    /// XDP packet data_end pointer
    DataEnd,
    /// XDP ingress interface index
    IngressIfindex,
    /// skb ifindex (`__sk_buff.ifindex`)
    Ifindex,
    /// XDP receive queue index
    RxQueueIndex,
    /// XDP egress interface index
    EgressIfindex,
    /// skb tc_index (`__sk_buff.tc_index`)
    TcIndex,
    /// skb hash (`__sk_buff.hash`)
    SkbHash,
    /// skb hash from `bpf_get_hash_recalc`
    HashRecalc,
    /// bpf_sock_addr::user_family
    UserFamily,
    /// bpf_sock_addr::user_ip4 (normalized to host byte order)
    UserIp4,
    /// bpf_sock_addr::user_ip6[4] (normalized to host-byte-order u32 words)
    UserIp6,
    /// bpf_sock_addr::user_port (normalized to host byte order)
    UserPort,
    /// bpf_sock_addr::family
    Family,
    /// bpf_sock_addr::type
    SockType,
    /// bpf_sock_addr::protocol
    Protocol,
    /// current bpf_sock pointer on sk_lookup/sk_msg
    Socket,
    /// __sk_buff::flow_keys pointer on flow_dissector programs
    FlowKeys,
    /// bpf_nf_ctx::state trusted pointer
    NetfilterState,
    /// bpf_nf_ctx::skb trusted pointer
    NetfilterSkb,
    /// bpf_nf_ctx::state->hook
    NetfilterHook,
    /// bpf_nf_ctx::state->pf
    NetfilterProtocolFamily,
    /// sk_reuseport_md::bind_inany
    BindInany,
    /// sk_reuseport_md::migrating_sk
    MigratingSocket,
    /// bpf_sock::bound_dev_if
    BoundDevIf,
    /// bpf_sock::mark
    SockMark,
    /// bpf_sock::priority
    SockPriority,
    /// bpf_sock_addr::msg_src_ip4 (normalized to host byte order)
    MsgSrcIp4,
    /// bpf_sock_addr::msg_src_ip6[4] (normalized to host-byte-order u32 words)
    MsgSrcIp6,
    /// bpf_sk_lookup::remote_ip4 (normalized to host byte order)
    RemoteIp4,
    /// bpf_sk_lookup::remote_ip6[4] (normalized to host-byte-order u32 words)
    RemoteIp6,
    /// bpf_sk_lookup::remote_port (normalized to host byte order)
    RemotePort,
    /// bpf_sk_lookup::local_ip4 (normalized to host byte order)
    LocalIp4,
    /// bpf_sk_lookup::local_ip6[4] (normalized to host-byte-order u32 words)
    LocalIp6,
    /// bpf_sk_lookup::local_port (host byte order)
    LocalPort,
    /// bpf_sk_lookup::cookie
    LookupCookie,
    /// lirc mode2 raw sample word
    LircSample,
    /// lirc mode2 low 24-bit payload value
    LircValue,
    /// lirc mode2 high-byte event kind mask
    LircMode,
    /// Stable kernel socket cookie for supported socket-backed contexts
    SocketCookie,
    /// Owner UID of the socket associated with the current skb
    SocketUid,
    /// Stable kernel network-namespace cookie for supported socket-backed contexts
    NetnsCookie,
    /// bpf_cgroup_dev_ctx::access_type
    DeviceAccessType,
    /// cgroup device access flags (`access_type >> 16`)
    DeviceAccess,
    /// cgroup device kind (`access_type & 0xffff`)
    DeviceType,
    /// bpf_cgroup_dev_ctx::major
    DeviceMajor,
    /// bpf_cgroup_dev_ctx::minor
    DeviceMinor,
    /// bpf_sock_ops::op
    SockOp,
    /// bpf_sock_ops::args[4]
    SockOpsArgs,
    /// bpf_sock_ops::reply
    SockOpsReply,
    /// bpf_sock_ops::replylong[4]
    SockOpsReplyLong,
    /// bpf_sock_ops::is_fullsock
    IsFullsock,
    /// bpf_sock_ops::snd_cwnd
    SockOpsSndCwnd,
    /// bpf_sock_ops::srtt_us
    SockOpsSrttUs,
    /// bpf_sock_ops::bpf_sock_ops_cb_flags
    SockOpsCbFlags,
    /// bpf_sock_ops::state
    SockState,
    /// bpf_sock::rx_queue_mapping
    SockRxQueueMapping,
    /// bpf_sock_ops::rtt_min
    SockOpsRttMin,
    /// bpf_sock_ops::snd_ssthresh
    SockOpsSndSsthresh,
    /// bpf_sock_ops::rcv_nxt
    SockOpsRcvNxt,
    /// bpf_sock_ops::snd_nxt
    SockOpsSndNxt,
    /// bpf_sock_ops::snd_una
    SockOpsSndUna,
    /// bpf_sock_ops::mss_cache
    SockOpsMssCache,
    /// bpf_sock_ops::ecn_flags
    SockOpsEcnFlags,
    /// bpf_sock_ops::rate_delivered
    SockOpsRateDelivered,
    /// bpf_sock_ops::rate_interval_us
    SockOpsRateIntervalUs,
    /// bpf_sock_ops::packets_out
    SockOpsPacketsOut,
    /// bpf_sock_ops::retrans_out
    SockOpsRetransOut,
    /// bpf_sock_ops::total_retrans
    SockOpsTotalRetrans,
    /// bpf_sock_ops::segs_in
    SockOpsSegsIn,
    /// bpf_sock_ops::data_segs_in
    SockOpsDataSegsIn,
    /// bpf_sock_ops::segs_out
    SockOpsSegsOut,
    /// bpf_sock_ops::data_segs_out
    SockOpsDataSegsOut,
    /// bpf_sock_ops::lost_out
    SockOpsLostOut,
    /// bpf_sock_ops::sacked_out
    SockOpsSackedOut,
    /// bpf_sock_ops::sk_txhash
    SockOpsSkTxhash,
    /// bpf_sock_ops::bytes_received
    SockOpsBytesReceived,
    /// bpf_sock_ops::bytes_acked
    SockOpsBytesAcked,
    /// bpf_sock_ops::skb_len
    SockOpsSkbLen,
    /// bpf_sock_ops::skb_tcp_flags
    SockOpsSkbTcpFlags,
    /// bpf_sock_ops::skb_hwtstamp
    SockOpsSkbHwtstamp,
    /// bpf_sysctl::write
    SysctlWrite,
    /// bpf_sysctl::file_pos
    SysctlFilePos,
    /// Sysctl full name copied by bpf_sysctl_get_name(ctx, ..., 0)
    SysctlName,
    /// Sysctl base name copied by bpf_sysctl_get_name(ctx, ..., BPF_F_SYSCTL_BASE_NAME)
    SysctlBaseName,
    /// Sysctl current value copied by bpf_sysctl_get_current_value(ctx, ...)
    SysctlCurrentValue,
    /// Sysctl proposed new value copied by bpf_sysctl_get_new_value(ctx, ...)
    SysctlNewValue,
    /// bpf_sockopt::level
    SockoptLevel,
    /// bpf_sockopt::optname
    SockoptOptname,
    /// bpf_sockopt::optlen
    SockoptOptlen,
    /// bpf_sockopt::optval kernel pointer
    SockoptOptval,
    /// bpf_sockopt::optval_end kernel pointer
    SockoptOptvalEnd,
    /// bpf_sockopt::retval
    SockoptRetval,
    /// Program argument (pt_regs-backed probes, raw tracepoints, and BTF-backed trampolines)
    Arg(u8),
    /// Number of argument registers available to BTF-backed tracing programs
    ArgCount,
    /// Return value (return probes and BTF-backed trampolines)
    RetVal,
    /// Kernel stack ID
    KStack,
    /// User stack ID
    UStack,
    /// Tracepoint field by name
    TracepointField(String),
}

impl CtxField {
    pub fn display_name(&self) -> String {
        match self {
            CtxField::Context => "ctx".to_string(),
            CtxField::Pid => "pid".to_string(),
            CtxField::Tgid => "tgid".to_string(),
            CtxField::PidTgid => "pid_tgid".to_string(),
            CtxField::Uid => "uid".to_string(),
            CtxField::Gid => "gid".to_string(),
            CtxField::UidGid => "uid_gid".to_string(),
            CtxField::Comm => "comm".to_string(),
            CtxField::Task => "task".to_string(),
            CtxField::IterTask => "iter_task".to_string(),
            CtxField::IterMeta => "iter_meta".to_string(),
            CtxField::IterFd => "iter_fd".to_string(),
            CtxField::IterFile => "iter_file".to_string(),
            CtxField::IterVma => "iter_vma".to_string(),
            CtxField::IterCgroup => "iter_cgroup".to_string(),
            CtxField::IterMap => "iter_map".to_string(),
            CtxField::IterMapKey => "iter_key".to_string(),
            CtxField::IterMapValue => "iter_value".to_string(),
            CtxField::IterProg => "iter_prog".to_string(),
            CtxField::IterLink => "iter_link".to_string(),
            CtxField::IterSkCommon => "iter_sk_common".to_string(),
            CtxField::IterUdpSk => "iter_udp_sk".to_string(),
            CtxField::IterUnixSk => "iter_unix_sk".to_string(),
            CtxField::IterUid => "iter_uid".to_string(),
            CtxField::IterBucket => "iter_bucket".to_string(),
            CtxField::IterDmabuf => "iter_dmabuf".to_string(),
            CtxField::IterIpv6Route => "iter_ipv6_route".to_string(),
            CtxField::IterKmemCache => "iter_kmem_cache".to_string(),
            CtxField::IterKsym => "iter_ksym".to_string(),
            CtxField::IterNetlinkSk => "iter_netlink_sk".to_string(),
            CtxField::IterSock => "iter_sock".to_string(),
            CtxField::Cgroup => "cgroup".to_string(),
            CtxField::Cpu => "cpu".to_string(),
            CtxField::NumaNode => "numa_node".to_string(),
            CtxField::Random => "random".to_string(),
            CtxField::Timestamp => "timestamp".to_string(),
            CtxField::BootTimestamp => "ktime_boot".to_string(),
            CtxField::CoarseTimestamp => "ktime_coarse".to_string(),
            CtxField::TaiTimestamp => "ktime_tai".to_string(),
            CtxField::Jiffies => "jiffies".to_string(),
            CtxField::FuncIp => "func_ip".to_string(),
            CtxField::AttachCookie => "attach_cookie".to_string(),
            CtxField::CgroupId => "cgroup_id".to_string(),
            CtxField::PerfSamplePeriod => "sample_period".to_string(),
            CtxField::PerfAddr => "addr".to_string(),
            CtxField::PerfCounter => "perf_counter".to_string(),
            CtxField::PerfEnabled => "perf_enabled".to_string(),
            CtxField::PerfRunning => "perf_running".to_string(),
            CtxField::PacketLen => "packet_len".to_string(),
            CtxField::XdpBuffLen => "xdp_buff_len".to_string(),
            CtxField::PktType => "pkt_type".to_string(),
            CtxField::QueueMapping => "queue_mapping".to_string(),
            CtxField::EthProtocol => "eth_protocol".to_string(),
            CtxField::VlanPresent => "vlan_present".to_string(),
            CtxField::VlanTci => "vlan_tci".to_string(),
            CtxField::VlanProto => "vlan_proto".to_string(),
            CtxField::SkbCb => "cb".to_string(),
            CtxField::TcClassid => "tc_classid".to_string(),
            CtxField::CgroupClassid => "cgroup_classid".to_string(),
            CtxField::RouteRealm => "route_realm".to_string(),
            CtxField::CsumLevel => "csum_level".to_string(),
            CtxField::SkbCgroupId => "skb_cgroup_id".to_string(),
            CtxField::NapiId => "napi_id".to_string(),
            CtxField::WireLen => "wire_len".to_string(),
            CtxField::GsoSegs => "gso_segs".to_string(),
            CtxField::GsoSize => "gso_size".to_string(),
            CtxField::Tstamp => "tstamp".to_string(),
            CtxField::TstampType => "tstamp_type".to_string(),
            CtxField::Hwtstamp => "hwtstamp".to_string(),
            CtxField::Data => "data".to_string(),
            CtxField::DataMeta => "data_meta".to_string(),
            CtxField::DataEnd => "data_end".to_string(),
            CtxField::IngressIfindex => "ingress_ifindex".to_string(),
            CtxField::Ifindex => "ifindex".to_string(),
            CtxField::RxQueueIndex => "rx_queue_index".to_string(),
            CtxField::EgressIfindex => "egress_ifindex".to_string(),
            CtxField::TcIndex => "tc_index".to_string(),
            CtxField::SkbHash => "hash".to_string(),
            CtxField::HashRecalc => "hash_recalc".to_string(),
            CtxField::UserFamily => "user_family".to_string(),
            CtxField::UserIp4 => "user_ip4".to_string(),
            CtxField::UserIp6 => "user_ip6".to_string(),
            CtxField::UserPort => "user_port".to_string(),
            CtxField::Family => "family".to_string(),
            CtxField::SockType => "sock_type".to_string(),
            CtxField::Protocol => "protocol".to_string(),
            CtxField::Socket => "sk".to_string(),
            CtxField::FlowKeys => "flow_keys".to_string(),
            CtxField::NetfilterState => "state".to_string(),
            CtxField::NetfilterSkb => "skb".to_string(),
            CtxField::NetfilterHook => "hook".to_string(),
            CtxField::NetfilterProtocolFamily => "pf".to_string(),
            CtxField::BindInany => "bind_inany".to_string(),
            CtxField::MigratingSocket => "migrating_sk".to_string(),
            CtxField::BoundDevIf => "bound_dev_if".to_string(),
            CtxField::SockMark => "mark".to_string(),
            CtxField::SockPriority => "priority".to_string(),
            CtxField::MsgSrcIp4 => "msg_src_ip4".to_string(),
            CtxField::MsgSrcIp6 => "msg_src_ip6".to_string(),
            CtxField::RemoteIp4 => "remote_ip4".to_string(),
            CtxField::RemoteIp6 => "remote_ip6".to_string(),
            CtxField::RemotePort => "remote_port".to_string(),
            CtxField::LocalIp4 => "local_ip4".to_string(),
            CtxField::LocalIp6 => "local_ip6".to_string(),
            CtxField::LocalPort => "local_port".to_string(),
            CtxField::LookupCookie => "cookie".to_string(),
            CtxField::LircSample => "sample".to_string(),
            CtxField::LircValue => "value".to_string(),
            CtxField::LircMode => "mode".to_string(),
            CtxField::SocketCookie => "socket_cookie".to_string(),
            CtxField::SocketUid => "socket_uid".to_string(),
            CtxField::NetnsCookie => "netns_cookie".to_string(),
            CtxField::DeviceAccessType => "access_type".to_string(),
            CtxField::DeviceAccess => "device_access".to_string(),
            CtxField::DeviceType => "device_type".to_string(),
            CtxField::DeviceMajor => "major".to_string(),
            CtxField::DeviceMinor => "minor".to_string(),
            CtxField::SockOp => "op".to_string(),
            CtxField::SockOpsArgs => "args".to_string(),
            CtxField::SockOpsReply => "reply".to_string(),
            CtxField::SockOpsReplyLong => "replylong".to_string(),
            CtxField::IsFullsock => "is_fullsock".to_string(),
            CtxField::SockOpsSndCwnd => "snd_cwnd".to_string(),
            CtxField::SockOpsSrttUs => "srtt_us".to_string(),
            CtxField::SockOpsCbFlags => "cb_flags".to_string(),
            CtxField::SockState => "state".to_string(),
            CtxField::SockRxQueueMapping => "rx_queue_mapping".to_string(),
            CtxField::SockOpsRttMin => "rtt_min".to_string(),
            CtxField::SockOpsSndSsthresh => "snd_ssthresh".to_string(),
            CtxField::SockOpsRcvNxt => "rcv_nxt".to_string(),
            CtxField::SockOpsSndNxt => "snd_nxt".to_string(),
            CtxField::SockOpsSndUna => "snd_una".to_string(),
            CtxField::SockOpsMssCache => "mss_cache".to_string(),
            CtxField::SockOpsEcnFlags => "ecn_flags".to_string(),
            CtxField::SockOpsRateDelivered => "rate_delivered".to_string(),
            CtxField::SockOpsRateIntervalUs => "rate_interval_us".to_string(),
            CtxField::SockOpsPacketsOut => "packets_out".to_string(),
            CtxField::SockOpsRetransOut => "retrans_out".to_string(),
            CtxField::SockOpsTotalRetrans => "total_retrans".to_string(),
            CtxField::SockOpsSegsIn => "segs_in".to_string(),
            CtxField::SockOpsDataSegsIn => "data_segs_in".to_string(),
            CtxField::SockOpsSegsOut => "segs_out".to_string(),
            CtxField::SockOpsDataSegsOut => "data_segs_out".to_string(),
            CtxField::SockOpsLostOut => "lost_out".to_string(),
            CtxField::SockOpsSackedOut => "sacked_out".to_string(),
            CtxField::SockOpsSkTxhash => "sk_txhash".to_string(),
            CtxField::SockOpsBytesReceived => "bytes_received".to_string(),
            CtxField::SockOpsBytesAcked => "bytes_acked".to_string(),
            CtxField::SockOpsSkbLen => "skb_len".to_string(),
            CtxField::SockOpsSkbTcpFlags => "skb_tcp_flags".to_string(),
            CtxField::SockOpsSkbHwtstamp => "skb_hwtstamp".to_string(),
            CtxField::SysctlWrite => "write".to_string(),
            CtxField::SysctlFilePos => "file_pos".to_string(),
            CtxField::SysctlName => "sysctl_name".to_string(),
            CtxField::SysctlBaseName => "sysctl_base_name".to_string(),
            CtxField::SysctlCurrentValue => "sysctl_current_value".to_string(),
            CtxField::SysctlNewValue => "sysctl_new_value".to_string(),
            CtxField::SockoptLevel => "level".to_string(),
            CtxField::SockoptOptname => "optname".to_string(),
            CtxField::SockoptOptlen => "optlen".to_string(),
            CtxField::SockoptOptval => "optval".to_string(),
            CtxField::SockoptOptvalEnd => "optval_end".to_string(),
            CtxField::SockoptRetval => "sockopt_retval".to_string(),
            CtxField::Arg(idx) => format!("arg{}", idx),
            CtxField::ArgCount => "arg_count".to_string(),
            CtxField::RetVal => "retval".to_string(),
            CtxField::KStack => "kstack".to_string(),
            CtxField::UStack => "ustack".to_string(),
            CtxField::TracepointField(name) => name.clone(),
        }
    }

    pub fn bounded_end_field(&self) -> Option<CtxField> {
        match self {
            CtxField::DataMeta => Some(CtxField::Data),
            CtxField::SockoptOptval => Some(CtxField::SockoptOptvalEnd),
            _ => None,
        }
    }
}

/// Writable context-field targets.
///
/// This is intentionally narrower than `CtxField`: some context values are
/// readable but not writable, and some writable semantics do not map cleanly
/// to the read-side surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CtxStoreTarget {
    /// `bpf_sock_ops.reply`
    SockOpsReply,
    /// `bpf_sock_ops.replylong[idx]`
    SockOpsReplyLong(u8),
    /// `bpf_sock_ops_cb_flags_set(ctx, flags)`
    SockOpsCbFlags,
    /// `bpf_sock_ops.sk_txhash`
    SockOpsSkTxhash,
    /// `bpf_sock.bound_dev_if`
    CgroupSockBoundDevIf,
    /// `bpf_sock.mark`
    CgroupSockMark,
    /// `bpf_sock.priority`
    CgroupSockPriority,
    /// `__sk_buff.mark`
    SkbMark,
    /// `__sk_buff.queue_mapping`
    SkbQueueMapping,
    /// `__sk_buff.priority`
    SkbPriority,
    /// `__sk_buff.tc_index`
    SkbTcIndex,
    /// `__sk_buff.cb[idx]`
    SkbCbWord(u8),
    /// `__sk_buff.tc_classid`
    SkbTcClassid,
    /// `__sk_buff.tstamp`
    SkbTstamp,
    /// `bpf_sysctl.file_pos`
    SysctlFilePos,
    /// `bpf_sockopt.level`
    SockoptLevel,
    /// `bpf_sockopt.optname`
    SockoptOptname,
    /// `bpf_sockopt.optlen`
    SockoptOptlen,
    /// `bpf_sockopt.retval`
    SockoptRetval,
    /// `bpf_sock_addr.user_ip4` (stored in network byte order)
    CgroupSockAddrUserIp4,
    /// `bpf_sock_addr.user_ip6[idx]` (stored in network byte order)
    CgroupSockAddrUserIp6Word(u8),
    /// `bpf_sock_addr.user_port` (stored in network byte order)
    CgroupSockAddrUserPort,
    /// `bpf_sock_addr.msg_src_ip4` (stored in network byte order)
    CgroupSockAddrMsgSrcIp4,
    /// `bpf_sock_addr.msg_src_ip6[idx]` (stored in network byte order)
    CgroupSockAddrMsgSrcIp6Word(u8),
}

impl CtxStoreTarget {
    pub fn value_type(&self) -> MirType {
        match self {
            CtxStoreTarget::SockOpsReply
            | CtxStoreTarget::SockOpsReplyLong(_)
            | CtxStoreTarget::SockOpsCbFlags
            | CtxStoreTarget::SockOpsSkTxhash
            | CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority
            | CtxStoreTarget::SkbMark
            | CtxStoreTarget::SkbQueueMapping
            | CtxStoreTarget::SkbPriority
            | CtxStoreTarget::SkbTcIndex
            | CtxStoreTarget::SkbCbWord(_)
            | CtxStoreTarget::SkbTcClassid
            | CtxStoreTarget::SysctlFilePos => MirType::U32,
            CtxStoreTarget::SkbTstamp => MirType::U64,
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => MirType::I32,
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => MirType::U32,
        }
    }

    pub fn type_error_message(&self, actual: &MirType) -> String {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                format!(
                    "writable sock_ops reply fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SockOpsCbFlags => {
                format!(
                    "writable sock_ops cb_flags requires a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SockOpsSkTxhash => {
                format!(
                    "writable sock_ops sk_txhash requires a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority => {
                format!(
                    "writable cgroup_sock scalar fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SkbMark
            | CtxStoreTarget::SkbQueueMapping
            | CtxStoreTarget::SkbPriority
            | CtxStoreTarget::SkbTcIndex
            | CtxStoreTarget::SkbCbWord(_)
            | CtxStoreTarget::SkbTcClassid => {
                format!(
                    "writable skb metadata fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SkbTstamp => {
                format!("writable skb tstamp requires a u64 store, got {:?}", actual)
            }
            CtxStoreTarget::SysctlFilePos => {
                format!(
                    "writable cgroup_sysctl file_pos requires a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => format!(
                "writable cgroup_sockopt scalar fields require an i32 store, got {:?}",
                actual
            ),
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => {
                format!(
                    "writable cgroup_sock_addr rewrite fields require a u32 store, got {:?}",
                    actual
                )
            }
        }
    }

    pub fn missing_context_error(&self) -> &'static str {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                "writable sock_ops reply fields are only supported on sock_ops programs"
            }
            CtxStoreTarget::SockOpsCbFlags => {
                "writable sock_ops cb_flags is only supported on sock_ops programs"
            }
            CtxStoreTarget::SockOpsSkTxhash => {
                "writable sock_ops sk_txhash is only supported on sock_ops programs"
            }
            CtxStoreTarget::CgroupSockBoundDevIf => {
                "writable cgroup_sock bound_dev_if is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::CgroupSockMark => {
                "writable cgroup_sock mark is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::CgroupSockPriority => {
                "writable cgroup_sock priority is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::SkbMark => {
                "ctx.mark is only writable on lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
            }
            CtxStoreTarget::SkbQueueMapping => {
                "ctx.queue_mapping is only writable on tc_action, tc, tcx, and netkit programs"
            }
            CtxStoreTarget::SkbPriority => {
                "ctx.priority is only writable on lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
            }
            CtxStoreTarget::SkbTcIndex => {
                "ctx.tc_index is only writable on tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
            }
            CtxStoreTarget::SkbCbWord(_) => {
                "ctx.cb is only writable on socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
            }
            CtxStoreTarget::SkbTcClassid => {
                "ctx.tc_classid is only writable on tc_action, tc, tcx, and netkit programs"
            }
            CtxStoreTarget::SkbTstamp => {
                "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
            }
            CtxStoreTarget::SysctlFilePos => {
                "writable cgroup_sysctl file_pos is only supported on cgroup_sysctl programs"
            }
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => {
                "writable cgroup_sockopt scalar fields require cgroup_sockopt context"
            }
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => {
                "writable cgroup_sock_addr rewrite fields require cgroup_sock_addr context"
            }
        }
    }
}

/// MIR instruction
#[derive(Debug, Clone)]
pub enum MirInst {
    // Data movement
    /// Copy value to virtual register
    Copy { dst: VReg, src: MirValue },

    /// Load from memory (stack or via pointer)
    Load {
        dst: VReg,
        ptr: VReg,
        offset: i32,
        ty: MirType,
    },

    /// Store to memory
    Store {
        ptr: VReg,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    /// Load from stack slot
    LoadSlot {
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        ty: MirType,
    },

    /// Store to stack slot
    StoreSlot {
        slot: StackSlotId,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    // Arithmetic
    /// Binary operation
    BinOp {
        dst: VReg,
        op: BinOpKind,
        lhs: MirValue,
        rhs: MirValue,
    },

    /// Unary operation
    UnaryOp {
        dst: VReg,
        op: UnaryOpKind,
        src: MirValue,
    },

    // BPF helpers
    /// Call BPF helper function
    CallHelper {
        dst: VReg,
        helper: u32, // BPF helper ID
        args: Vec<MirValue>,
    },

    /// Call BPF kfunc (BTF-described kernel function)
    CallKfunc {
        dst: VReg,
        kfunc: String,
        /// Optional explicit BTF ID. If absent, backend resolves from `kfunc`.
        btf_id: Option<u32>,
        args: Vec<VReg>,
    },

    /// Materialize a map reference for helper-call lowering.
    LoadMapFd { dst: VReg, map: MapRef },

    /// Map lookup
    MapLookup { dst: VReg, map: MapRef, key: VReg },

    /// Load a compiler-generated global symbol from `.rodata`, `.data`, or `.bss`
    LoadGlobal {
        dst: VReg,
        symbol: String,
        ty: MirType,
    },

    /// Materialize a pointer to a local BPF subprogram for callback-taking helpers.
    LoadSubprogram { dst: VReg, subfn: SubfunctionId },

    /// Map update
    MapUpdate {
        map: MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    },

    /// Map delete
    MapDelete { map: MapRef, key: VReg },

    /// Queue/stack push
    MapPush { map: MapRef, val: VReg, flags: u64 },

    /// Histogram aggregation - computes log2 bucket and increments counter
    Histogram {
        /// Value to compute histogram bucket for
        value: VReg,
    },

    /// Start timer - stores current ktime keyed by TID
    StartTimer,

    /// Stop timer - looks up start time, computes delta, deletes entry
    /// Result is stored in dst (0 if no matching start)
    StopTimer { dst: VReg },

    /// Emit event to ring buffer
    EmitEvent { data: VReg, size: usize },

    /// Emit structured record to ring buffer
    EmitRecord {
        /// Fields to emit, in order
        fields: Vec<RecordFieldDef>,
    },

    // Context access
    /// Load context field
    LoadCtxField {
        dst: VReg,
        field: CtxField,
        /// Optional stack slot backing the field (for stack-based ctx data like comm)
        slot: Option<StackSlotId>,
    },

    /// Store a writable context field
    StoreCtxField {
        target: CtxStoreTarget,
        val: MirValue,
        ty: MirType,
    },

    // String operations
    /// Read string from user/kernel memory
    ReadStr {
        dst: StackSlotId,
        ptr: VReg,
        user_space: bool,
        max_len: usize,
    },

    /// Compare two strings on stack
    StrCmp {
        dst: VReg,
        lhs: StackSlotId,
        rhs: StackSlotId,
        len: usize,
    },

    /// Append a value to a string buffer
    /// dst_buffer is the destination string buffer on stack
    /// dst_len is a vreg holding the current string length
    /// val is the value to append (string slot or int)
    StringAppend {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: MirValue,
        val_type: StringAppendType,
    },

    /// Format an integer as decimal string into a buffer
    /// Used for string interpolation with integers
    IntToString {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    },

    // Record building
    /// Store field to record buffer
    RecordStore {
        buffer: StackSlotId,
        field_offset: usize,
        val: MirValue,
        ty: MirType,
    },

    // List operations
    /// Initialize an empty list on the stack
    /// Layout: [length: u64, elem0: u64, elem1: u64, ...]
    /// max_len determines the allocated buffer size
    ListNew {
        dst: VReg,
        buffer: StackSlotId,
        max_len: usize,
    },

    /// Push an element onto the end of a list
    /// Stores at offset (length * 8) + 8, then increments length
    ListPush { list: VReg, item: VReg },

    /// Get the current length of a list
    ListLen { dst: VReg, list: VReg },

    /// Get an element from a list by index
    /// Returns 0 if index out of bounds
    ListGet {
        dst: VReg,
        list: VReg,
        idx: MirValue,
    },

    // SSA phi function
    /// Phi node for SSA form - selects value based on incoming edge
    /// Must appear at the start of a block, before any non-phi instructions
    Phi {
        dst: VReg,
        /// (predecessor block, value from that predecessor)
        args: Vec<(BlockId, VReg)>,
    },

    // Control flow (terminators - must be last in block)
    /// Unconditional jump
    Jump { target: BlockId },

    /// Conditional branch
    Branch {
        cond: VReg,
        if_true: BlockId,
        if_false: BlockId,
    },

    /// Return from program
    Return { val: Option<MirValue> },

    /// Tail call to another program
    TailCall { prog_map: MapRef, index: MirValue },

    /// Call a BPF subfunction (BPF-to-BPF call)
    /// Arguments are passed in R1-R5, return value in R0
    CallSubfn {
        dst: VReg,
        subfn: SubfunctionId,
        args: Vec<VReg>,
    },

    // Pseudo-instructions (expanded during lowering)
    /// Bounded loop header (eBPF verifier requirement)
    LoopHeader {
        counter: VReg,
        start: i64,
        step: i64,
        limit: i64,
        body: BlockId,
        exit: BlockId,
    },

    /// Loop increment and back-edge
    LoopBack {
        counter: VReg,
        step: i64,
        header: BlockId,
    },

    /// Placeholder terminator (not a real terminator, must be replaced)
    Placeholder,
}

/// A basic block with instructions and a terminator
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Non-terminator instructions
    pub instructions: Vec<MirInst>,
    /// Block terminator (must be Jump, Branch, Return, or TailCall)
    pub terminator: MirInst,
}

/// A complete MIR function
#[derive(Debug, Clone)]
pub struct MirFunction {
    /// Function name (for debugging and ELF section naming)
    pub name: Option<String>,
    /// Basic blocks (entry block is first)
    pub blocks: Vec<BasicBlock>,
    /// Entry block ID
    pub entry: BlockId,
    /// Number of virtual registers used
    pub vreg_count: u32,
    /// Stack slots
    pub stack_slots: Vec<StackSlot>,
    /// Maps used by this function
    pub maps_used: Vec<MapRef>,
    /// Parameter count (for BPF subfunction calling convention)
    pub param_count: usize,
    /// Synthetic stack slots that model stack-object parameters for verifier/VCC analysis.
    pub param_stack_slots: HashMap<usize, StackSlotId>,
    /// ABI-backed pointer parameters that are known non-null at function entry.
    pub param_non_null: HashSet<usize>,
    /// ABI-backed kernel pointer parameters that preserve trusted BTF provenance.
    pub param_trusted_btf: HashSet<usize>,
    /// Synthetic dynptr parameter slots that enter initialized.
    pub entry_initialized_dynptr_slots: HashSet<StackSlotId>,
    /// Mutable-global symbols that semantically alias incoming parameters.
    ///
    /// This is used to recover "returns arg N" summaries for subfunctions that
    /// read aliased parameters back through `LoadGlobal` to preserve non-null
    /// global semantics.
    pub global_param_aliases: HashMap<String, usize>,
}

/// A complete MIR program (may have subfunctions for BPF-to-BPF calls)
#[derive(Debug, Clone)]
pub struct MirProgram {
    /// Main function
    pub main: MirFunction,
    /// Subfunctions (for BPF-to-BPF calls)
    pub subfunctions: Vec<MirFunction>,
}

/// Optional type hints for MIR registers, usually derived from HIR inference.
#[derive(Debug, Clone, Default)]
pub struct MirTypeHints {
    pub main: HashMap<VReg, MirType>,
    pub subfunctions: Vec<HashMap<VReg, MirType>>,
    pub main_stack_slots: HashMap<StackSlotId, MirType>,
    pub subfunction_stack_slots: Vec<HashMap<StackSlotId, MirType>>,
    /// Context fields implied by higher-level typed projections that do not
    /// appear as direct LoadCtxField instructions after lowering.
    pub used_ctx_fields: HashSet<CtxField>,
    pub generic_map_key_types: HashMap<MapRef, MirType>,
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    pub generic_map_max_entries: HashMap<MapRef, u32>,
    pub generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
}

#[cfg(test)]
mod tests;
