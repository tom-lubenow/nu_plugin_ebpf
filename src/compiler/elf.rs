//! Minimal ELF generation for eBPF programs
//!
//! This module creates ELF object files that can be loaded by Aya or libbpf.
//! The ELF format includes:
//! - A section with the eBPF bytecode (named for the program type, e.g., "kprobe/func")
//! - A "license" section containing the license string (required for most helpers)
//! - Optional ".maps" section for BPF map definitions

use std::collections::HashMap;

use crate::program_spec::ProgramSpec;
use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionFlags, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

use super::CompileError;
use super::btf::BtfBuilder;
use super::instruction::EbpfBuilder;
use super::mir::{
    BYTES_COUNTER_MAP_NAME, BitfieldInfo, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapRef, MirType, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME,
    TIMESTAMP_MAP_NAME, USTACK_MAP_NAME,
};

mod program_impl;

/// BPF map types (subset of types we might use)
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
#[allow(dead_code)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PerCpuHash = 5,
    PerCpuArray = 6,
    LruHash = 9,
    LruPerCpuHash = 10,
    LpmTrie = 11,
    StackTrace = 7,
    RingBuf = 27,
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
            MirType::U64 | MirType::Ptr { .. } | MirType::MapRef { .. } | MirType::Unknown => {
                CounterKeySchema::Int {
                    size: ty.size().max(1),
                    signed: false,
                }
            }
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
    /// BTF function entry probe (fentry)
    Fentry,
    /// BTF function exit probe (fexit)
    Fexit,
    /// Tracepoint
    Tracepoint,
    /// Raw tracepoint
    RawTracepoint,
    /// User-space probe (uprobe)
    Uprobe,
    /// User-space return probe (uretprobe)
    Uretprobe,
    /// Linux security module hook program
    Lsm,
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
    /// Struct-ops callback program emitted into a `struct_ops/*` section.
    StructOps,
}

impl EbpfProgramType {
    pub fn info(&self) -> &'static ProgramTypeInfo {
        match self {
            EbpfProgramType::Kprobe => &KPROBE_INFO,
            EbpfProgramType::Kretprobe => &KRETPROBE_INFO,
            EbpfProgramType::Fentry => &FENTRY_INFO,
            EbpfProgramType::Fexit => &FEXIT_INFO,
            EbpfProgramType::Tracepoint => &TRACEPOINT_INFO,
            EbpfProgramType::RawTracepoint => &RAW_TRACEPOINT_INFO,
            EbpfProgramType::Uprobe => &UPROBE_INFO,
            EbpfProgramType::Uretprobe => &URETPROBE_INFO,
            EbpfProgramType::Lsm => &LSM_INFO,
            EbpfProgramType::Xdp => &XDP_INFO,
            EbpfProgramType::PerfEvent => &PERF_EVENT_INFO,
            EbpfProgramType::SocketFilter => &SOCKET_FILTER_INFO,
            EbpfProgramType::CgroupDevice => &CGROUP_DEVICE_INFO,
            EbpfProgramType::SkLookup => &SK_LOOKUP_INFO,
            EbpfProgramType::SkMsg => &SK_MSG_INFO,
            EbpfProgramType::SkSkb => &SK_SKB_INFO,
            EbpfProgramType::SkSkbParser => &SK_SKB_PARSER_INFO,
            EbpfProgramType::SockOps => &SOCK_OPS_INFO,
            EbpfProgramType::Tc => &TC_INFO,
            EbpfProgramType::CgroupSkb => &CGROUP_SKB_INFO,
            EbpfProgramType::CgroupSock => &CGROUP_SOCK_INFO,
            EbpfProgramType::CgroupSysctl => &CGROUP_SYSCTL_INFO,
            EbpfProgramType::CgroupSockopt => &CGROUP_SOCKOPT_INFO,
            EbpfProgramType::CgroupSockAddr => &CGROUP_SOCK_ADDR_INFO,
            EbpfProgramType::StructOps => &STRUCT_OPS_INFO,
        }
    }

    pub fn supported_spec_prefixes() -> &'static [&'static str] {
        PROGRAM_SPEC_PREFIXES
    }

    pub fn from_spec_prefix(prefix: &str) -> Option<Self> {
        [
            EbpfProgramType::Kprobe,
            EbpfProgramType::Kretprobe,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::Tracepoint,
            EbpfProgramType::RawTracepoint,
            EbpfProgramType::Uprobe,
            EbpfProgramType::Uretprobe,
            EbpfProgramType::Lsm,
            EbpfProgramType::Xdp,
            EbpfProgramType::PerfEvent,
            EbpfProgramType::SocketFilter,
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
            EbpfProgramType::SockOps,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSysctl,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::StructOps,
        ]
        .into_iter()
        .find(|program_type| program_type.info().spec_aliases.contains(&prefix))
    }

    pub fn canonical_prefix(&self) -> &'static str {
        self.info().canonical_prefix
    }

    /// Get the ELF section name prefix for this program type
    pub fn section_prefix(&self) -> &'static str {
        self.info().section_prefix
    }

    pub fn attach_kind(&self) -> ProgramAttachKind {
        self.info().attach_kind
    }

    pub fn target_kind(&self) -> ProgramTargetKind {
        self.info().target_kind
    }

    pub fn kernel_target_validation(&self) -> Option<KernelTargetValidationKind> {
        self.info().kernel_target_validation
    }

    pub fn supports_intrinsic(&self, intrinsic: ProgramIntrinsic) -> bool {
        self.supports_capability(intrinsic.required_capability())
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

    pub fn uses_btf_trampoline(&self) -> bool {
        matches!(
            (self.arg_access(), self.retval_access()),
            (ProgramValueAccess::Trampoline, _) | (_, ProgramValueAccess::Trampoline)
        )
    }

    /// Returns true if this runs at function return time.
    pub fn is_return_probe(&self) -> bool {
        !matches!(self.retval_access(), ProgramValueAccess::None)
    }

    /// Returns true if this is a userspace probe (uprobe or uretprobe)
    pub fn is_userspace(&self) -> bool {
        self.info().is_userspace
    }

    /// Returns true if this program type exposes function arguments via ctx.argN.
    pub fn supports_ctx_args(&self) -> bool {
        !matches!(self.arg_access(), ProgramValueAccess::None)
    }

    /// Returns true if this program type exposes ctx.retval.
    pub fn supports_ctx_retval(&self) -> bool {
        !matches!(self.retval_access(), ProgramValueAccess::None)
    }

    /// Returns true if this program type exposes named tracepoint fields.
    pub fn supports_tracepoint_fields(&self) -> bool {
        self.info().supports_tracepoint_fields
    }

    pub fn supports_task_ctx_fields(&self) -> bool {
        self.info().supports_task_ctx_fields
    }

    pub fn supports_cpu_ctx_field(&self) -> bool {
        self.info().supports_cpu_ctx_field
    }

    pub fn supports_timestamp_ctx_field(&self) -> bool {
        self.info().supports_timestamp_ctx_field
    }

    pub fn supports_stack_ctx_fields(&self) -> bool {
        self.info().supports_stack_ctx_fields
    }

    pub fn supports_xdp_md_ctx_fields(&self) -> bool {
        self.info().supports_xdp_md_ctx_fields
    }

    pub fn packet_context_kind(&self) -> Option<PacketContextKind> {
        self.info().packet_context_kind
    }

    pub fn supports_packet_len_ctx_field(&self) -> bool {
        self.info().supports_packet_len_ctx_field
    }

    pub fn supports_packet_data_ctx_fields(&self) -> bool {
        self.info().supports_packet_data_ctx_fields
    }

    pub fn supports_ingress_ifindex_ctx_field(&self) -> bool {
        self.info().supports_ingress_ifindex_ctx_field
    }

    pub fn supports_rx_queue_index_ctx_field(&self) -> bool {
        self.info().supports_rx_queue_index_ctx_field
    }

    pub fn supports_egress_ifindex_ctx_field(&self) -> bool {
        self.info().supports_egress_ifindex_ctx_field
    }
}

impl ProgramSpec {
    pub fn program_type(&self) -> EbpfProgramType {
        match self {
            ProgramSpec::Kprobe { .. } => EbpfProgramType::Kprobe,
            ProgramSpec::Kretprobe { .. } => EbpfProgramType::Kretprobe,
            ProgramSpec::Fentry { .. } => EbpfProgramType::Fentry,
            ProgramSpec::Fexit { .. } => EbpfProgramType::Fexit,
            ProgramSpec::Lsm { .. } => EbpfProgramType::Lsm,
            ProgramSpec::Tracepoint { .. } => EbpfProgramType::Tracepoint,
            ProgramSpec::RawTracepoint { .. } => EbpfProgramType::RawTracepoint,
            ProgramSpec::Uprobe { .. } => EbpfProgramType::Uprobe,
            ProgramSpec::Uretprobe { .. } => EbpfProgramType::Uretprobe,
            ProgramSpec::Xdp { .. } => EbpfProgramType::Xdp,
            ProgramSpec::PerfEvent { .. } => EbpfProgramType::PerfEvent,
            ProgramSpec::SocketFilter { .. } => EbpfProgramType::SocketFilter,
            ProgramSpec::CgroupDevice { .. } => EbpfProgramType::CgroupDevice,
            ProgramSpec::SkLookup { .. } => EbpfProgramType::SkLookup,
            ProgramSpec::SkMsg { .. } => EbpfProgramType::SkMsg,
            ProgramSpec::SkSkb { .. } => EbpfProgramType::SkSkb,
            ProgramSpec::SkSkbParser { .. } => EbpfProgramType::SkSkbParser,
            ProgramSpec::SockOps { .. } => EbpfProgramType::SockOps,
            ProgramSpec::Tc { .. } => EbpfProgramType::Tc,
            ProgramSpec::CgroupSkb { .. } => EbpfProgramType::CgroupSkb,
            ProgramSpec::CgroupSock { .. } => EbpfProgramType::CgroupSock,
            ProgramSpec::CgroupSysctl { .. } => EbpfProgramType::CgroupSysctl,
            ProgramSpec::CgroupSockopt { .. } => EbpfProgramType::CgroupSockopt,
            ProgramSpec::CgroupSockAddr { .. } => EbpfProgramType::CgroupSockAddr,
            ProgramSpec::StructOps { .. } => EbpfProgramType::StructOps,
        }
    }
}

impl std::fmt::Display for ProgramSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.program_type().canonical_prefix(),
            self.target_string()
        )
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
    pub probe_type: EbpfProgramType,
    /// The target function or tracepoint name
    pub target: String,
    /// Optional kernel BTF container type for `struct_ops` callbacks.
    pub struct_ops_value_type_name: Option<String>,
}

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
                    "ctx.{} is only available on packet-context programs (xdp, socket_filter, tc, cgroup_skb)",
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
            CtxField::LookupCookie if !matches!(self.probe_type, EbpfProgramType::SkLookup) => {
                Some(format!(
                    "ctx.{} is only available on sk_lookup programs",
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
            CtxField::BoundDevIf if !matches!(self.probe_type, EbpfProgramType::CgroupSock) =>
            {
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
                Some(
                    "ctx.msg_src_ip4 is only available on cgroup_sock_addr programs".to_string(),
                )
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
                Some(
                    "ctx.msg_src_ip6 is only available on cgroup_sock_addr programs".to_string(),
                )
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
            CtxField::Arg(_) if !self.probe_type.supports_ctx_args() => Some(format!(
                "ctx.{} is only available on function probes with argument access (kprobe, uprobe, fentry, fexit)",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramAttachKind {
    Kprobe,
    Kretprobe,
    Fentry,
    Fexit,
    Tracepoint,
    RawTracepoint,
    Uprobe,
    Uretprobe,
    Lsm,
    Xdp,
    PerfEvent,
    SocketFilter,
    CgroupDevice,
    SkLookup,
    SkMsg,
    SkSkb,
    SkSkbParser,
    SockOps,
    Tc,
    CgroupSkb,
    CgroupSock,
    CgroupSysctl,
    CgroupSockopt,
    CgroupSockAddr,
    StructOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramTargetKind {
    KernelFunction,
    LsmHook,
    Tracepoint,
    RawTracepoint,
    UserFunction,
    NetworkInterface,
    PerfEventTarget,
    SocketFilterTarget,
    NetworkNamespacePath,
    PinnedSockMapPath,
    TrafficControlInterface,
    CgroupPathAttachType,
    CgroupPathSockAttachType,
    CgroupPath,
    CgroupPathSockoptAttachType,
    CgroupPathSockAddrAttachType,
    StructOpsCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketContextKind {
    XdpMd,
    SkBuff,
    SkMsg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelTargetValidationKind {
    SymbolOnly,
    FentryTrampoline,
    FexitTrampoline,
    LsmHook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramValueAccess {
    None,
    PtRegs,
    Trampoline,
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
    KfuncCall,
    GlobalDefine,
    GlobalGet,
    GlobalSet,
    MapGet,
    MapPut,
    MapDelete,
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
            ProgramIntrinsic::KfuncCall => "kfunc-call",
            ProgramIntrinsic::GlobalDefine => "global-define",
            ProgramIntrinsic::GlobalGet => "global-get",
            ProgramIntrinsic::GlobalSet => "global-set",
            ProgramIntrinsic::MapGet => "map-get",
            ProgramIntrinsic::MapPut => "map-put",
            ProgramIntrinsic::MapDelete => "map-delete",
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
            "kfunc-call" => Some(ProgramIntrinsic::KfuncCall),
            "global-define" => Some(ProgramIntrinsic::GlobalDefine),
            "global-get" => Some(ProgramIntrinsic::GlobalGet),
            "global-set" => Some(ProgramIntrinsic::GlobalSet),
            "map-get" => Some(ProgramIntrinsic::MapGet),
            "map-put" => Some(ProgramIntrinsic::MapPut),
            "map-delete" => Some(ProgramIntrinsic::MapDelete),
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
            ProgramIntrinsic::KfuncCall => ProgramCapability::KfuncCalls,
            ProgramIntrinsic::GlobalDefine
            | ProgramIntrinsic::GlobalGet
            | ProgramIntrinsic::GlobalSet => ProgramCapability::Globals,
            ProgramIntrinsic::MapGet | ProgramIntrinsic::MapPut | ProgramIntrinsic::MapDelete => {
                ProgramCapability::GenericMaps
            }
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
    KfuncCalls,
    Globals,
    GenericMaps,
    TailCalls,
}

impl ProgramCapability {
    pub fn description(&self) -> &'static str {
        match self {
            ProgramCapability::Emit => "event emission",
            ProgramCapability::Counters => "counter aggregations",
            ProgramCapability::Histograms => "histogram aggregations",
            ProgramCapability::Timers => "timer aggregations",
            ProgramCapability::StackTraces => "stack trace collection",
            ProgramCapability::ReadUserString => "userspace string reads",
            ProgramCapability::ReadKernelString => "kernel string reads",
            ProgramCapability::KfuncCalls => "kfunc calls",
            ProgramCapability::Globals => "program globals",
            ProgramCapability::GenericMaps => "generic map operations",
            ProgramCapability::TailCalls => "tail calls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramTypeInfo {
    pub program_type: EbpfProgramType,
    pub canonical_prefix: &'static str,
    pub spec_aliases: &'static [&'static str],
    pub section_prefix: &'static str,
    pub section_uses_target: bool,
    pub attach_kind: ProgramAttachKind,
    pub target_kind: ProgramTargetKind,
    pub kernel_target_validation: Option<KernelTargetValidationKind>,
    pub supported_capabilities: &'static [ProgramCapability],
    pub arg_access: ProgramValueAccess,
    pub retval_access: ProgramValueAccess,
    pub supports_task_ctx_fields: bool,
    pub supports_cpu_ctx_field: bool,
    pub supports_timestamp_ctx_field: bool,
    pub packet_context_kind: Option<PacketContextKind>,
    pub supports_packet_len_ctx_field: bool,
    pub supports_packet_data_ctx_fields: bool,
    pub supports_ingress_ifindex_ctx_field: bool,
    pub supports_rx_queue_index_ctx_field: bool,
    pub supports_egress_ifindex_ctx_field: bool,
    pub supports_xdp_md_ctx_fields: bool,
    pub supports_stack_ctx_fields: bool,
    pub supports_tracepoint_fields: bool,
    pub is_userspace: bool,
}

const KPROBE_SPEC_ALIASES: &[&str] = &["kprobe"];
const KRETPROBE_SPEC_ALIASES: &[&str] = &["kretprobe"];
const FENTRY_SPEC_ALIASES: &[&str] = &["fentry"];
const FEXIT_SPEC_ALIASES: &[&str] = &["fexit"];
const TRACEPOINT_SPEC_ALIASES: &[&str] = &["tracepoint"];
const RAW_TRACEPOINT_SPEC_ALIASES: &[&str] = &["raw_tracepoint", "raw_tp"];
const UPROBE_SPEC_ALIASES: &[&str] = &["uprobe"];
const URETPROBE_SPEC_ALIASES: &[&str] = &["uretprobe"];
const LSM_SPEC_ALIASES: &[&str] = &["lsm"];
const XDP_SPEC_ALIASES: &[&str] = &["xdp"];
const PERF_EVENT_SPEC_ALIASES: &[&str] = &["perf_event"];
const SOCKET_FILTER_SPEC_ALIASES: &[&str] = &["socket_filter", "sock_filter"];
const CGROUP_DEVICE_SPEC_ALIASES: &[&str] = &["cgroup_device"];
const SK_LOOKUP_SPEC_ALIASES: &[&str] = &["sk_lookup"];
const SK_MSG_SPEC_ALIASES: &[&str] = &["sk_msg"];
const SK_SKB_SPEC_ALIASES: &[&str] = &["sk_skb"];
const SK_SKB_PARSER_SPEC_ALIASES: &[&str] = &["sk_skb_parser"];
const SOCK_OPS_SPEC_ALIASES: &[&str] = &["sock_ops", "sockops"];
const TC_SPEC_ALIASES: &[&str] = &["tc"];
const CGROUP_SKB_SPEC_ALIASES: &[&str] = &["cgroup_skb"];
const CGROUP_SOCK_SPEC_ALIASES: &[&str] = &["cgroup_sock"];
const CGROUP_SYSCTL_SPEC_ALIASES: &[&str] = &["cgroup_sysctl"];
const CGROUP_SOCKOPT_SPEC_ALIASES: &[&str] = &["cgroup_sockopt"];
const CGROUP_SOCK_ADDR_SPEC_ALIASES: &[&str] = &["cgroup_sock_addr"];
const STRUCT_OPS_SPEC_ALIASES: &[&str] = &["struct_ops"];
const DEFAULT_PROBE_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::StackTraces,
    ProgramCapability::ReadUserString,
    ProgramCapability::ReadKernelString,
    ProgramCapability::KfuncCalls,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];
const DEFAULT_XDP_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];

const KPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Kprobe,
    canonical_prefix: "kprobe",
    spec_aliases: KPROBE_SPEC_ALIASES,
    section_prefix: "kprobe",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Kprobe,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::SymbolOnly),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const KRETPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Kretprobe,
    canonical_prefix: "kretprobe",
    spec_aliases: KRETPROBE_SPEC_ALIASES,
    section_prefix: "kretprobe",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Kretprobe,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::SymbolOnly),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const FENTRY_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Fentry,
    canonical_prefix: "fentry",
    spec_aliases: FENTRY_SPEC_ALIASES,
    section_prefix: "fentry",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Fentry,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::FentryTrampoline),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const FEXIT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Fexit,
    canonical_prefix: "fexit",
    spec_aliases: FEXIT_SPEC_ALIASES,
    section_prefix: "fexit",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Fexit,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::FexitTrampoline),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::Trampoline,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const TRACEPOINT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Tracepoint,
    canonical_prefix: "tracepoint",
    spec_aliases: TRACEPOINT_SPEC_ALIASES,
    section_prefix: "tracepoint",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Tracepoint,
    target_kind: ProgramTargetKind::Tracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: true,
    is_userspace: false,
};

const RAW_TRACEPOINT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::RawTracepoint,
    canonical_prefix: "raw_tracepoint",
    spec_aliases: RAW_TRACEPOINT_SPEC_ALIASES,
    section_prefix: "raw_tracepoint",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::RawTracepoint,
    target_kind: ProgramTargetKind::RawTracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const UPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Uprobe,
    canonical_prefix: "uprobe",
    spec_aliases: UPROBE_SPEC_ALIASES,
    section_prefix: "uprobe",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Uprobe,
    target_kind: ProgramTargetKind::UserFunction,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: true,
};

const URETPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Uretprobe,
    canonical_prefix: "uretprobe",
    spec_aliases: URETPROBE_SPEC_ALIASES,
    section_prefix: "uretprobe",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Uretprobe,
    target_kind: ProgramTargetKind::UserFunction,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: true,
};

const LSM_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Lsm,
    canonical_prefix: "lsm",
    spec_aliases: LSM_SPEC_ALIASES,
    section_prefix: "lsm",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::Lsm,
    target_kind: ProgramTargetKind::LsmHook,
    kernel_target_validation: Some(KernelTargetValidationKind::LsmHook),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const XDP_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Xdp,
    canonical_prefix: "xdp",
    spec_aliases: XDP_SPEC_ALIASES,
    section_prefix: "xdp",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::Xdp,
    target_kind: ProgramTargetKind::NetworkInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::XdpMd),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: true,
    supports_egress_ifindex_ctx_field: true,
    supports_xdp_md_ctx_fields: true,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const PERF_EVENT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::PerfEvent,
    canonical_prefix: "perf_event",
    spec_aliases: PERF_EVENT_SPEC_ALIASES,
    section_prefix: "perf_event",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::PerfEvent,
    target_kind: ProgramTargetKind::PerfEventTarget,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: true,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: true,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SOCKET_FILTER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SocketFilter,
    canonical_prefix: "socket_filter",
    spec_aliases: SOCKET_FILTER_SPEC_ALIASES,
    section_prefix: "socket",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SocketFilter,
    target_kind: ProgramTargetKind::SocketFilterTarget,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkBuff),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_DEVICE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupDevice,
    canonical_prefix: "cgroup_device",
    spec_aliases: CGROUP_DEVICE_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupDevice,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SK_LOOKUP_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkLookup,
    canonical_prefix: "sk_lookup",
    spec_aliases: SK_LOOKUP_SPEC_ALIASES,
    section_prefix: "sk_lookup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SkLookup,
    target_kind: ProgramTargetKind::NetworkNamespacePath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SK_MSG_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkMsg,
    canonical_prefix: "sk_msg",
    spec_aliases: SK_MSG_SPEC_ALIASES,
    section_prefix: "sk_msg",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SkMsg,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkMsg),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SK_SKB_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkSkb,
    canonical_prefix: "sk_skb",
    spec_aliases: SK_SKB_SPEC_ALIASES,
    section_prefix: "sk_skb/stream_verdict",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SkSkb,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkBuff),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SK_SKB_PARSER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkSkbParser,
    canonical_prefix: "sk_skb_parser",
    spec_aliases: SK_SKB_PARSER_SPEC_ALIASES,
    section_prefix: "sk_skb/stream_parser",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SkSkbParser,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkBuff),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const SOCK_OPS_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SockOps,
    canonical_prefix: "sock_ops",
    spec_aliases: SOCK_OPS_SPEC_ALIASES,
    section_prefix: "sockops",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::SockOps,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const TC_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Tc,
    canonical_prefix: "tc",
    spec_aliases: TC_SPEC_ALIASES,
    section_prefix: "classifier",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::Tc,
    target_kind: ProgramTargetKind::TrafficControlInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkBuff),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_SKB_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSkb,
    canonical_prefix: "cgroup_skb",
    spec_aliases: CGROUP_SKB_SPEC_ALIASES,
    section_prefix: "cgroup_skb",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupSkb,
    target_kind: ProgramTargetKind::CgroupPathAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: Some(PacketContextKind::SkBuff),
    supports_packet_len_ctx_field: true,
    supports_packet_data_ctx_fields: true,
    supports_ingress_ifindex_ctx_field: true,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_SOCK_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSock,
    canonical_prefix: "cgroup_sock",
    spec_aliases: CGROUP_SOCK_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupSock,
    target_kind: ProgramTargetKind::CgroupPathSockAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_SYSCTL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSysctl,
    canonical_prefix: "cgroup_sysctl",
    spec_aliases: CGROUP_SYSCTL_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupSysctl,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_SOCKOPT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSockopt,
    canonical_prefix: "cgroup_sockopt",
    spec_aliases: CGROUP_SOCKOPT_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupSockopt,
    target_kind: ProgramTargetKind::CgroupPathSockoptAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const CGROUP_SOCK_ADDR_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSockAddr,
    canonical_prefix: "cgroup_sock_addr",
    spec_aliases: CGROUP_SOCK_ADDR_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    attach_kind: ProgramAttachKind::CgroupSockAddr,
    target_kind: ProgramTargetKind::CgroupPathSockAddrAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: true,
    supports_timestamp_ctx_field: true,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const STRUCT_OPS_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::KfuncCalls,
    ProgramCapability::TailCalls,
];

const STRUCT_OPS_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::StructOps,
    canonical_prefix: "struct_ops",
    spec_aliases: STRUCT_OPS_SPEC_ALIASES,
    section_prefix: "struct_ops",
    section_uses_target: true,
    attach_kind: ProgramAttachKind::StructOps,
    target_kind: ProgramTargetKind::StructOpsCallback,
    kernel_target_validation: None,
    supported_capabilities: STRUCT_OPS_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
    supports_task_ctx_fields: false,
    supports_cpu_ctx_field: false,
    supports_timestamp_ctx_field: false,
    packet_context_kind: None,
    supports_packet_len_ctx_field: false,
    supports_packet_data_ctx_fields: false,
    supports_ingress_ifindex_ctx_field: false,
    supports_rx_queue_index_ctx_field: false,
    supports_egress_ifindex_ctx_field: false,
    supports_xdp_md_ctx_fields: false,
    supports_stack_ctx_fields: false,
    supports_tracepoint_fields: false,
    is_userspace: false,
};

const PROGRAM_SPEC_PREFIXES: &[&str] = &[
    "kprobe",
    "kretprobe",
    "fentry",
    "fexit",
    "lsm",
    "tracepoint",
    "raw_tracepoint",
    "raw_tp",
    "uprobe",
    "uretprobe",
    "perf_event",
    "xdp",
    "socket_filter",
    "sock_filter",
    "cgroup_device",
    "sk_lookup",
    "sk_msg",
    "sk_skb",
    "sk_skb_parser",
    "sock_ops",
    "sockops",
    "tc",
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_sysctl",
    "cgroup_sockopt",
    "cgroup_sock_addr",
    "struct_ops",
];

const PROGRAM_INTRINSICS: &[ProgramIntrinsic] = &[
    ProgramIntrinsic::Emit,
    ProgramIntrinsic::Count,
    ProgramIntrinsic::Histogram,
    ProgramIntrinsic::StartTimer,
    ProgramIntrinsic::StopTimer,
    ProgramIntrinsic::ReadStr,
    ProgramIntrinsic::ReadKernelStr,
    ProgramIntrinsic::KfuncCall,
    ProgramIntrinsic::GlobalDefine,
    ProgramIntrinsic::GlobalGet,
    ProgramIntrinsic::GlobalSet,
    ProgramIntrinsic::MapGet,
    ProgramIntrinsic::MapPut,
    ProgramIntrinsic::MapDelete,
];

/// One program section within an eBPF ELF object.
#[derive(Debug, Clone)]
pub struct EbpfProgramSection {
    /// Optional explicit ELF section name. When absent, derive from `prog_type` and `target`.
    pub section_name_override: Option<String>,
    /// The program type
    pub prog_type: EbpfProgramType,
    /// The target function/tracepoint name
    pub target: String,
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
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
    /// Optional schema for runtime decoding of `bytes_counters` keys
    pub bytes_counter_key_schema: Option<CounterKeySchema>,
    /// Optional typed generic map value schemas keyed by map identity
    pub generic_map_value_types: HashMap<MapRef, MirType>,
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
    match value_type_name {
        // sched_ext documents these callbacks as sleepable and they must be
        // emitted under `struct_ops.s/...` rather than plain `struct_ops/...`.
        "sched_ext_ops" => matches!(
            callback_name,
            "init_task"
                | "cgroup_init"
                | "cgroup_exit"
                | "cgroup_prep_move"
                | "cpu_online"
                | "cpu_offline"
                | "init"
                | "exit"
        ),
        _ => false,
    }
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
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
    /// Optional schema for runtime decoding of `bytes_counters` keys
    pub bytes_counter_key_schema: Option<CounterKeySchema>,
    /// Optional typed generic map value schemas keyed by map identity
    pub generic_map_value_types: HashMap<MapRef, MirType>,
}

#[cfg(test)]
mod tests;
