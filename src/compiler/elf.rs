//! Minimal ELF generation for eBPF programs
//!
//! This module creates ELF object files that can be loaded by Aya or libbpf.
//! The ELF format includes:
//! - A section with the eBPF bytecode (named for the program type, e.g., "kprobe/func")
//! - A "license" section containing the license string (required for most helpers)
//! - Optional ".maps" section for BPF map definitions

use std::collections::HashMap;

use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionFlags, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

use super::CompileError;
use super::btf::BtfBuilder;
use super::context_schema::{resolve_program_ctx_field_name, resolve_untyped_ctx_field_name};
use super::instruction::BpfHelper;
use super::instruction::EbpfBuilder;
use super::mir::{
    BYTES_COUNTER_MAP_NAME, BitfieldInfo, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapRef, MirType, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME,
    TIMESTAMP_MAP_NAME, USTACK_MAP_NAME,
};

mod probe_context;
mod program_impl;
mod program_types;

use program_types::*;
pub use program_types::{ProgramContextFamily, ProgramTypeInfo};

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
    Queue = 22,
    Stack = 23,
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
    /// BTF-enabled raw tracepoint (`tp_btf`)
    TpBtf,
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
            EbpfProgramType::Fentry => &FENTRY_INFO,
            EbpfProgramType::Fexit => &FEXIT_INFO,
            EbpfProgramType::TpBtf => &TP_BTF_INFO,
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
            EbpfProgramType::LircMode2 => &LIRC_MODE2_INFO,
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
            EbpfProgramType::TpBtf,
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
            EbpfProgramType::LircMode2,
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

    pub fn uses_raw_tracepoint_args(&self) -> bool {
        matches!(self.arg_access(), ProgramValueAccess::RawTracepoint)
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

    pub(crate) fn return_action_alias(&self, alias: &str) -> Option<ProgramReturnAlias> {
        let alias = alias.to_ascii_lowercase();

        match self {
            EbpfProgramType::Xdp => match alias.as_str() {
                "abort" | "aborted" => Some(ProgramReturnAlias::Const(0)),
                "drop" => Some(ProgramReturnAlias::Const(1)),
                "pass" => Some(ProgramReturnAlias::Const(2)),
                "tx" => Some(ProgramReturnAlias::Const(3)),
                "redirect" => Some(ProgramReturnAlias::Const(4)),
                _ => None,
            },
            EbpfProgramType::SocketFilter => match alias.as_str() {
                "deny" | "drop" | "reject" => Some(ProgramReturnAlias::Const(0)),
                "allow" | "accept" | "permit" | "keep" | "pass" => {
                    Some(ProgramReturnAlias::PacketLen)
                }
                _ => None,
            },
            EbpfProgramType::Tc => match alias.as_str() {
                "ok" => Some(ProgramReturnAlias::Const(0)),
                "reclassify" => Some(ProgramReturnAlias::Const(1)),
                "shot" | "drop" => Some(ProgramReturnAlias::Const(2)),
                "pipe" => Some(ProgramReturnAlias::Const(3)),
                "stolen" => Some(ProgramReturnAlias::Const(4)),
                "queued" => Some(ProgramReturnAlias::Const(5)),
                "repeat" => Some(ProgramReturnAlias::Const(6)),
                "redirect" => Some(ProgramReturnAlias::Const(7)),
                "trap" => Some(ProgramReturnAlias::Const(8)),
                _ => None,
            },
            EbpfProgramType::CgroupSkb
            | EbpfProgramType::CgroupDevice
            | EbpfProgramType::CgroupSock
            | EbpfProgramType::CgroupSysctl
            | EbpfProgramType::CgroupSockopt
            | EbpfProgramType::CgroupSockAddr
            | EbpfProgramType::SkLookup
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkMsg => match alias.as_str() {
                "deny" | "drop" | "reject" => Some(ProgramReturnAlias::Const(0)),
                "allow" | "pass" | "accept" | "permit" => Some(ProgramReturnAlias::Const(1)),
                _ => None,
            },
            _ => None,
        }
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

    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel
                if *self != EbpfProgramType::LircMode2 =>
            {
                Some(format!(
                    "helper '{}' is only valid in lirc_mode2 programs",
                    helper.name()
                ))
            }
            BpfHelper::Redirect if !matches!(self, EbpfProgramType::Xdp | EbpfProgramType::Tc) => {
                Some(format!(
                    "helper '{}' is only valid in xdp and tc programs",
                    helper.name()
                ))
            }
            BpfHelper::RedirectNeigh if *self != EbpfProgramType::Tc => Some(format!(
                "helper '{}' is only valid in tc programs",
                helper.name()
            )),
            BpfHelper::MsgApplyBytes
            | BpfHelper::MsgCorkBytes
            | BpfHelper::MsgPullData
            | BpfHelper::MsgPushData
            | BpfHelper::MsgPopData
                if *self != EbpfProgramType::SkMsg =>
            {
                Some(format!(
                    "helper '{}' is only valid in sk_msg programs",
                    helper.name()
                ))
            }
            BpfHelper::SetSockOpt | BpfHelper::GetSockOpt
                if !matches!(
                    self,
                    EbpfProgramType::SockOps | EbpfProgramType::CgroupSockAddr
                ) =>
            {
                Some(format!(
                    "helper '{}' is only valid in sock_ops and cgroup_sock_addr programs",
                    helper.name()
                ))
            }
            BpfHelper::Bind if *self != EbpfProgramType::CgroupSockAddr => Some(format!(
                "helper '{}' is only valid in cgroup_sock_addr programs",
                helper.name()
            )),
            BpfHelper::SockOpsCbFlagsSet if *self != EbpfProgramType::SockOps => Some(format!(
                "helper '{}' is only valid in sock_ops programs",
                helper.name()
            )),
            BpfHelper::SysctlGetName
            | BpfHelper::SysctlGetCurrentValue
            | BpfHelper::SysctlGetNewValue
            | BpfHelper::SysctlSetNewValue
                if *self != EbpfProgramType::CgroupSysctl =>
            {
                Some(format!(
                    "helper '{}' is only valid in cgroup_sysctl programs",
                    helper.name()
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        match (helper, self) {
            (BpfHelper::Redirect, EbpfProgramType::Xdp) => {
                Some((1, "helper 'bpf_redirect' requires arg1 = 0 in xdp programs"))
            }
            _ => None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolve_ctx_field_name(&self, field_name: &str) -> Result<CtxField, String> {
        resolve_program_ctx_field_name(*self, field_name)
    }

    pub(crate) fn resolve_untyped_ctx_field_name(field_name: &str) -> Result<CtxField, String> {
        resolve_untyped_ctx_field_name(field_name)
    }

    pub fn supports_skb_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::SkBuffPacket)
    }

    pub fn supports_socket_ref_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::CgroupSockopt
                | EbpfProgramType::SkLookup
                | EbpfProgramType::SkMsg
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_socket_common_ctx_fields(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkLookup
                | EbpfProgramType::SkMsg
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_socket_tuple_ctx_fields(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SkLookup
                | EbpfProgramType::SkMsg
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_sock_type_protocol_ctx_fields(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkLookup
        )
    }

    pub fn supports_sock_mark_priority_ctx_fields(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::CgroupSock
                | EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
        )
    }

    pub fn supports_socket_cookie_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_socket_uid_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::SkSkb
        )
    }

    pub fn supports_netns_cookie_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockopt
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkMsg
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_lookup_cookie_ctx_field(&self) -> bool {
        matches!(self, EbpfProgramType::SkLookup)
    }

    pub fn supports_cgroup_sock_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSock)
    }

    pub fn supports_cgroup_sock_addr_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSockAddr)
    }

    pub fn supports_cgroup_sockopt_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSockopt)
    }

    pub fn supports_cgroup_sysctl_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSysctl)
    }

    pub fn supports_device_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupDevice)
    }

    pub fn supports_sock_ops_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::SockOps)
    }

    pub fn supports_lirc_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::LircMode2)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramAttachKind {
    Kprobe,
    Kretprobe,
    Fentry,
    Fexit,
    TpBtf,
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
    LircMode2,
    StructOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramTargetKind {
    KernelFunction,
    BtfTracepoint,
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
    LircDevicePath,
    StructOpsCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketContextKind {
    XdpMd,
    SkBuff,
    SkMsg,
    SockOps,
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
    RawTracepoint,
    Trampoline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProgramReturnAlias {
    Const(i64),
    PacketLen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SocketContextLayout {
    SockAddr,
    CgroupSock,
    CgroupSockopt,
    SkLookup,
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
    HelperCall,
    KfuncCall,
    GlobalDefine,
    GlobalGet,
    GlobalSet,
    MapGet,
    MapPut,
    MapDelete,
    MapPush,
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
            ProgramIntrinsic::HelperCall => "helper-call",
            ProgramIntrinsic::KfuncCall => "kfunc-call",
            ProgramIntrinsic::GlobalDefine => "global-define",
            ProgramIntrinsic::GlobalGet => "global-get",
            ProgramIntrinsic::GlobalSet => "global-set",
            ProgramIntrinsic::MapGet => "map-get",
            ProgramIntrinsic::MapPut => "map-put",
            ProgramIntrinsic::MapDelete => "map-delete",
            ProgramIntrinsic::MapPush => "map-push",
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
            "helper-call" => Some(ProgramIntrinsic::HelperCall),
            "kfunc-call" => Some(ProgramIntrinsic::KfuncCall),
            "global-define" => Some(ProgramIntrinsic::GlobalDefine),
            "global-get" => Some(ProgramIntrinsic::GlobalGet),
            "global-set" => Some(ProgramIntrinsic::GlobalSet),
            "map-get" => Some(ProgramIntrinsic::MapGet),
            "map-put" => Some(ProgramIntrinsic::MapPut),
            "map-delete" => Some(ProgramIntrinsic::MapDelete),
            "map-push" => Some(ProgramIntrinsic::MapPush),
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
            ProgramIntrinsic::HelperCall => ProgramCapability::HelperCalls,
            ProgramIntrinsic::KfuncCall => ProgramCapability::KfuncCalls,
            ProgramIntrinsic::GlobalDefine
            | ProgramIntrinsic::GlobalGet
            | ProgramIntrinsic::GlobalSet => ProgramCapability::Globals,
            ProgramIntrinsic::MapGet
            | ProgramIntrinsic::MapPut
            | ProgramIntrinsic::MapDelete
            | ProgramIntrinsic::MapPush => ProgramCapability::GenericMaps,
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
    /// Optional logical semantics for generic map values with richer layouts
    pub generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
}

#[cfg(test)]
mod tests;
