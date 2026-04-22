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
use super::instruction::BpfHelper;
use super::instruction::EbpfBuilder;
use super::mir::CtxStoreTarget;
use super::mir::{
    BYTES_COUNTER_MAP_NAME, BitfieldInfo, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapRef, MirType, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME,
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
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPerCpuHash = 10,
    LpmTrie = 11,
    DevMap = 14,
    SockMap = 15,
    CpuMap = 16,
    XskMap = 17,
    SockHash = 18,
    ReuseportSockArray = 20,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevMapHash = 25,
    RingBuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    CgrpStorage = 32,
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

struct ProgramBtfCallableSurfaceSpec {
    program_types: &'static [EbpfProgramType],
    surface: ProgramBtfCallableSurface,
}

const FUNCTION_TRAMPOLINE_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
];

const TP_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::TpBtf];

const LSM_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Lsm, EbpfProgramType::LsmCgroup];

const STRUCT_OPS_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::StructOps];

const BTF_CALLABLE_SURFACES: &[ProgramBtfCallableSurfaceSpec] = &[
    ProgramBtfCallableSurfaceSpec {
        program_types: FUNCTION_TRAMPOLINE_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::FunctionTrampoline,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: TP_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::TpBtf,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: LSM_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::LsmHook,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: STRUCT_OPS_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::StructOpsCallback,
    },
];

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

    /// Get the underlying kernel UAPI `BPF_PROG_TYPE_*` enum name.
    pub fn kernel_prog_type(&self) -> &'static str {
        self.info().kernel_prog_type
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
        self.arg_access().is_trampoline() || self.retval_access().is_trampoline()
    }

    pub fn btf_callable_surface(&self) -> Option<ProgramBtfCallableSurface> {
        BTF_CALLABLE_SURFACES
            .iter()
            .find(|surface| surface.program_types.contains(self))
            .map(|surface| surface.surface)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramTargetKind {
    KernelFunction,
    KernelFunctionPattern,
    KernelSyscall,
    BtfTracepoint,
    LsmHook,
    ExtensionFunction,
    SyscallProgram,
    Tracepoint,
    RawTracepoint,
    UserFunction,
    UserFunctionPattern,
    NetworkInterface,
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
    StructOpsCallback,
}

impl ProgramTargetKind {
    pub fn is_userspace_function(self) -> bool {
        matches!(self, Self::UserFunction | Self::UserFunctionPattern)
    }

    pub fn is_tracepoint(self) -> bool {
        matches!(self, Self::Tracepoint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramBtfCallableSurface {
    FunctionTrampoline,
    TpBtf,
    LsmHook,
    StructOpsCallback,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramValueAccess {
    None,
    PtRegs,
    RawTracepoint,
    Trampoline,
}

impl ProgramValueAccess {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProgramReturnAlias {
    Const(i64),
    PacketLen,
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
    MapGet,
    MapPut,
    MapDelete,
    MapContains,
    MapPush,
    MapPeek,
    MapPop,
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
