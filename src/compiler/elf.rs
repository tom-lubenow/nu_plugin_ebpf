//! Minimal ELF generation for eBPF programs
//!
//! This module creates ELF object files that can be loaded by Aya or libbpf.
//! The ELF format includes:
//! - A section with the eBPF bytecode (named for the program type, e.g., "kprobe/func")
//! - A "license" section containing the license string (required for most helpers)
//! - Optional ".maps" section for BPF map definitions

use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionFlags, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

use super::CompileError;
use super::btf::BtfBuilder;
use super::instruction::EbpfBuilder;

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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct EbpfMap {
    pub name: String,
    pub def: BpfMapDef,
}

/// Location in bytecode that needs a map reference
#[derive(Debug, Clone)]
pub struct MapRelocation {
    /// Offset in bytecode (in bytes) where the LD_DW_IMM instruction is
    pub insn_offset: usize,
    /// Name of the map to reference
    pub map_name: String,
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
    /// 64-bit integer (8 bytes)
    Int,
    /// Short string from bpf-comm (16 bytes, TASK_COMM_LEN)
    Comm,
    /// Long string from bpf-read-str (128 bytes max)
    String,
}

impl BpfFieldType {
    /// Get the size in bytes for this field type
    pub fn size(&self) -> usize {
        match self {
            BpfFieldType::Int => 8,
            BpfFieldType::Comm => 16,
            BpfFieldType::String => 128,
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
    /// Byte offset within the event struct
    pub offset: usize,
}

/// Schema describing the structure of events emitted by an eBPF program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSchema {
    /// Fields in the event, in order
    pub fields: Vec<SchemaField>,
    /// Total size of the event struct in bytes
    pub total_size: usize,
}

/// eBPF program type
#[derive(Debug, Clone, Copy)]
pub enum EbpfProgramType {
    /// Kernel probe (kprobe)
    Kprobe,
    /// Kernel return probe (kretprobe)
    Kretprobe,
    /// Tracepoint
    Tracepoint,
    /// Raw tracepoint
    RawTracepoint,
    /// User-space probe (uprobe)
    Uprobe,
    /// User-space return probe (uretprobe)
    Uretprobe,
}

impl EbpfProgramType {
    /// Get the ELF section name prefix for this program type
    pub fn section_prefix(&self) -> &'static str {
        match self {
            EbpfProgramType::Kprobe => "kprobe",
            EbpfProgramType::Kretprobe => "kretprobe",
            EbpfProgramType::Tracepoint => "tracepoint",
            EbpfProgramType::RawTracepoint => "raw_tracepoint",
            EbpfProgramType::Uprobe => "uprobe",
            EbpfProgramType::Uretprobe => "uretprobe",
        }
    }

    /// Returns true if this is a return probe (kretprobe or uretprobe)
    pub fn is_return_probe(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::Kretprobe | EbpfProgramType::Uretprobe
        )
    }

    /// Returns true if this is a userspace probe (uprobe or uretprobe)
    pub fn is_userspace(&self) -> bool {
        matches!(self, EbpfProgramType::Uprobe | EbpfProgramType::Uretprobe)
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
    /// For tracepoints: the category (e.g., "syscalls")
    pub tracepoint_category: Option<String>,
}

impl ProbeContext {
    /// Create a new probe context
    pub fn new(probe_type: EbpfProgramType, target: impl Into<String>) -> Self {
        let target = target.into();
        let tracepoint_category = if matches!(probe_type, EbpfProgramType::Tracepoint) {
            // Parse "category/name" format
            target.split('/').next().map(|s| s.to_string())
        } else {
            None
        };

        Self {
            probe_type,
            target,
            tracepoint_category,
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
            tracepoint_category: None,
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
        matches!(
            self.probe_type,
            EbpfProgramType::Tracepoint | EbpfProgramType::RawTracepoint
        )
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
}

/// A complete eBPF program ready for loading
#[derive(Debug)]
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
    /// Relocations for map references
    pub relocations: Vec<MapRelocation>,
    /// Subfunction symbols for BPF-to-BPF calls
    pub subfunctions: Vec<SubfunctionSymbol>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
}

#[cfg(test)]
mod tests;
