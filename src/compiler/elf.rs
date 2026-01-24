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

/// BPF map types (subset of types we might use)
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
#[allow(dead_code)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    PerfEventArray = 4,
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
        Self {
            map_type: BpfMapType::Hash as u32,
            key_size: 8,        // sizeof(i64) - the key to count
            value_size: 8,      // sizeof(i64) - the count
            max_entries: 10240, // Maximum number of unique keys
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a hash map for counting with string keys (key: 16 bytes comm, value: i64)
    ///
    /// Used when counting by process name ($ctx.comm) instead of numeric keys.
    pub fn string_counter_hash() -> Self {
        Self {
            map_type: BpfMapType::Hash as u32,
            key_size: 16,       // sizeof(comm) - 16-byte process name
            value_size: 8,      // sizeof(i64) - the count
            max_entries: 10240, // Maximum number of unique keys
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a hash map for storing timestamps (key: i64 TID, value: i64 timestamp)
    pub fn timestamp_hash() -> Self {
        Self {
            map_type: BpfMapType::Hash as u32,
            key_size: 8,        // sizeof(i64) - thread ID
            value_size: 8,      // sizeof(i64) - timestamp in nanoseconds
            max_entries: 10240, // Maximum concurrent traced threads
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
    }

    /// Create a hash map for histogram buckets (key: i64 bucket, value: i64 count)
    pub fn histogram_hash() -> Self {
        Self {
            map_type: BpfMapType::Hash as u32,
            key_size: 8,     // sizeof(i64) - bucket index (log2 of value)
            value_size: 8,   // sizeof(i64) - count
            max_entries: 64, // 64 buckets covers 0 to 2^63
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
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
#[derive(Debug, Clone)]
pub struct SchemaField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: BpfFieldType,
    /// Byte offset within the event struct
    pub offset: usize,
}

/// Schema describing the structure of events emitted by an eBPF program
#[derive(Debug, Clone)]
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
    /// License string (must be GPL-compatible for most helpers)
    pub license: String,
    /// Maps used by this program
    pub maps: Vec<EbpfMap>,
    /// Relocations for map references
    pub relocations: Vec<MapRelocation>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
}

impl EbpfProgram {
    /// Create a new eBPF program from a builder
    pub fn new(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        builder: EbpfBuilder,
    ) -> Self {
        Self {
            prog_type,
            target: target.into(),
            name: name.into(),
            bytecode: builder.build(),
            license: "GPL".to_string(),
            maps: Vec::new(),
            relocations: Vec::new(),
            event_schema: None,
        }
    }

    /// Create a new eBPF program from raw bytecode
    pub fn from_bytecode(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        bytecode: Vec<u8>,
    ) -> Self {
        Self {
            prog_type,
            target: target.into(),
            name: name.into(),
            bytecode,
            license: "GPL".to_string(),
            maps: Vec::new(),
            relocations: Vec::new(),
            event_schema: None,
        }
    }

    /// Create a new eBPF program with maps and relocations
    pub fn with_maps(
        prog_type: EbpfProgramType,
        target: impl Into<String>,
        name: impl Into<String>,
        bytecode: Vec<u8>,
        maps: Vec<EbpfMap>,
        relocations: Vec<MapRelocation>,
        event_schema: Option<EventSchema>,
    ) -> Self {
        Self {
            prog_type,
            target: target.into(),
            name: name.into(),
            bytecode,
            license: "GPL".to_string(),
            maps,
            relocations,
            event_schema,
        }
    }

    /// Enable pinning on all maps in this program
    ///
    /// When pinning is enabled, maps will be pinned to the BPF filesystem
    /// and can be shared between separate eBPF programs. This is required
    /// for latency measurement using start-timer/stop-timer across
    /// kprobe/kretprobe pairs.
    pub fn with_pinning(mut self) -> Self {
        for map in &mut self.maps {
            map.def.pinning = BpfPinningType::ByName;
        }
        self
    }

    /// Create a simple "hello world" kprobe that just returns 0
    ///
    /// This is useful for testing the loading infrastructure.
    pub fn hello_world(target: impl Into<String>) -> Self {
        use super::instruction::{EbpfInsn, EbpfReg};

        let mut builder = EbpfBuilder::new();

        // Simple program: mov r0, 0; exit
        // This just returns 0, which is a valid kprobe return
        builder
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
            .push(EbpfInsn::exit());

        Self::new(EbpfProgramType::Kprobe, target, "hello_world", builder)
    }

    /// Get the ELF section name for this program
    pub fn section_name(&self) -> String {
        format!("{}/{}", self.prog_type.section_prefix(), self.target)
    }

    /// Generate an ELF object file containing this program
    pub fn to_elf(&self) -> Result<Vec<u8>, CompileError> {
        use std::collections::HashMap;

        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

        // Track map symbol IDs for relocations
        let mut map_symbols: HashMap<String, object::write::SymbolId> = HashMap::new();

        // Add maps section if we have any maps (using BTF-defined format)
        if !self.maps.is_empty() {
            let maps_section_id = obj.add_section(vec![], b".maps".to_vec(), SectionKind::Data);

            let maps_section = obj.section_mut(maps_section_id);
            maps_section.flags = SectionFlags::Elf {
                sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_WRITE as u64,
            };

            // BTF-defined maps use a struct with pointer-sized fields (40 bytes per map)
            // Fields: type, key_size, value_size, max_entries, pinning (5 pointers * 8 bytes)
            let btf_map_size = 40u64;

            for map in &self.maps {
                // BTF-defined map data is all zeros (values come from BTF type metadata)
                let map_data = [0u8; 40];
                let map_offset = obj.append_section_data(maps_section_id, &map_data, 8);

                // Add a symbol for this map (must be GLOBAL with DEFAULT visibility for libbpf/Aya)
                let sym_id = obj.add_symbol(Symbol {
                    name: map.name.as_bytes().to_vec(),
                    value: map_offset,
                    size: btf_map_size,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Linkage, // GLOBAL binding
                    weak: false,
                    section: SymbolSection::Section(maps_section_id),
                    flags: SymbolFlags::Elf {
                        st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_OBJECT,
                        st_other: object::elf::STV_DEFAULT,
                    },
                });
                map_symbols.insert(map.name.clone(), sym_id);
            }

            // Generate BTF for BTF-defined maps
            let btf_data = self.generate_btf();
            let btf_section_id = obj.add_section(vec![], b".BTF".to_vec(), SectionKind::Metadata);
            obj.append_section_data(btf_section_id, &btf_data, 1);
        }

        // Create the program section (e.g., "kprobe/sys_clone")
        let section_name = self.section_name();
        let section_id = obj.add_section(
            vec![], // No segment
            section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );

        // Set section flags for eBPF
        let section = obj.section_mut(section_id);
        section.flags = SectionFlags::Elf {
            sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_EXECINSTR as u64,
        };

        // Add the bytecode to the section
        let offset = obj.append_section_data(section_id, &self.bytecode, 8);

        // Add a symbol for the program (must be GLOBAL with DEFAULT visibility for libbpf/Aya)
        obj.add_symbol(Symbol {
            name: self.name.as_bytes().to_vec(),
            value: offset,
            size: self.bytecode.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage, // GLOBAL binding
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::Elf {
                st_info: (object::elf::STB_GLOBAL << 4) | object::elf::STT_FUNC,
                st_other: object::elf::STV_DEFAULT,
            },
        });

        // Add relocations for map references
        for reloc in &self.relocations {
            if let Some(&sym_id) = map_symbols.get(&reloc.map_name) {
                // BPF uses R_BPF_64_64 relocation type (value = 1)
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: (offset + reloc.insn_offset as u64),
                        symbol: sym_id,
                        addend: 0,
                        flags: RelocationFlags::Elf {
                            r_type: 1, // R_BPF_64_64
                        },
                    },
                )
                .map_err(|e| CompileError::ElfError(e.to_string()))?;
            }
        }

        // Add the license section
        let license_section_id = obj.add_section(vec![], b"license".to_vec(), SectionKind::Data);

        // License must be null-terminated
        let mut license_data = self.license.as_bytes().to_vec();
        license_data.push(0);
        obj.append_section_data(license_section_id, &license_data, 1);

        // Write the ELF file
        obj.write()
            .map_err(|e| CompileError::ElfError(e.to_string()))
    }

    /// Check if this program uses any maps (and thus needs perf buffer support)
    pub fn has_maps(&self) -> bool {
        !self.maps.is_empty()
    }

    /// Generate BTF (BPF Type Format) metadata for BTF-defined maps
    ///
    /// This implements the libbpf BTF-defined map format where map attributes
    /// are encoded using the __uint macro pattern: int (*name)[value]
    ///
    /// The BTF represents:
    /// - An anonymous struct with pointer members
    /// - Each pointer points to an array whose size encodes the attribute value
    /// - e.g., __uint(type, 4) becomes: PTR -> ARRAY[4] -> INT
    fn generate_btf(&self) -> Vec<u8> {
        use super::btf::BtfVarLinkage;

        let mut btf = BtfBuilder::new();

        // Add base int type (used as array element and index type)
        let int_type = btf.add_int("int", 4, true);

        // Track variable type IDs and offsets for datasec
        let mut vars: Vec<(u32, u32, u32)> = Vec::new();
        let mut offset = 0u32;

        for map in &self.maps {
            // Create __uint types for each map attribute
            // __uint(name, val) expands to: int (*name)[val]

            // type field: __uint(type, map_type_value)
            let type_ptr = btf.add_uint_type(int_type, map.def.map_type);

            // key_size field: __uint(key_size, size_value)
            let key_size_ptr = btf.add_uint_type(int_type, map.def.key_size);

            // value_size field: __uint(value_size, size_value)
            let value_size_ptr = btf.add_uint_type(int_type, map.def.value_size);

            // max_entries field: __uint(max_entries, count)
            // Note: 0 means auto-size (e.g., num_cpus for perf event arrays)
            let max_entries_ptr = btf.add_uint_type(int_type, map.def.max_entries);

            // pinning field: __uint(pinning, LIBBPF_PIN_BY_NAME) for shared maps
            let pinning_ptr = btf.add_uint_type(int_type, map.def.pinning as u32);

            // Create the anonymous map struct with pointer-sized members
            let struct_type = btf.add_btf_map_struct(&[
                ("type", type_ptr),
                ("key_size", key_size_ptr),
                ("value_size", value_size_ptr),
                ("max_entries", max_entries_ptr),
                ("pinning", pinning_ptr),
            ]);

            // Add a variable for this map
            let var_type = btf.add_var(&map.name, struct_type, BtfVarLinkage::GlobalAlloc);

            // Size of BTF-defined map struct (5 pointers * 8 bytes = 40 bytes)
            let map_size = 40u32;
            vars.push((var_type, offset, map_size));
            offset += map_size;
        }

        // Add datasec for .maps section
        btf.add_datasec(".maps", &vars);

        btf.build()
    }

    /// Generate map section data for BTF-defined maps
    ///
    /// For BTF-defined maps, the .maps section contains the struct with
    /// pointer-sized fields (all zeros since values are in BTF type metadata).
    #[allow(dead_code)]
    fn generate_btf_map_data(&self) -> Vec<u8> {
        let mut data = Vec::new();

        for _map in &self.maps {
            // BTF-defined map struct has 5 pointer fields = 40 bytes
            // All zeros - actual values are encoded in BTF type metadata
            data.extend_from_slice(&[0u8; 40]);
        }

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world_creation() {
        let prog = EbpfProgram::hello_world("sys_clone");
        assert_eq!(prog.target, "sys_clone");
        assert_eq!(prog.name, "hello_world");
        assert_eq!(prog.bytecode.len(), 16); // 2 instructions * 8 bytes
    }

    #[test]
    fn test_section_name() {
        let prog = EbpfProgram::hello_world("sys_clone");
        assert_eq!(prog.section_name(), "kprobe/sys_clone");
    }

    #[test]
    fn test_elf_generation() {
        let prog = EbpfProgram::hello_world("sys_clone");
        let elf = prog.to_elf().expect("Failed to generate ELF");

        // Should start with ELF magic number
        assert_eq!(&elf[0..4], b"\x7fELF");

        // Should be little-endian (byte 5 = 1)
        assert_eq!(elf[5], 1);

        // Should be BPF architecture
        // (This is in the e_machine field at offset 18-19)
    }
}
