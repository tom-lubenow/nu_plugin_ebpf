//! eBPF program loading and management
//!
//! This module handles loading eBPF programs into the kernel using Aya,
//! and managing active probes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya::maps::{HashMap as AyaHashMap, RingBuf};
use aya::programs::{KProbe, RawTracePoint, TracePoint, UProbe};
use aya::{Ebpf, EbpfLoader};
use thiserror::Error;

use crate::compiler::{BpfFieldType, CompileError, EbpfProgram, EbpfProgramType, EventSchema};
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};

/// Errors that can occur during eBPF loading
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Compilation error: {0}")]
    Compile(#[from] CompileError),

    #[error("Failed to load eBPF program: {0}")]
    Load(String),

    #[error("Failed to attach probe: {0}")]
    Attach(String),

    #[error("Probe not found: {0}")]
    ProbeNotFound(u32),

    #[error("Permission denied: eBPF requires CAP_BPF or root")]
    PermissionDenied,

    #[error("Program not found in ELF: {0}")]
    ProgramNotFound(String),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Perf buffer error: {0}")]
    PerfBuffer(String),

    #[error("Function not found: {name}")]
    FunctionNotFound {
        name: String,
        suggestions: Vec<String>,
    },

    #[error("Tracepoint not found: {category}/{name}")]
    TracepointNotFound { category: String, name: String },

    #[error("Elevated privileges required")]
    NeedsSudo,
}

/// Parsed uprobe/uretprobe target information
#[derive(Debug, Clone)]
pub struct UprobeTarget {
    /// Path to the binary or library
    pub binary_path: String,
    /// Function name (None if using offset-only)
    pub function_name: Option<String>,
    /// Offset within the function or binary (0 if attaching to function entry)
    pub offset: u64,
    /// Optional PID to filter (None means all processes)
    pub pid: Option<i32>,
}

impl UprobeTarget {
    /// Parse a uprobe target string
    ///
    /// Formats supported:
    /// - `/path/to/binary:function_name` - attach to function entry
    /// - `/path/to/binary:0x1234` - attach to offset (hex)
    /// - `/path/to/binary:function_name+0x10` - attach to function + offset
    /// - Any of the above with `@PID` suffix for PID filtering
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        // Check for PID suffix (@1234)
        let (target_part, pid) = if let Some(at_idx) = target.rfind('@') {
            let pid_str = &target[at_idx + 1..];
            match pid_str.parse::<i32>() {
                Ok(pid) => (&target[..at_idx], Some(pid)),
                Err(_) => (target, None), // Not a valid PID, treat @ as part of target
            }
        } else {
            (target, None)
        };

        // Find the last colon that separates path from function/offset
        // We need to find the colon that's not part of the path
        // Path can't contain colon on Unix, so the last colon is our separator
        let colon_idx = target_part.rfind(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid uprobe target: {target}. Expected format: /path/to/binary:function_name"
            ))
        })?;

        let binary_path = target_part[..colon_idx].to_string();
        let func_or_offset = &target_part[colon_idx + 1..];

        if binary_path.is_empty() {
            return Err(LoadError::Load(
                "Uprobe binary path cannot be empty".to_string(),
            ));
        }

        // Parse function name and/or offset
        // Format: function_name, 0x1234, or function_name+0x10
        let (function_name, offset) = if let Some(plus_idx) = func_or_offset.find('+') {
            // function_name+offset
            let name = &func_or_offset[..plus_idx];
            let offset_str = &func_or_offset[plus_idx + 1..];
            let offset = parse_offset(offset_str)?;
            (Some(name.to_string()), offset)
        } else if func_or_offset.starts_with("0x") || func_or_offset.starts_with("0X") {
            // Pure offset
            let offset = parse_offset(func_or_offset)?;
            (None, offset)
        } else {
            // Pure function name
            (Some(func_or_offset.to_string()), 0)
        };

        Ok(UprobeTarget {
            binary_path,
            function_name,
            offset,
            pid,
        })
    }
}

/// Parse a hex or decimal offset string
fn parse_offset(s: &str) -> Result<u64, LoadError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| LoadError::Load(format!("Invalid hex offset: {s}")))
    } else {
        s.parse::<u64>()
            .map_err(|_| LoadError::Load(format!("Invalid offset: {s}")))
    }
}

/// Information about an active probe
pub struct ActiveProbe {
    /// Unique probe ID
    pub id: u32,
    /// The probe specification (e.g., "kprobe:sys_clone")
    pub probe_spec: String,
    /// When the probe was attached
    pub attached_at: Instant,
    /// The loaded eBPF object (keeps program alive)
    ebpf: Ebpf,
    /// Whether this probe has a ring buffer map for output
    has_ringbuf: bool,
    /// Whether this probe has a counter hash map (integer keys)
    has_counter_map: bool,
    /// Whether this probe has a string counter hash map (string keys like $ctx.comm)
    has_string_counter_map: bool,
    /// Whether this probe has a histogram hash map
    has_histogram_map: bool,
    /// Whether this probe has a kernel stack trace map
    has_kstack_map: bool,
    /// Whether this probe has a user stack trace map
    has_ustack_map: bool,
    /// Ring buffer for event output (only if has_ringbuf)
    ringbuf: Option<RingBuf<aya::maps::MapData>>,
    /// Optional schema for structured events
    event_schema: Option<EventSchema>,
    /// Pin group name (if maps are pinned for sharing)
    pin_group: Option<String>,
}

impl std::fmt::Debug for ActiveProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveProbe")
            .field("id", &self.id)
            .field("probe_spec", &self.probe_spec)
            .field("attached_at", &self.attached_at)
            .field("has_ringbuf", &self.has_ringbuf)
            .field("has_counter_map", &self.has_counter_map)
            .field("has_string_counter_map", &self.has_string_counter_map)
            .field("has_histogram_map", &self.has_histogram_map)
            .field("has_kstack_map", &self.has_kstack_map)
            .field("has_ustack_map", &self.has_ustack_map)
            .field("event_schema", &self.event_schema.is_some())
            .finish()
    }
}

/// A field value in a structured event
#[derive(Debug, Clone)]
pub enum BpfFieldValue {
    /// An integer value
    Int(i64),
    /// A string value
    String(String),
}

/// The data payload of an eBPF event
#[derive(Debug, Clone)]
pub enum BpfEventData {
    /// An integer value (8 bytes from bpf-emit)
    Int(i64),
    /// A string value (16 bytes from $ctx.comm | emit, null-terminated)
    String(String),
    /// Raw bytes for unknown sizes
    Bytes(Vec<u8>),
    /// A structured record with named fields
    Record(Vec<(String, BpfFieldValue)>),
}

/// An event received from an eBPF program via emit
#[derive(Debug, Clone)]
pub struct BpfEvent {
    /// The data emitted by the eBPF program
    pub data: BpfEventData,
    /// Which CPU the event came from
    pub cpu: u32,
}

/// A counter entry from the bpf-count hash map (integer keys)
#[derive(Debug, Clone)]
pub struct CounterEntry {
    /// The key (e.g., PID as i64)
    pub key: i64,
    /// The count value
    pub count: i64,
}

/// A counter entry from the bpf-count hash map (string keys like $ctx.comm)
#[derive(Debug, Clone)]
pub struct StringCounterEntry {
    /// The key (e.g., process name from $ctx.comm)
    pub key: String,
    /// The count value
    pub count: i64,
}

/// Histogram bucket entry
#[derive(Debug, Clone)]
pub struct HistogramEntry {
    /// The bucket index (log2 of value range)
    pub bucket: i64,
    /// The count of values in this bucket
    pub count: i64,
}

/// A stack trace with raw instruction pointer addresses
#[derive(Debug, Clone)]
pub struct StackTrace {
    /// The stack ID (used as key in the stack trace map)
    pub id: i64,
    /// The instruction pointer addresses (frames from top to bottom)
    pub frames: Vec<u64>,
}

/// Global state for managing eBPF probes
pub struct EbpfState {
    /// Active probes indexed by ID
    probes: Mutex<HashMap<u32, ActiveProbe>>,
    /// Next probe ID
    next_id: AtomicU32,
    /// Reference counts for pin groups (for cleanup when last probe detaches)
    pin_group_refs: Mutex<HashMap<String, u32>>,
}

impl Default for EbpfState {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfState {
    pub fn new() -> Self {
        Self {
            probes: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            pin_group_refs: Mutex::new(HashMap::new()),
        }
    }

    /// Get the next available probe ID
    fn next_probe_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Load and attach an eBPF program
    pub fn attach(&self, program: &EbpfProgram) -> Result<u32, LoadError> {
        self.attach_with_pin(program, None)
    }

    /// Load and attach an eBPF program with optional map pinning
    ///
    /// If `pin_group` is Some, maps will be pinned to /sys/fs/bpf/nushell/<group>/.
    /// This enables map sharing between separate eBPF programs - for example, a kprobe
    /// and kretprobe can share a timestamp map for latency measurement via start-timer/stop-timer.
    ///
    /// When a pinned map already exists, the new program will reuse it instead of creating a new one.
    /// Maps are automatically unpinned when no programs are using them.
    pub fn attach_with_pin(
        &self,
        program: &EbpfProgram,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        // Generate ELF
        let elf_bytes = program.to_elf()?;

        // Load with Aya using EbpfLoader for optional map pinning
        let mut ebpf = if let Some(group) = pin_group {
            let pin_path = format!("/sys/fs/bpf/nushell/{}", group);
            // Create the directory if it doesn't exist
            std::fs::create_dir_all(&pin_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    LoadError::PermissionDenied
                } else {
                    LoadError::Load(format!(
                        "Failed to create pin directory {}: {}",
                        pin_path, e
                    ))
                }
            })?;
            // Use EbpfLoader with map pinning to enable map sharing between programs
            EbpfLoader::new().map_pin_path(&pin_path).load(&elf_bytes)
        } else {
            // No pinning - use simple Ebpf::load
            Ebpf::load(&elf_bytes)
        }
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("EPERM") || msg.contains("permission") {
                LoadError::PermissionDenied
            } else {
                LoadError::Load(msg)
            }
        })?;

        // Get the program by name
        let prog = ebpf
            .program_mut(&program.name)
            .ok_or_else(|| LoadError::ProgramNotFound(program.name.clone()))?;

        // Attach based on program type
        match program.prog_type {
            EbpfProgramType::Kprobe => {
                let kprobe: &mut KProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to KProbe: {e}")))?;
                kprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load kprobe: {e}")))?;
                kprobe
                    .attach(&program.target, 0)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach kprobe: {e}")))?;
            }
            EbpfProgramType::Kretprobe => {
                // Kretprobe uses the same KProbe type - Aya detects it from the section name
                let kretprobe: &mut KProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to KRetProbe: {e}")))?;
                kretprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load kretprobe: {e}")))?;
                kretprobe
                    .attach(&program.target, 0)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach kretprobe: {e}")))?;
            }
            EbpfProgramType::Tracepoint => {
                // Tracepoint target format: "category/name" (e.g., "syscalls/sys_enter_openat")
                let parts: Vec<&str> = program.target.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return Err(LoadError::Load(format!(
                        "Invalid tracepoint target: {}. Expected format: category/name",
                        program.target
                    )));
                }
                let (category, name) = (parts[0], parts[1]);

                let tracepoint: &mut TracePoint = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to TracePoint: {e}"))
                })?;
                tracepoint
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load tracepoint: {e}")))?;
                tracepoint
                    .attach(category, name)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tracepoint: {e}")))?;
            }
            EbpfProgramType::RawTracepoint => {
                // Raw tracepoint target is just the name (e.g., "sys_enter")
                let raw_tp: &mut RawTracePoint = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to RawTracePoint: {e}"))
                })?;
                raw_tp
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load raw_tracepoint: {e}")))?;
                raw_tp.attach(&program.target).map_err(|e| {
                    LoadError::Attach(format!("Failed to attach raw_tracepoint: {e}"))
                })?;
            }
            EbpfProgramType::Uprobe => {
                // Uprobe target format: /path/to/binary:function_name or /path/to/binary:0x1234
                let target = UprobeTarget::parse(&program.target)?;
                let uprobe: &mut UProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to UProbe: {e}")))?;
                uprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load uprobe: {e}")))?;
                uprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| LoadError::Attach(format!("Failed to attach uprobe: {e}")))?;
            }
            EbpfProgramType::Uretprobe => {
                // Uretprobe uses the same UProbe type - Aya detects it from the section name
                let target = UprobeTarget::parse(&program.target)?;
                let uretprobe: &mut UProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to URetProbe: {e}")))?;
                uretprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load uretprobe: {e}")))?;
                uretprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| LoadError::Attach(format!("Failed to attach uretprobe: {e}")))?;
            }
        }

        // Check for maps
        let has_ringbuf = ebpf.map("events").is_some();
        let has_counter_map = ebpf.map("counters").is_some();
        let has_string_counter_map = ebpf.map("str_counters").is_some();
        let has_histogram_map = ebpf.map("histogram").is_some();
        let has_kstack_map = ebpf.map("kstacks").is_some();
        let has_ustack_map = ebpf.map("ustacks").is_some();

        // Set up ring buffer if the program uses bpf-emit
        let ringbuf = if has_ringbuf {
            let ring_map = ebpf
                .take_map("events")
                .ok_or_else(|| LoadError::MapNotFound("events".to_string()))?;

            let ringbuf = RingBuf::try_from(ring_map).map_err(|e| {
                LoadError::PerfBuffer(format!("Failed to convert ring buffer map: {e}"))
            })?;

            Some(ringbuf)
        } else {
            None
        };

        // Store the active probe
        let id = self.next_probe_id();
        let probe_spec = format!("{}:{}", program.prog_type.section_prefix(), program.target);

        // Track pin group reference count for cleanup
        let pin_group_owned = pin_group.map(|s| s.to_string());
        if let Some(ref group) = pin_group_owned {
            let mut refs = self.pin_group_refs.lock().unwrap();
            *refs.entry(group.clone()).or_insert(0) += 1;
        }

        let active_probe = ActiveProbe {
            id,
            probe_spec,
            attached_at: Instant::now(),
            ebpf,
            has_ringbuf,
            has_counter_map,
            has_string_counter_map,
            has_histogram_map,
            has_kstack_map,
            has_ustack_map,
            ringbuf,
            event_schema: program.event_schema.clone(),
            pin_group: pin_group_owned,
        };

        self.probes.lock().unwrap().insert(id, active_probe);

        Ok(id)
    }

    /// Poll for events from a probe's ring buffer
    ///
    /// Returns events emitted by the eBPF program via bpf-emit.
    /// The timeout specifies how long to wait for events.
    pub fn poll_events(&self, id: u32, _timeout: Duration) -> Result<Vec<BpfEvent>, LoadError> {
        let mut probes = self.probes.lock().unwrap();
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !probe.has_ringbuf {
            // No ring buffer, return empty
            return Ok(Vec::new());
        }

        let ringbuf = match &mut probe.ringbuf {
            Some(rb) => rb,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::new();

        // Clone the schema for use in parsing (to avoid borrow issues)
        let schema = probe.event_schema.clone();

        // Read events from ring buffer (non-blocking)
        // Ring buffer returns events one at a time via next()
        while let Some(item) = ringbuf.next() {
            let buf: &[u8] = &item;
            let data = if let Some(ref event_schema) = schema {
                // We have a schema - deserialize structured event
                Self::deserialize_structured_event(buf, event_schema)
            } else {
                // No schema - use legacy size-based detection
                Self::deserialize_simple_event(buf)
            };

            if let Some(data) = data {
                events.push(BpfEvent {
                    data,
                    cpu: 0, // Ring buffer doesn't provide CPU info directly
                });
            }
        }

        Ok(events)
    }

    /// Deserialize a simple (non-structured) event based on size
    fn deserialize_simple_event(buf: &[u8]) -> Option<BpfEventData> {
        // Ring buffer events have exact sizes (no padding like perf buffer)
        // - 8 bytes: integer from emit
        // - 16+ bytes: string ($ctx.comm uses 16, read-str uses 128)
        if buf.len() == 8 {
            // 8 bytes = integer from emit
            let value = i64::from_le_bytes(buf[0..8].try_into().unwrap());
            Some(BpfEventData::Int(value))
        } else if buf.len() >= 16 {
            // 16+ bytes = string (from $ctx.comm | emit or read-str)
            // Find null terminator within the buffer
            let null_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let s = String::from_utf8_lossy(&buf[..null_pos]).to_string();
            Some(BpfEventData::String(s))
        } else if !buf.is_empty() {
            // Unknown size - return raw bytes
            Some(BpfEventData::Bytes(buf.to_vec()))
        } else {
            None
        }
    }

    /// Deserialize a structured event using the schema
    fn deserialize_structured_event(buf: &[u8], schema: &EventSchema) -> Option<BpfEventData> {
        if buf.len() < schema.total_size {
            // Buffer too small for the expected schema
            return Self::deserialize_simple_event(buf);
        }

        let mut fields = Vec::with_capacity(schema.fields.len());

        for field in &schema.fields {
            // Bounds check: ensure field.offset is within buffer
            if field.offset >= buf.len() {
                // Field offset out of bounds, skip this field
                continue;
            }
            let field_buf = &buf[field.offset..];
            let value = match field.field_type {
                BpfFieldType::Int => {
                    if field_buf.len() >= 8 {
                        let val = i64::from_le_bytes(field_buf[0..8].try_into().unwrap());
                        BpfFieldValue::Int(val)
                    } else {
                        BpfFieldValue::Int(0)
                    }
                }
                BpfFieldType::Comm => {
                    // 16-byte comm string
                    let max_len = field_buf.len().min(16);
                    let null_pos = field_buf[..max_len]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(max_len);
                    let s = String::from_utf8_lossy(&field_buf[..null_pos]).to_string();
                    BpfFieldValue::String(s)
                }
                BpfFieldType::String => {
                    // 128-byte string
                    let max_len = field_buf.len().min(128);
                    let null_pos = field_buf[..max_len]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(max_len);
                    let s = String::from_utf8_lossy(&field_buf[..null_pos]).to_string();
                    BpfFieldValue::String(s)
                }
            };
            fields.push((field.name.clone(), value));
        }

        Some(BpfEventData::Record(fields))
    }

    /// Helper to read all entries from an i64->i64 hash map
    fn read_i64_hash_map(
        &self,
        id: u32,
        has_map: impl Fn(&ActiveProbe) -> bool,
        map_name: &str,
    ) -> Result<Vec<(i64, i64)>, LoadError> {
        let mut probes = self.probes.lock().unwrap();
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !has_map(probe) {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        if let Some(map) = probe.ebpf.map_mut(map_name) {
            let hash_map: AyaHashMap<_, i64, i64> = AyaHashMap::try_from(map).map_err(|e| {
                LoadError::MapNotFound(format!("Failed to convert {map_name} map: {e}"))
            })?;

            for (key, value) in hash_map.iter().filter_map(|item| item.ok()) {
                entries.push((key, value));
            }
        }

        Ok(entries)
    }

    /// Read all counter entries from a probe's counter map (integer keys)
    ///
    /// Returns all key-value pairs from the bpf-count hash map.
    pub fn get_counters(&self, id: u32) -> Result<Vec<CounterEntry>, LoadError> {
        let entries = self.read_i64_hash_map(id, |p| p.has_counter_map, "counters")?;
        Ok(entries
            .into_iter()
            .map(|(key, count)| CounterEntry { key, count })
            .collect())
    }

    /// Read all counter entries from a probe's string counter map
    ///
    /// Returns all key-value pairs from the bpf-count hash map with string keys
    /// (e.g., process names from $ctx.comm).
    pub fn get_string_counters(&self, id: u32) -> Result<Vec<StringCounterEntry>, LoadError> {
        let mut probes = self.probes.lock().unwrap();
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !probe.has_string_counter_map {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        if let Some(map) = probe.ebpf.map_mut("str_counters") {
            // String counter map uses [u8; 16] as key (comm is 16 bytes)
            let hash_map: AyaHashMap<_, [u8; 16], i64> =
                AyaHashMap::try_from(map).map_err(|e| {
                    LoadError::MapNotFound(format!("Failed to convert str_counters map: {e}"))
                })?;

            for (key_bytes, count) in hash_map.iter().filter_map(|item| item.ok()) {
                // Convert the key bytes to a string (null-terminated)
                let key = std::str::from_utf8(&key_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();
                entries.push(StringCounterEntry { key, count });
            }
        }

        Ok(entries)
    }

    /// Read all histogram entries from a probe's histogram map
    ///
    /// Returns all bucket-count pairs from the bpf-histogram hash map,
    /// sorted by bucket number.
    pub fn get_histogram(&self, id: u32) -> Result<Vec<HistogramEntry>, LoadError> {
        let mut entries: Vec<HistogramEntry> = self
            .read_i64_hash_map(id, |p| p.has_histogram_map, "histogram")?
            .into_iter()
            .map(|(bucket, count)| HistogramEntry { bucket, count })
            .collect();

        // Sort by bucket for display
        entries.sort_by_key(|e| e.bucket);

        Ok(entries)
    }

    /// Read all kernel stack traces from a probe's stack trace map
    ///
    /// Returns all stack traces collected by $ctx.kstack.
    /// Each stack trace contains a unique ID and the instruction pointer addresses.
    pub fn get_kernel_stacks(&self, id: u32) -> Result<Vec<StackTrace>, LoadError> {
        self.get_stacks_from_map(id, "kstacks", |p| p.has_kstack_map)
    }

    /// Read all user stack traces from a probe's stack trace map
    ///
    /// Returns all stack traces collected by $ctx.ustack.
    /// Each stack trace contains a unique ID and the instruction pointer addresses.
    pub fn get_user_stacks(&self, id: u32) -> Result<Vec<StackTrace>, LoadError> {
        self.get_stacks_from_map(id, "ustacks", |p| p.has_ustack_map)
    }

    /// Helper to read stack traces from a named stack trace map
    fn get_stacks_from_map(
        &self,
        id: u32,
        map_name: &str,
        has_map: impl Fn(&ActiveProbe) -> bool,
    ) -> Result<Vec<StackTrace>, LoadError> {
        let mut probes = self.probes.lock().unwrap();
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !has_map(probe) {
            return Ok(Vec::new());
        }

        let mut stacks = Vec::new();

        if let Some(map) = probe.ebpf.map_mut(map_name) {
            // StackTraceMap is keyed by stack_id (u32) and contains arrays of u64 IPs
            let stack_map: aya::maps::StackTraceMap<_> = aya::maps::StackTraceMap::try_from(map)
                .map_err(|e| {
                    LoadError::MapNotFound(format!("Failed to access {}: {}", map_name, e))
                })?;

            for (stack_id, trace) in stack_map.iter().filter_map(|item| item.ok()) {
                // Extract instruction pointers from the trace, filtering zeros
                let frames: Vec<u64> = trace
                    .frames()
                    .iter()
                    .map(|f| f.ip)
                    .filter(|&ip| ip != 0)
                    .collect();

                if !frames.is_empty() {
                    stacks.push(StackTrace {
                        id: stack_id as i64,
                        frames,
                    });
                }
            }
        }

        Ok(stacks)
    }

    /// Detach a probe by ID
    ///
    /// If the probe was using a pin group and this is the last probe using it,
    /// the pinned maps will be automatically cleaned up.
    pub fn detach(&self, id: u32) -> Result<(), LoadError> {
        let mut probes = self.probes.lock().unwrap();
        if let Some(probe) = probes.remove(&id) {
            // Check if we need to clean up a pin group
            if let Some(ref group) = probe.pin_group {
                let mut refs = self.pin_group_refs.lock().unwrap();
                if let Some(count) = refs.get_mut(group) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        refs.remove(group);
                        // Clean up the pin directory
                        let pin_path = format!("/sys/fs/bpf/nushell/{}", group);
                        let _ = std::fs::remove_dir_all(&pin_path);
                        // Also try to remove the parent if empty
                        let _ = std::fs::remove_dir("/sys/fs/bpf/nushell");
                    }
                }
            }
            // Dropping the ActiveProbe will detach the program
            Ok(())
        } else {
            Err(LoadError::ProbeNotFound(id))
        }
    }

    /// List all active probes
    pub fn list(&self) -> Vec<ProbeInfo> {
        let probes = self.probes.lock().unwrap();
        probes
            .values()
            .map(|p| ProbeInfo {
                id: p.id,
                probe_spec: p.probe_spec.clone(),
                uptime_secs: p.attached_at.elapsed().as_secs(),
            })
            .collect()
    }
}

/// Information about a probe for display
#[derive(Debug, Clone)]
pub struct ProbeInfo {
    pub id: u32,
    pub probe_spec: String,
    pub uptime_secs: u64,
}

/// Global eBPF state (lazily initialized)
static EBPF_STATE: std::sync::OnceLock<Arc<EbpfState>> = std::sync::OnceLock::new();

/// Get the global eBPF state
pub fn get_state() -> Arc<EbpfState> {
    EBPF_STATE
        .get_or_init(|| Arc::new(EbpfState::new()))
        .clone()
}

/// Validate a kprobe/kretprobe target function exists
///
/// If the function doesn't exist, returns an error with suggestions for similar function names.
/// If elevated privileges are needed to validate, returns NeedsSudo error.
fn validate_kprobe_target(func_name: &str) -> Result<(), LoadError> {
    let btf = KernelBtf::get();

    match btf.check_function(func_name) {
        FunctionCheckResult::Exists => Ok(()),
        FunctionCheckResult::NotFound { suggestions } => Err(LoadError::FunctionNotFound {
            name: func_name.to_string(),
            suggestions,
        }),
        FunctionCheckResult::NeedsSudo => Err(LoadError::NeedsSudo),
        FunctionCheckResult::CannotValidate => {
            // Can't validate - allow the attempt, kernel will reject if invalid
            Ok(())
        }
    }
}

/// Validate a tracepoint target exists
///
/// Tracepoint format: category/name (e.g., syscalls/sys_enter_openat)
fn validate_tracepoint_target(target: &str) -> Result<(), LoadError> {
    let btf = KernelBtf::get();

    // If we can't validate (no tracefs), allow the attempt
    if !btf.has_tracefs() {
        return Ok(());
    }

    // Parse category/name
    let parts: Vec<&str> = target.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(LoadError::Load(format!(
            "Invalid tracepoint format: {target}. Expected: category/name (e.g., syscalls/sys_enter_openat)"
        )));
    }

    let (category, name) = (parts[0], parts[1]);

    if btf.tracepoint_exists(category, name) {
        return Ok(());
    }

    Err(LoadError::TracepointNotFound {
        category: category.to_string(),
        name: name.to_string(),
    })
}

/// Parse a probe specification like "kprobe:sys_clone" or "tracepoint:syscalls/sys_enter_read"
///
/// Supported formats:
/// - `kprobe:function_name`
/// - `kretprobe:function_name`
/// - `tracepoint:category/name`
/// - `raw_tracepoint:name` or `raw_tp:name`
/// - `uprobe:/path/to/binary:function_name`
/// - `uretprobe:/path/to/binary:function_name`
/// - `uprobe:/path/to/binary:0x1234` (offset-based)
/// - `uprobe:/path/to/binary:function@PID` (PID-filtered)
pub fn parse_probe_spec(spec: &str) -> Result<(EbpfProgramType, String), LoadError> {
    // Handle uprobe/uretprobe specially since their targets contain colons
    if let Some(target) = spec.strip_prefix("uprobe:") {
        // Validate the uprobe target format
        UprobeTarget::parse(target)?;
        return Ok((EbpfProgramType::Uprobe, target.to_string()));
    }
    if let Some(target) = spec.strip_prefix("uretprobe:") {
        // Validate the uprobe target format
        UprobeTarget::parse(target)?;
        return Ok((EbpfProgramType::Uretprobe, target.to_string()));
    }

    // For other probe types, use simple colon split
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(LoadError::Load(format!(
            "Invalid probe spec: {spec}. Expected format: type:target (e.g., kprobe:sys_clone)"
        )));
    }

    let target = parts[1];

    let prog_type = match parts[0] {
        "kprobe" => {
            // Validate function exists
            validate_kprobe_target(target)?;
            EbpfProgramType::Kprobe
        }
        "kretprobe" => {
            // Validate function exists
            validate_kprobe_target(target)?;
            EbpfProgramType::Kretprobe
        }
        "tracepoint" => {
            // Validate tracepoint exists
            validate_tracepoint_target(target)?;
            EbpfProgramType::Tracepoint
        }
        "raw_tracepoint" | "raw_tp" => EbpfProgramType::RawTracepoint,
        other => {
            return Err(LoadError::Load(format!(
                "Unknown probe type: {other}. Supported: kprobe, kretprobe, tracepoint, raw_tracepoint, uprobe, uretprobe"
            )));
        }
    };

    Ok((prog_type, target.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uprobe_target_basic() {
        let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/python");
        assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
        assert_eq!(target.offset, 0);
        assert_eq!(target.pid, None);
    }

    #[test]
    fn test_uprobe_target_offset_hex() {
        let target = UprobeTarget::parse("/lib/libc.so.6:0x12345").unwrap();
        assert_eq!(target.binary_path, "/lib/libc.so.6");
        assert_eq!(target.function_name, None);
        assert_eq!(target.offset, 0x12345);
        assert_eq!(target.pid, None);
    }

    #[test]
    fn test_uprobe_target_function_plus_offset() {
        let target = UprobeTarget::parse("/usr/bin/app:main+0x10").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/app");
        assert_eq!(target.function_name, Some("main".to_string()));
        assert_eq!(target.offset, 0x10);
        assert_eq!(target.pid, None);
    }

    #[test]
    fn test_uprobe_target_with_pid() {
        let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize@1234").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/python");
        assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
        assert_eq!(target.offset, 0);
        assert_eq!(target.pid, Some(1234));
    }

    #[test]
    fn test_uprobe_target_offset_with_pid() {
        let target = UprobeTarget::parse("/lib/libc.so.6:malloc+0x20@5678").unwrap();
        assert_eq!(target.binary_path, "/lib/libc.so.6");
        assert_eq!(target.function_name, Some("malloc".to_string()));
        assert_eq!(target.offset, 0x20);
        assert_eq!(target.pid, Some(5678));
    }

    #[test]
    fn test_uprobe_target_invalid_no_colon() {
        let result = UprobeTarget::parse("/usr/bin/python");
        assert!(result.is_err());
    }

    #[test]
    fn test_uprobe_target_invalid_empty_path() {
        let result = UprobeTarget::parse(":function");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_probe_spec_uprobe() {
        let (prog_type, target) = parse_probe_spec("uprobe:/usr/bin/app:main").unwrap();
        assert!(matches!(prog_type, EbpfProgramType::Uprobe));
        assert_eq!(target, "/usr/bin/app:main");
    }

    #[test]
    fn test_parse_probe_spec_uretprobe() {
        let (prog_type, target) = parse_probe_spec("uretprobe:/lib/libc.so.6:malloc").unwrap();
        assert!(matches!(prog_type, EbpfProgramType::Uretprobe));
        assert_eq!(target, "/lib/libc.so.6:malloc");
    }

    #[test]
    fn test_parse_probe_spec_kprobe_unchanged() {
        // This test may fail with NeedsSudo if running without root
        // That's expected - we're testing the parsing, not the permissions
        let result = parse_probe_spec("kprobe:sys_clone");

        match result {
            Ok((prog_type, target)) => {
                assert!(matches!(prog_type, EbpfProgramType::Kprobe));
                assert_eq!(target, "sys_clone");
            }
            Err(LoadError::NeedsSudo) => {
                // Expected when running tests without root - validation correctly detected
                // that we don't have permission to read the function list
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
