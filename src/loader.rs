//! eBPF program loading and management
//!
//! This module handles loading eBPF programs into the kernel using Aya,
//! and managing active probes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya::maps::{HashMap as AyaHashMap, PerCpuHashMap, RingBuf};
use aya::programs::{KProbe, RawTracePoint, TracePoint, UProbe};
use aya::{Ebpf, EbpfLoader};
use thiserror::Error;

use crate::compiler::{BpfFieldType, CompileError, EbpfProgram, EbpfProgramType, EventSchema};

/// Maximum entries per eBPF hash map
const MAX_MAP_ENTRIES: usize = 10240;

/// Threshold for map capacity warnings (80%)
const MAP_CAPACITY_WARN_THRESHOLD: usize = MAX_MAP_ENTRIES * 8 / 10;

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

    #[error("Internal error: lock poisoned")]
    LockPoisoned,
}

#[path = "loader/events.rs"]
mod events;

#[path = "loader/targets.rs"]
mod targets;

#[path = "loader/maps.rs"]
mod maps;

pub use targets::{UprobeTarget, parse_probe_spec};

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
    /// Whether this probe has a counter map (hash or per-CPU hash, integer keys)
    has_counter_map: bool,
    /// Whether this probe has a string counter map (hash or per-CPU hash)
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
            let mut refs = self
                .pin_group_refs
                .lock()
                .map_err(|_| LoadError::LockPoisoned)?;
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

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }

    /// Detach a probe by ID
    ///
    /// If the probe was using a pin group and this is the last probe using it,
    /// the pinned maps will be automatically cleaned up.
    pub fn detach(&self, id: u32) -> Result<(), LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        if let Some(probe) = probes.remove(&id) {
            // Check if we need to clean up a pin group
            if let Some(ref group) = probe.pin_group {
                let mut refs = self
                    .pin_group_refs
                    .lock()
                    .map_err(|_| LoadError::LockPoisoned)?;
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
    pub fn list(&self) -> Result<Vec<ProbeInfo>, LoadError> {
        let probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        Ok(probes
            .values()
            .map(|p| ProbeInfo {
                id: p.id,
                probe_spec: p.probe_spec.clone(),
                uptime_secs: p.attached_at.elapsed().as_secs(),
            })
            .collect())
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

#[cfg(test)]
mod tests;
