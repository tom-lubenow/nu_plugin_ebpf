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

#[path = "loader/attach.rs"]
mod attach;
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
