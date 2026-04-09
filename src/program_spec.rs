use aya::programs::{CgroupSkbAttachType, CgroupSockAddrAttachType, TcAttachType};

/// Parsed uprobe/uretprobe target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UprobeTarget {
    /// Path to the binary or library.
    pub binary_path: String,
    /// Function name (None if using offset-only).
    pub function_name: Option<String>,
    /// Offset within the function or binary (0 if attaching to function entry).
    pub offset: u64,
    /// Optional PID to filter (None means all processes).
    pub pid: Option<i32>,
}

impl UprobeTarget {
    /// Render this parsed target back into canonical target syntax.
    pub fn target_string(&self) -> String {
        let mut target = String::with_capacity(self.binary_path.len() + 32);
        target.push_str(&self.binary_path);
        target.push(':');
        match (&self.function_name, self.offset) {
            (Some(function_name), 0) => target.push_str(function_name),
            (Some(function_name), offset) => {
                target.push_str(function_name);
                target.push('+');
                target.push_str(&format!("0x{offset:x}"));
            }
            (None, offset) => target.push_str(&format!("0x{offset:x}")),
        }
        if let Some(pid) = self.pid {
            target.push('@');
            target.push_str(&pid.to_string());
        }
        target
    }
}

/// Parsed tc target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcTarget {
    /// Network interface name.
    pub interface: String,
    /// Attach direction.
    pub attach_type: TcAttachType,
}

impl TcTarget {
    pub fn target_string(&self) -> String {
        let direction = match self.attach_type {
            TcAttachType::Ingress => "ingress",
            TcAttachType::Egress => "egress",
            _ => "unknown",
        };
        format!("{}:{direction}", self.interface)
    }
}

/// Parsed cgroup_skb target information.
#[derive(Debug, Clone)]
pub struct CgroupSkbTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach direction.
    pub attach_type: CgroupSkbAttachType,
}

impl CgroupSkbTarget {
    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSkbAttachType::Ingress => "ingress",
            CgroupSkbAttachType::Egress => "egress",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }
}

impl PartialEq for CgroupSkbTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSkbTarget {}

/// Parsed cgroup_sock_addr target information.
#[derive(Debug, Clone)]
pub struct CgroupSockAddrTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach kind.
    pub attach_type: CgroupSockAddrAttachType,
}

impl CgroupSockAddrTarget {
    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSockAddrAttachType::Bind4 => "bind4",
            CgroupSockAddrAttachType::Bind6 => "bind6",
            CgroupSockAddrAttachType::Connect4 => "connect4",
            CgroupSockAddrAttachType::Connect6 => "connect6",
            CgroupSockAddrAttachType::GetPeerName4 => "getpeername4",
            CgroupSockAddrAttachType::GetPeerName6 => "getpeername6",
            CgroupSockAddrAttachType::GetSockName4 => "getsockname4",
            CgroupSockAddrAttachType::GetSockName6 => "getsockname6",
            CgroupSockAddrAttachType::UDPSendMsg4 => "sendmsg4",
            CgroupSockAddrAttachType::UDPSendMsg6 => "sendmsg6",
            CgroupSockAddrAttachType::UDPRecvMsg4 => "recvmsg4",
            CgroupSockAddrAttachType::UDPRecvMsg6 => "recvmsg6",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }
}

impl PartialEq for CgroupSockAddrTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSockAddrTarget {}

pub const DEFAULT_PERF_EVENT_PERIOD: u64 = 1_000_000;

/// Supported software perf events for the initial perf_event program surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventSoftwareEvent {
    CpuClock,
    TaskClock,
    ContextSwitches,
    CpuMigrations,
    PageFaults,
    MinorFaults,
    MajorFaults,
}

impl PerfEventSoftwareEvent {
    pub fn name(&self) -> &'static str {
        match self {
            PerfEventSoftwareEvent::CpuClock => "cpu-clock",
            PerfEventSoftwareEvent::TaskClock => "task-clock",
            PerfEventSoftwareEvent::ContextSwitches => "context-switches",
            PerfEventSoftwareEvent::CpuMigrations => "cpu-migrations",
            PerfEventSoftwareEvent::PageFaults => "page-faults",
            PerfEventSoftwareEvent::MinorFaults => "minor-faults",
            PerfEventSoftwareEvent::MajorFaults => "major-faults",
        }
    }
}

/// Supported hardware perf events for the initial perf_event hardware surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventHardwareEvent {
    CpuCycles,
    Instructions,
    CacheReferences,
    CacheMisses,
    BranchInstructions,
    BranchMisses,
    BusCycles,
    StalledCyclesFrontend,
    StalledCyclesBackend,
    RefCpuCycles,
}

impl PerfEventHardwareEvent {
    pub fn name(&self) -> &'static str {
        match self {
            PerfEventHardwareEvent::CpuCycles => "cpu-cycles",
            PerfEventHardwareEvent::Instructions => "instructions",
            PerfEventHardwareEvent::CacheReferences => "cache-references",
            PerfEventHardwareEvent::CacheMisses => "cache-misses",
            PerfEventHardwareEvent::BranchInstructions => "branch-instructions",
            PerfEventHardwareEvent::BranchMisses => "branch-misses",
            PerfEventHardwareEvent::BusCycles => "bus-cycles",
            PerfEventHardwareEvent::StalledCyclesFrontend => "stalled-cycles-frontend",
            PerfEventHardwareEvent::StalledCyclesBackend => "stalled-cycles-backend",
            PerfEventHardwareEvent::RefCpuCycles => "ref-cpu-cycles",
        }
    }
}

/// Supported perf_event sources and their event selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventEvent {
    Software(PerfEventSoftwareEvent),
    Hardware(PerfEventHardwareEvent),
}

impl PerfEventEvent {
    pub fn source_name(&self) -> &'static str {
        match self {
            PerfEventEvent::Software(_) => "software",
            PerfEventEvent::Hardware(_) => "hardware",
        }
    }

    pub fn event_name(&self) -> &'static str {
        match self {
            PerfEventEvent::Software(event) => event.name(),
            PerfEventEvent::Hardware(event) => event.name(),
        }
    }
}

/// Sample policy for perf_event programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventSamplePolicy {
    Period(u64),
    Frequency(u64),
}

impl PerfEventSamplePolicy {
    pub fn is_default(&self) -> bool {
        matches!(
            self,
            PerfEventSamplePolicy::Period(DEFAULT_PERF_EVENT_PERIOD)
        )
    }
}

/// Parsed perf_event target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfEventTarget {
    /// Perf event source and selector.
    pub event: PerfEventEvent,
    /// Optional CPU selector. `None` means attach on all online CPUs.
    pub cpu: Option<u32>,
    /// Optional PID selector. `None` means attach across processes.
    pub pid: Option<u32>,
    /// Perf sampling policy.
    pub sample_policy: PerfEventSamplePolicy,
}

impl PerfEventTarget {
    pub fn target_string(&self) -> String {
        let mut target = format!("{}:{}", self.event.source_name(), self.event.event_name());
        if let Some(cpu) = self.cpu {
            target.push_str(&format!(":cpu={cpu}"));
        }
        if let Some(pid) = self.pid {
            target.push_str(&format!(":pid={pid}"));
        }
        match self.sample_policy {
            PerfEventSamplePolicy::Period(period) if period != DEFAULT_PERF_EVENT_PERIOD => {
                target.push_str(&format!(":period={period}"));
            }
            PerfEventSamplePolicy::Frequency(freq) => {
                target.push_str(&format!(":freq={freq}"));
            }
            _ => {}
        }
        target
    }
}

/// Parsed program specification with structured target metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramSpec {
    Kprobe { function: String },
    Kretprobe { function: String },
    Fentry { function: String },
    Fexit { function: String },
    Lsm { hook: String },
    Tracepoint { category: String, name: String },
    RawTracepoint { name: String },
    Uprobe { target: UprobeTarget },
    Uretprobe { target: UprobeTarget },
    Xdp { interface: String },
    PerfEvent { target: PerfEventTarget },
    Tc { target: TcTarget },
    CgroupSkb { target: CgroupSkbTarget },
    CgroupSockAddr { target: CgroupSockAddrTarget },
    StructOps { value_type_name: String },
}

impl ProgramSpec {
    pub fn target_string(&self) -> String {
        match self {
            ProgramSpec::Kprobe { function }
            | ProgramSpec::Kretprobe { function }
            | ProgramSpec::Fentry { function }
            | ProgramSpec::Fexit { function } => function.clone(),
            ProgramSpec::Lsm { hook } => hook.clone(),
            ProgramSpec::Tracepoint { category, name } => format!("{category}/{name}"),
            ProgramSpec::RawTracepoint { name } => name.clone(),
            ProgramSpec::Uprobe { target } | ProgramSpec::Uretprobe { target } => {
                target.target_string()
            }
            ProgramSpec::Xdp { interface } => interface.clone(),
            ProgramSpec::PerfEvent { target } => target.target_string(),
            ProgramSpec::Tc { target } => target.target_string(),
            ProgramSpec::CgroupSkb { target } => target.target_string(),
            ProgramSpec::CgroupSockAddr { target } => target.target_string(),
            ProgramSpec::StructOps { value_type_name } => value_type_name.clone(),
        }
    }
}
