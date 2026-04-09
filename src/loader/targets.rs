use super::LoadError;
use crate::compiler::{EbpfProgramType, KernelTargetValidationKind, ProgramTargetKind};
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};
use crate::program_spec::{
    CgroupSkbTarget, CgroupSockAddrTarget, CgroupSockTarget, CgroupSockoptTarget,
    DEFAULT_PERF_EVENT_PERIOD, PerfEventEvent, PerfEventHardwareEvent, PerfEventSamplePolicy,
    PerfEventSoftwareEvent, PerfEventTarget, ProgramSpec, SkLookupTarget, TcTarget, UprobeTarget,
};
use aya::programs::{
    CgroupSkbAttachType, CgroupSockAddrAttachType, CgroupSockAttachType, CgroupSockoptAttachType,
    TcAttachType,
};
use aya::util::online_cpus;
use std::path::Path;

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

impl TcTarget {
    /// Parse a tc target string of the form `iface:ingress` or `iface:egress`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let (interface, direction) = target.split_once(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid tc target: {target}. Expected format: interface:ingress or interface:egress"
            ))
        })?;

        if interface.is_empty() {
            return Err(LoadError::Load(
                "TC interface target cannot be empty".to_string(),
            ));
        }

        let attach_type = match direction {
            "ingress" => TcAttachType::Ingress,
            "egress" => TcAttachType::Egress,
            _ => {
                return Err(LoadError::Load(format!(
                    "Invalid tc attach direction: {direction}. Expected ingress or egress"
                )));
            }
        };

        Ok(Self {
            interface: interface.to_string(),
            attach_type,
        })
    }
}

impl CgroupSkbTarget {
    /// Parse a cgroup_skb target string of the form `/sys/fs/cgroup:ingress`
    /// or `/sys/fs/cgroup:egress`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let (cgroup_path, direction) = target.rsplit_once(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid cgroup_skb target: {target}. Expected format: /path/to/cgroup:ingress or /path/to/cgroup:egress"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(LoadError::Load(
                "cgroup_skb cgroup path cannot be empty".to_string(),
            ));
        }

        let attach_type = match direction {
            "ingress" => CgroupSkbAttachType::Ingress,
            "egress" => CgroupSkbAttachType::Egress,
            _ => {
                return Err(LoadError::Load(format!(
                    "Invalid cgroup_skb attach direction: {direction}. Expected ingress or egress"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }
}

impl CgroupSockTarget {
    /// Parse a cgroup_sock target string of the form `/sys/fs/cgroup:sock_create`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid cgroup_sock target: {target}. Expected format: /path/to/cgroup:sock_create|sock_release|post_bind4|post_bind6"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(LoadError::Load(
                "cgroup_sock cgroup path cannot be empty".to_string(),
            ));
        }

        let attach_type = match attach_kind {
            "sock_create" => CgroupSockAttachType::SockCreate,
            "sock_release" => CgroupSockAttachType::SockRelease,
            "post_bind4" => CgroupSockAttachType::PostBind4,
            "post_bind6" => CgroupSockAttachType::PostBind6,
            _ => {
                return Err(LoadError::Load(format!(
                    "Invalid cgroup_sock attach kind: {attach_kind}. Expected sock_create, sock_release, post_bind4, or post_bind6"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }
}

impl CgroupSockAddrTarget {
    /// Parse a cgroup_sock_addr target string of the form `/sys/fs/cgroup:connect4`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid cgroup_sock_addr target: {target}. Expected format: /path/to/cgroup:attach_kind"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(LoadError::Load(
                "cgroup_sock_addr cgroup path cannot be empty".to_string(),
            ));
        }

        let attach_type = match attach_kind {
            "bind4" => CgroupSockAddrAttachType::Bind4,
            "bind6" => CgroupSockAddrAttachType::Bind6,
            "connect4" => CgroupSockAddrAttachType::Connect4,
            "connect6" => CgroupSockAddrAttachType::Connect6,
            "getpeername4" => CgroupSockAddrAttachType::GetPeerName4,
            "getpeername6" => CgroupSockAddrAttachType::GetPeerName6,
            "getsockname4" => CgroupSockAddrAttachType::GetSockName4,
            "getsockname6" => CgroupSockAddrAttachType::GetSockName6,
            "sendmsg4" => CgroupSockAddrAttachType::UDPSendMsg4,
            "sendmsg6" => CgroupSockAddrAttachType::UDPSendMsg6,
            "recvmsg4" => CgroupSockAddrAttachType::UDPRecvMsg4,
            "recvmsg6" => CgroupSockAddrAttachType::UDPRecvMsg6,
            _ => {
                return Err(LoadError::Load(format!(
                    "Invalid cgroup_sock_addr attach kind: {attach_kind}. Expected one of bind4, bind6, connect4, connect6, getpeername4, getpeername6, getsockname4, getsockname6, sendmsg4, sendmsg6, recvmsg4, recvmsg6"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }
}

impl CgroupSockoptTarget {
    /// Parse a cgroup_sockopt target string of the form `/sys/fs/cgroup:get`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid cgroup_sockopt target: {target}. Expected format: /path/to/cgroup:get or /path/to/cgroup:set"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(LoadError::Load(
                "cgroup_sockopt cgroup path cannot be empty".to_string(),
            ));
        }

        let attach_type = match attach_kind {
            "get" => CgroupSockoptAttachType::Get,
            "set" => CgroupSockoptAttachType::Set,
            _ => {
                return Err(LoadError::Load(format!(
                    "Invalid cgroup_sockopt attach kind: {attach_kind}. Expected get or set"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }
}

impl SkLookupTarget {
    /// Parse an sk_lookup target string of the form `/proc/self/ns/net`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        if target.is_empty() {
            return Err(LoadError::Load(
                "sk_lookup network namespace path cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            netns_path: target.to_string(),
        })
    }
}

impl PerfEventTarget {
    /// Parse a perf_event target string of the form
    /// `software:cpu-clock[:cpu=0][:pid=1234][:period=1000000]` or
    /// `hardware:cpu-cycles[:cpu=0][:pid=1234][:period=1000000]`.
    pub fn parse(target: &str) -> Result<Self, LoadError> {
        let mut parts = target.split(':');
        let source = parts.next().ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid perf_event target: {target}. Expected format: software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N] or hardware:cpu-cycles[:cpu=N][:pid=N][:period=N|freq=N]"
            ))
        })?;
        let event_name = parts.next().ok_or_else(|| {
            LoadError::Load(format!(
                "Invalid perf_event target: {target}. Expected format: software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N] or hardware:cpu-cycles[:cpu=N][:pid=N][:period=N|freq=N]"
            ))
        })?;

        let event = match source {
            "software" => match event_name {
                "cpu-clock" => PerfEventEvent::Software(PerfEventSoftwareEvent::CpuClock),
                "task-clock" => PerfEventEvent::Software(PerfEventSoftwareEvent::TaskClock),
                "context-switches" => {
                    PerfEventEvent::Software(PerfEventSoftwareEvent::ContextSwitches)
                }
                "cpu-migrations" => PerfEventEvent::Software(PerfEventSoftwareEvent::CpuMigrations),
                "page-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::PageFaults),
                "minor-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::MinorFaults),
                "major-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::MajorFaults),
                _ => {
                    return Err(LoadError::Load(format!(
                        "Unsupported perf_event software event: {event_name}. Expected one of cpu-clock, task-clock, context-switches, cpu-migrations, page-faults, minor-faults, major-faults"
                    )));
                }
            },
            "hardware" => match event_name {
                "cpu-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::CpuCycles),
                "instructions" => PerfEventEvent::Hardware(PerfEventHardwareEvent::Instructions),
                "cache-references" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::CacheReferences)
                }
                "cache-misses" => PerfEventEvent::Hardware(PerfEventHardwareEvent::CacheMisses),
                "branch-instructions" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::BranchInstructions)
                }
                "branch-misses" => PerfEventEvent::Hardware(PerfEventHardwareEvent::BranchMisses),
                "bus-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::BusCycles),
                "stalled-cycles-frontend" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::StalledCyclesFrontend)
                }
                "stalled-cycles-backend" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::StalledCyclesBackend)
                }
                "ref-cpu-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::RefCpuCycles),
                _ => {
                    return Err(LoadError::Load(format!(
                        "Unsupported perf_event hardware event: {event_name}. Expected one of cpu-cycles, instructions, cache-references, cache-misses, branch-instructions, branch-misses, bus-cycles, stalled-cycles-frontend, stalled-cycles-backend, ref-cpu-cycles"
                    )));
                }
            },
            _ => {
                return Err(LoadError::Load(format!(
                    "Unsupported perf_event source: {source}. Expected software or hardware"
                )));
            }
        };

        let mut cpu = None;
        let mut pid = None;
        let mut sample_policy = PerfEventSamplePolicy::Period(DEFAULT_PERF_EVENT_PERIOD);

        for option in parts {
            if let Some(raw_cpu) = option.strip_prefix("cpu=") {
                if cpu.is_some() {
                    return Err(LoadError::Load(
                        "perf_event target cannot specify cpu more than once".to_string(),
                    ));
                }
                cpu = Some(raw_cpu.parse::<u32>().map_err(|_| {
                    LoadError::Load(format!("Invalid perf_event cpu selector: {raw_cpu}"))
                })?);
                continue;
            }

            if let Some(raw_pid) = option.strip_prefix("pid=") {
                if pid.is_some() {
                    return Err(LoadError::Load(
                        "perf_event target cannot specify pid more than once".to_string(),
                    ));
                }
                let parsed_pid = raw_pid.parse::<u32>().map_err(|_| {
                    LoadError::Load(format!("Invalid perf_event pid selector: {raw_pid}"))
                })?;
                if parsed_pid == 0 {
                    return Err(LoadError::Load(
                        "perf_event pid selector must be greater than zero".to_string(),
                    ));
                }
                pid = Some(parsed_pid);
                continue;
            }

            if let Some(raw_period) = option.strip_prefix("period=") {
                let period = raw_period.parse::<u64>().map_err(|_| {
                    LoadError::Load(format!("Invalid perf_event period: {raw_period}"))
                })?;
                if period == 0 {
                    return Err(LoadError::Load(
                        "perf_event period must be greater than zero".to_string(),
                    ));
                }
                match sample_policy {
                    PerfEventSamplePolicy::Period(v) if v == DEFAULT_PERF_EVENT_PERIOD => {
                        sample_policy = PerfEventSamplePolicy::Period(period);
                    }
                    _ => {
                        return Err(LoadError::Load(
                            "perf_event target cannot specify both period and freq".to_string(),
                        ));
                    }
                }
                continue;
            }

            if let Some(raw_freq) = option.strip_prefix("freq=") {
                let freq = raw_freq.parse::<u64>().map_err(|_| {
                    LoadError::Load(format!("Invalid perf_event frequency: {raw_freq}"))
                })?;
                if freq == 0 {
                    return Err(LoadError::Load(
                        "perf_event frequency must be greater than zero".to_string(),
                    ));
                }
                if !matches!(
                    sample_policy,
                    PerfEventSamplePolicy::Period(v) if v == DEFAULT_PERF_EVENT_PERIOD
                ) {
                    return Err(LoadError::Load(
                        "perf_event target cannot specify both period and freq".to_string(),
                    ));
                }
                sample_policy = PerfEventSamplePolicy::Frequency(freq);
                continue;
            }

            return Err(LoadError::Load(format!(
                "Unrecognized perf_event selector: {option}. Expected cpu=N, pid=N, period=N, or freq=N"
            )));
        }

        Ok(Self {
            event,
            cpu,
            pid,
            sample_policy,
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

fn validate_trampoline_target(
    validation: KernelTargetValidationKind,
    probe_type: &str,
    func_name: &str,
) -> Result<(), LoadError> {
    let btf = KernelBtf::get();
    let result = match validation {
        KernelTargetValidationKind::FentryTrampoline => btf.validate_fentry_target(func_name),
        KernelTargetValidationKind::FexitTrampoline => btf.validate_fexit_target(func_name),
        KernelTargetValidationKind::LsmHook => btf.validate_lsm_hook_target(func_name),
        KernelTargetValidationKind::SymbolOnly => return Ok(()),
    };

    result.map_err(|e| LoadError::UnsupportedTrampolineTarget {
        probe_type: probe_type.to_string(),
        target: func_name.to_string(),
        reason: e.to_string(),
    })
}

fn validate_network_interface_target(target: &str) -> Result<(), LoadError> {
    if target.is_empty() {
        return Err(LoadError::Load(
            "Network interface target cannot be empty".to_string(),
        ));
    }

    let iface_path = Path::new("/sys/class/net").join(target);
    if iface_path.exists() {
        Ok(())
    } else {
        Err(LoadError::Load(format!(
            "Unknown network interface: {target}"
        )))
    }
}

fn validate_tc_target(target: &str) -> Result<(), LoadError> {
    let parsed = TcTarget::parse(target)?;
    validate_network_interface_target(&parsed.interface)
}

fn validate_cgroup_skb_target(target: &str) -> Result<(), LoadError> {
    let parsed = CgroupSkbTarget::parse(target)?;
    let cgroup_path = Path::new(&parsed.cgroup_path);

    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown cgroup path: {}",
            parsed.cgroup_path
        )));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "cgroup_skb target must be a directory: {}",
            parsed.cgroup_path
        )));
    }

    Ok(())
}

fn validate_cgroup_sock_target(target: &str) -> Result<(), LoadError> {
    let parsed = CgroupSockTarget::parse(target)?;
    let cgroup_path = Path::new(&parsed.cgroup_path);

    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown cgroup path: {}",
            parsed.cgroup_path
        )));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "cgroup_sock target must be a directory: {}",
            parsed.cgroup_path
        )));
    }

    Ok(())
}

fn validate_cgroup_path_target(target: &str) -> Result<(), LoadError> {
    let cgroup_path = Path::new(target);

    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!("Unknown cgroup path: {}", target)));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "cgroup target must be a directory: {}",
            target
        )));
    }

    Ok(())
}

fn validate_cgroup_sockopt_target(target: &str) -> Result<(), LoadError> {
    let parsed = CgroupSockoptTarget::parse(target)?;
    let cgroup_path = Path::new(&parsed.cgroup_path);

    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown cgroup path: {}",
            parsed.cgroup_path
        )));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "cgroup_sockopt target must be a directory: {}",
            parsed.cgroup_path
        )));
    }

    Ok(())
}

fn validate_cgroup_sock_addr_target(target: &str) -> Result<(), LoadError> {
    let parsed = CgroupSockAddrTarget::parse(target)?;
    let cgroup_path = Path::new(&parsed.cgroup_path);

    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown cgroup path: {}",
            parsed.cgroup_path
        )));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "cgroup_sock_addr target must be a directory: {}",
            parsed.cgroup_path
        )));
    }

    Ok(())
}

fn validate_sk_lookup_target(target: &str) -> Result<(), LoadError> {
    let parsed = SkLookupTarget::parse(target)?;
    let netns_path = Path::new(&parsed.netns_path);

    if !netns_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown network namespace path: {}",
            parsed.netns_path
        )));
    }

    if netns_path.is_dir() {
        return Err(LoadError::Load(format!(
            "sk_lookup target must be a network namespace file, not a directory: {}",
            parsed.netns_path
        )));
    }

    Ok(())
}

fn validate_target_for_program_type(
    prog_type: EbpfProgramType,
    target: &str,
) -> Result<(), LoadError> {
    match prog_type.target_kind() {
        ProgramTargetKind::KernelFunction => {
            let validation = prog_type.kernel_target_validation().ok_or_else(|| {
                LoadError::Load(format!(
                    "Program type '{}' is missing kernel target validation metadata",
                    prog_type.canonical_prefix()
                ))
            })?;
            validate_kprobe_target(target)?;
            if !matches!(validation, KernelTargetValidationKind::SymbolOnly) {
                validate_trampoline_target(validation, prog_type.canonical_prefix(), target)?;
            }
            Ok(())
        }
        ProgramTargetKind::LsmHook => {
            if target.is_empty() {
                return Err(LoadError::Load(
                    "LSM hook target cannot be empty".to_string(),
                ));
            }
            KernelBtf::get()
                .validate_lsm_hook_target(target)
                .map_err(|e| LoadError::UnsupportedTrampolineTarget {
                    probe_type: prog_type.canonical_prefix().to_string(),
                    target: target.to_string(),
                    reason: e.to_string(),
                })
        }
        ProgramTargetKind::Tracepoint => validate_tracepoint_target(target),
        ProgramTargetKind::RawTracepoint => Ok(()),
        ProgramTargetKind::UserFunction => {
            UprobeTarget::parse(target)?;
            Ok(())
        }
        ProgramTargetKind::NetworkInterface => validate_network_interface_target(target),
        ProgramTargetKind::PerfEventTarget => {
            let parsed = PerfEventTarget::parse(target)?;
            if let Some(cpu) = parsed.cpu {
                let online = online_cpus().map_err(|(_, e)| {
                    LoadError::Load(format!("Failed to enumerate online CPUs: {e}"))
                })?;
                if !online.contains(&cpu) {
                    return Err(LoadError::Load(format!(
                        "perf_event cpu selector {cpu} is not currently online"
                    )));
                }
            }
            Ok(())
        }
        ProgramTargetKind::NetworkNamespacePath => validate_sk_lookup_target(target),
        ProgramTargetKind::TrafficControlInterface => validate_tc_target(target),
        ProgramTargetKind::CgroupPathAttachType => validate_cgroup_skb_target(target),
        ProgramTargetKind::CgroupPathSockAttachType => validate_cgroup_sock_target(target),
        ProgramTargetKind::CgroupPath => validate_cgroup_path_target(target),
        ProgramTargetKind::CgroupPathSockoptAttachType => validate_cgroup_sockopt_target(target),
        ProgramTargetKind::CgroupPathSockAddrAttachType => validate_cgroup_sock_addr_target(target),
        ProgramTargetKind::StructOpsCallback => validate_struct_ops_value_type(target),
    }
}

fn validate_struct_ops_value_type(value_type_name: &str) -> Result<(), LoadError> {
    if value_type_name.is_empty() {
        return Err(LoadError::Load(
            "struct_ops value type name cannot be empty".to_string(),
        ));
    }

    KernelBtf::get()
        .kernel_named_type_size_bytes(value_type_name)
        .map(|_| ())
        .map_err(|err| {
            LoadError::Load(format!(
                "Unknown struct_ops value type '{value_type_name}': {err}"
            ))
        })
}

/// Parse a probe specification like "kprobe:sys_clone" or "tracepoint:syscalls/sys_enter_read"
///
/// Supported formats:
/// - `kprobe:function_name`
/// - `kretprobe:function_name`
/// - `fentry:function_name`
/// - `fexit:function_name`
/// - `lsm:hook_name`
/// - `tracepoint:category/name`
/// - `raw_tracepoint:name` or `raw_tp:name`
/// - `uprobe:/path/to/binary:function_name`
/// - `uretprobe:/path/to/binary:function_name`
/// - `xdp:interface`
/// - `perf_event:software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N]`
/// - `sk_lookup:/proc/self/ns/net`
/// - `tc:interface:ingress`
/// - `tc:interface:egress`
/// - `cgroup_skb:/path/to/cgroup:ingress`
/// - `cgroup_skb:/path/to/cgroup:egress`
/// - `cgroup_sock:/path/to/cgroup:sock_create`
/// - `cgroup_sock:/path/to/cgroup:sock_release`
/// - `cgroup_sock:/path/to/cgroup:post_bind4`
/// - `cgroup_sock:/path/to/cgroup:post_bind6`
/// - `cgroup_sysctl:/path/to/cgroup`
/// - `cgroup_sockopt:/path/to/cgroup:get`
/// - `cgroup_sockopt:/path/to/cgroup:set`
/// - `cgroup_sock_addr:/path/to/cgroup:connect4`
/// - `uprobe:/path/to/binary:0x1234` (offset-based)
/// - `uprobe:/path/to/binary:function@PID` (PID-filtered)
pub fn parse_program_spec(spec: &str) -> Result<ProgramSpec, LoadError> {
    let Some((prefix, target)) = spec.split_once(':') else {
        return Err(LoadError::Load(format!(
            "Invalid probe spec: {spec}. Expected format: type:target (e.g., kprobe:sys_clone)"
        )));
    };

    let Some(prog_type) = EbpfProgramType::from_spec_prefix(prefix) else {
        return Err(LoadError::Load(format!(
            "Unknown probe type: {prefix}. Supported: {}",
            EbpfProgramType::supported_spec_prefixes().join(", ")
        )));
    };

    validate_target_for_program_type(prog_type, target)?;

    match prog_type {
        EbpfProgramType::Kprobe => Ok(ProgramSpec::Kprobe {
            function: target.to_string(),
        }),
        EbpfProgramType::Kretprobe => Ok(ProgramSpec::Kretprobe {
            function: target.to_string(),
        }),
        EbpfProgramType::Fentry => Ok(ProgramSpec::Fentry {
            function: target.to_string(),
        }),
        EbpfProgramType::Fexit => Ok(ProgramSpec::Fexit {
            function: target.to_string(),
        }),
        EbpfProgramType::Lsm => Ok(ProgramSpec::Lsm {
            hook: target.to_string(),
        }),
        EbpfProgramType::Tracepoint => {
            let (category, name) = target.split_once('/').ok_or_else(|| {
                LoadError::Load(format!(
                    "Invalid tracepoint target: {target}. Expected format: category/name"
                ))
            })?;
            Ok(ProgramSpec::Tracepoint {
                category: category.to_string(),
                name: name.to_string(),
            })
        }
        EbpfProgramType::RawTracepoint => Ok(ProgramSpec::RawTracepoint {
            name: target.to_string(),
        }),
        EbpfProgramType::Uprobe => Ok(ProgramSpec::Uprobe {
            target: UprobeTarget::parse(target)?,
        }),
        EbpfProgramType::Uretprobe => Ok(ProgramSpec::Uretprobe {
            target: UprobeTarget::parse(target)?,
        }),
        EbpfProgramType::Xdp => Ok(ProgramSpec::Xdp {
            interface: target.to_string(),
        }),
        EbpfProgramType::PerfEvent => Ok(ProgramSpec::PerfEvent {
            target: PerfEventTarget::parse(target)?,
        }),
        EbpfProgramType::SkLookup => Ok(ProgramSpec::SkLookup {
            target: SkLookupTarget::parse(target)?,
        }),
        EbpfProgramType::Tc => Ok(ProgramSpec::Tc {
            target: TcTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSkb => Ok(ProgramSpec::CgroupSkb {
            target: CgroupSkbTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSock => Ok(ProgramSpec::CgroupSock {
            target: CgroupSockTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSysctl => Ok(ProgramSpec::CgroupSysctl {
            cgroup_path: target.to_string(),
        }),
        EbpfProgramType::CgroupSockopt => Ok(ProgramSpec::CgroupSockopt {
            target: CgroupSockoptTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSockAddr => Ok(ProgramSpec::CgroupSockAddr {
            target: CgroupSockAddrTarget::parse(target)?,
        }),
        EbpfProgramType::StructOps => Ok(ProgramSpec::StructOps {
            value_type_name: target.to_string(),
        }),
    }
}

pub fn parse_probe_spec(spec: &str) -> Result<(EbpfProgramType, String), LoadError> {
    let Some((prefix, target)) = spec.split_once(':') else {
        return Err(LoadError::Load(format!(
            "Invalid probe spec: {spec}. Expected format: type:target (e.g., kprobe:sys_clone)"
        )));
    };

    let Some(prog_type) = EbpfProgramType::from_spec_prefix(prefix) else {
        return Err(LoadError::Load(format!(
            "Unknown probe type: {prefix}. Supported: {}",
            EbpfProgramType::supported_spec_prefixes().join(", ")
        )));
    };

    parse_program_spec(spec)?;

    Ok((prog_type, target.to_string()))
}
