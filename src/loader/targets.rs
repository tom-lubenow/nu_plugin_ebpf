use super::LoadError;
use crate::compiler::{EbpfProgramType, KernelTargetValidationKind, ProgramTargetKind};
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};
use crate::program_spec::{
    CgroupSkbTarget, CgroupSockAddrTarget, CgroupSockTarget, CgroupSockoptTarget, LircMode2Target,
    PerfEventTarget, ProgramSpec, ProgramSpecParseError, SkLookupTarget, SocketFilterTarget,
    TcTarget, UprobeTarget,
};
use aya::util::online_cpus;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

fn parse_error(err: ProgramSpecParseError) -> LoadError {
    LoadError::Load(err.to_string())
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
    let parsed = TcTarget::parse(target).map_err(parse_error)?;
    validate_network_interface_target(&parsed.interface)
}

fn validate_cgroup_skb_target(target: &str) -> Result<(), LoadError> {
    let parsed = CgroupSkbTarget::parse(target).map_err(parse_error)?;
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
    let parsed = CgroupSockTarget::parse(target).map_err(parse_error)?;
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
    let parsed = CgroupSockoptTarget::parse(target).map_err(parse_error)?;
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
    let parsed = CgroupSockAddrTarget::parse(target).map_err(parse_error)?;
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
    let parsed = SkLookupTarget::parse(target).map_err(parse_error)?;
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

fn validate_pinned_sockmap_target(target: &str) -> Result<(), LoadError> {
    let map_path = Path::new(target);

    if !map_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown pinned sockmap path: {}",
            target
        )));
    }

    if map_path.is_dir() {
        return Err(LoadError::Load(format!(
            "target must be a pinned sockmap or sockhash file, not a directory: {}",
            target
        )));
    }

    Ok(())
}

fn validate_socket_filter_target(target: &str) -> Result<(), LoadError> {
    SocketFilterTarget::parse(target).map_err(parse_error)?;
    Ok(())
}

fn validate_lirc_mode2_target(target: &str) -> Result<(), LoadError> {
    let parsed = LircMode2Target::parse(target).map_err(parse_error)?;
    let device_path = Path::new(&parsed.device_path);

    if !device_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown lirc device path: {}",
            parsed.device_path
        )));
    }

    if device_path.is_dir() {
        return Err(LoadError::Load(format!(
            "lirc_mode2 target must be a device file, not a directory: {}",
            parsed.device_path
        )));
    }

    let metadata = std::fs::metadata(device_path).map_err(|e| {
        LoadError::Load(format!(
            "Failed to inspect lirc_mode2 target {}: {}",
            parsed.device_path, e
        ))
    })?;
    if !metadata.file_type().is_char_device() {
        return Err(LoadError::Load(format!(
            "lirc_mode2 target must be a character device: {}",
            parsed.device_path
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
        ProgramTargetKind::BtfTracepoint => {
            if target.is_empty() {
                return Err(LoadError::Load("tp_btf target cannot be empty".to_string()));
            }
            KernelBtf::get()
                .validate_tp_btf_target(target)
                .map_err(|e| LoadError::UnsupportedTrampolineTarget {
                    probe_type: prog_type.canonical_prefix().to_string(),
                    target: target.to_string(),
                    reason: e.to_string(),
                })
        }
        ProgramTargetKind::Tracepoint => validate_tracepoint_target(target),
        ProgramTargetKind::RawTracepoint => Ok(()),
        ProgramTargetKind::UserFunction => {
            UprobeTarget::parse(target).map_err(parse_error)?;
            Ok(())
        }
        ProgramTargetKind::NetworkInterface => validate_network_interface_target(target),
        ProgramTargetKind::PerfEventTarget => {
            let parsed = PerfEventTarget::parse(target).map_err(parse_error)?;
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
        ProgramTargetKind::SocketFilterTarget => validate_socket_filter_target(target),
        ProgramTargetKind::NetworkNamespacePath => validate_sk_lookup_target(target),
        ProgramTargetKind::PinnedSockMapPath => validate_pinned_sockmap_target(target),
        ProgramTargetKind::TrafficControlInterface => validate_tc_target(target),
        ProgramTargetKind::CgroupPathAttachType => validate_cgroup_skb_target(target),
        ProgramTargetKind::CgroupPathSockAttachType => validate_cgroup_sock_target(target),
        ProgramTargetKind::CgroupPath => validate_cgroup_path_target(target),
        ProgramTargetKind::CgroupPathSockoptAttachType => validate_cgroup_sockopt_target(target),
        ProgramTargetKind::CgroupPathSockAddrAttachType => validate_cgroup_sock_addr_target(target),
        ProgramTargetKind::LircDevicePath => validate_lirc_mode2_target(target),
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
/// - `socket_filter:udp4:127.0.0.1:31337`
/// - `sk_lookup:/proc/self/ns/net`
/// - `sk_msg:/sys/fs/bpf/pinned_sockmap`
/// - `cgroup_device:/path/to/cgroup`
/// - `sock_ops:/path/to/cgroup`
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
/// - `lirc_mode2:/dev/lirc0`
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
    ProgramSpec::from_program_type_target(prog_type, target).map_err(parse_error)
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
