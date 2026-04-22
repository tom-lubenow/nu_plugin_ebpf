use super::LoadError;
use crate::compiler::{EbpfProgramType, KernelTargetValidationKind};
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};
use crate::program_spec::{ProgramSpec, ProgramSpecParseError};
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

fn validate_kprobe_multi_pattern(pattern: &str) -> Result<(), LoadError> {
    if pattern.is_empty() {
        return Err(LoadError::Load(
            "kprobe multi pattern cannot be empty".to_string(),
        ));
    }

    if pattern
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'*' | b'?'))
    {
        Ok(())
    } else {
        Err(LoadError::Load(format!(
            "Invalid kprobe multi pattern: {pattern}. Allowed characters: ASCII letters, digits, '_', '.', '*', and '?'"
        )))
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
        KernelTargetValidationKind::FmodRetTrampoline => btf.validate_fmod_ret_target(func_name),
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

fn validate_cgroup_directory_target(target_kind: &str, cgroup_path: &str) -> Result<(), LoadError> {
    let cgroup_path = Path::new(cgroup_path);
    if !cgroup_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown cgroup path: {}",
            cgroup_path.display()
        )));
    }

    if !cgroup_path.is_dir() {
        return Err(LoadError::Load(format!(
            "{target_kind} target must be a directory: {}",
            cgroup_path.display()
        )));
    }

    Ok(())
}

fn validate_cgroup_path_target(target: &str) -> Result<(), LoadError> {
    validate_cgroup_directory_target("cgroup", target)
}

fn validate_regular_path_target(
    missing_path_label: &str,
    not_directory_message: &str,
    target_path: &str,
) -> Result<(), LoadError> {
    let map_path = Path::new(target_path);

    if !map_path.exists() {
        return Err(LoadError::Load(format!(
            "Unknown {missing_path_label}: {target_path}"
        )));
    }

    if map_path.is_dir() {
        return Err(LoadError::Load(format!(
            "{not_directory_message}: {target_path}"
        )));
    }

    Ok(())
}

fn validate_lirc_mode2_device(device_path: &str) -> Result<(), LoadError> {
    validate_regular_path_target(
        "lirc device path",
        "lirc_mode2 target must be a device file, not a directory",
        device_path,
    )?;

    let metadata = std::fs::metadata(device_path).map_err(|e| {
        LoadError::Load(format!(
            "Failed to inspect lirc_mode2 target {}: {}",
            device_path, e
        ))
    })?;
    if !metadata.file_type().is_char_device() {
        return Err(LoadError::Load(format!(
            "lirc_mode2 target must be a character device: {}",
            device_path
        )));
    }

    Ok(())
}

fn validate_program_spec(spec: &ProgramSpec) -> Result<(), LoadError> {
    match spec {
        ProgramSpec::Kprobe { function }
        | ProgramSpec::Kretprobe { function }
        | ProgramSpec::Fentry { function, .. }
        | ProgramSpec::Fexit { function, .. }
        | ProgramSpec::FmodRet { function, .. } => {
            let prog_type = spec.program_type();
            let validation = prog_type.kernel_target_validation().ok_or_else(|| {
                LoadError::Load(format!(
                    "Program type '{}' is missing kernel target validation metadata",
                    prog_type.canonical_prefix()
                ))
            })?;
            validate_kprobe_target(function)?;
            if !matches!(validation, KernelTargetValidationKind::SymbolOnly) {
                validate_trampoline_target(validation, prog_type.canonical_prefix(), function)?;
            }
            Ok(())
        }
        ProgramSpec::Ksyscall { syscall } | ProgramSpec::KretSyscall { syscall } => {
            if syscall.is_empty() {
                Err(LoadError::Load(
                    "syscall probe target cannot be empty".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        ProgramSpec::KprobeMulti { pattern } | ProgramSpec::KretprobeMulti { pattern } => {
            validate_kprobe_multi_pattern(pattern)
        }
        ProgramSpec::Lsm { hook, .. } => {
            if hook.is_empty() {
                return Err(LoadError::Load(
                    "LSM hook target cannot be empty".to_string(),
                ));
            }
            KernelBtf::get()
                .validate_lsm_hook_target(hook)
                .map_err(|e| LoadError::UnsupportedTrampolineTarget {
                    probe_type: spec.program_type().canonical_prefix().to_string(),
                    target: hook.clone(),
                    reason: e.to_string(),
                })
        }
        ProgramSpec::TpBtf { name } => {
            if name.is_empty() {
                return Err(LoadError::Load("tp_btf target cannot be empty".to_string()));
            }
            KernelBtf::get().validate_tp_btf_target(name).map_err(|e| {
                LoadError::UnsupportedTrampolineTarget {
                    probe_type: spec.program_type().canonical_prefix().to_string(),
                    target: name.clone(),
                    reason: e.to_string(),
                }
            })
        }
        ProgramSpec::Tracepoint { .. } => validate_tracepoint_target(&spec.target_string()),
        ProgramSpec::RawTracepoint { .. } | ProgramSpec::RawTracepointWritable { .. } => Ok(()),
        ProgramSpec::Extension { target } => {
            if target.function.is_empty() {
                Err(LoadError::Load(
                    "freplace target function cannot be empty".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        ProgramSpec::Syscall { target } => {
            if target.label.is_empty() {
                Err(LoadError::Load(
                    "syscall target label cannot be empty".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        ProgramSpec::Uprobe { .. }
        | ProgramSpec::Uretprobe { .. }
        | ProgramSpec::UprobeMulti { .. }
        | ProgramSpec::UretprobeMulti { .. } => Ok(()),
        ProgramSpec::Xdp { target } => validate_network_interface_target(&target.interface),
        ProgramSpec::PerfEvent { target } => {
            if let Some(cpu) = target.cpu {
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
        ProgramSpec::SocketFilter { .. } => Ok(()),
        ProgramSpec::SkLookup { target } => validate_regular_path_target(
            "network namespace path",
            "sk_lookup target must be a network namespace file, not a directory",
            &target.netns_path,
        ),
        ProgramSpec::FlowDissector { target } => validate_regular_path_target(
            "network namespace path",
            "flow_dissector target must be a network namespace file, not a directory",
            &target.netns_path,
        ),
        ProgramSpec::Netfilter { .. } => Ok(()),
        ProgramSpec::LwtIn { .. }
        | ProgramSpec::LwtOut { .. }
        | ProgramSpec::LwtXmit { .. }
        | ProgramSpec::LwtSeg6Local { .. } => Ok(()),
        ProgramSpec::SkReuseport { .. } => Ok(()),
        ProgramSpec::SkMsg { .. } | ProgramSpec::SkSkb { .. } | ProgramSpec::SkSkbParser { .. } => {
            let map_path = spec.pinned_map_path().unwrap_or_else(|| {
                unreachable!("socket map program specs must carry a pinned map path")
            });
            validate_regular_path_target(
                "pinned sockmap path",
                "target must be a pinned sockmap or sockhash file, not a directory",
                map_path,
            )
        }
        ProgramSpec::CgroupDevice { .. }
        | ProgramSpec::SockOps { .. }
        | ProgramSpec::CgroupSysctl { .. } => {
            let cgroup_path = spec
                .cgroup_path()
                .unwrap_or_else(|| unreachable!("cgroup program specs must carry a cgroup path"));
            validate_cgroup_path_target(cgroup_path)
        }
        ProgramSpec::Tc { target } => validate_network_interface_target(&target.interface),
        ProgramSpec::TcAction { .. } => Ok(()),
        ProgramSpec::CgroupSkb { target } => {
            validate_cgroup_directory_target("cgroup_skb", &target.cgroup_path)
        }
        ProgramSpec::CgroupSock { target } => {
            validate_cgroup_directory_target("cgroup_sock", &target.cgroup_path)
        }
        ProgramSpec::CgroupSockopt { target } => {
            validate_cgroup_directory_target("cgroup_sockopt", &target.cgroup_path)
        }
        ProgramSpec::CgroupSockAddr { target } => {
            validate_cgroup_directory_target("cgroup_sock_addr", &target.cgroup_path)
        }
        ProgramSpec::LircMode2 { target } => validate_lirc_mode2_device(&target.device_path),
        ProgramSpec::StructOps { value_type_name }
        | ProgramSpec::StructOpsCallback {
            value_type_name, ..
        } => validate_struct_ops_value_type(value_type_name),
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
/// - `kprobe.multi:function_pattern`
/// - `kretprobe.multi:function_pattern`
/// - `ksyscall:syscall_name`
/// - `kretsyscall:syscall_name`
/// - `fentry:function_name`
/// - `fexit:function_name`
/// - `fmod_ret:function_name`
/// - `lsm:hook_name`
/// - `freplace:function_name` (or `extension:function_name`)
/// - `syscall:label`
/// - `tracepoint:category/name`
/// - `raw_tracepoint:name` or `raw_tp:name`
/// - `uprobe:/path/to/binary:function_name`
/// - `uprobe.s:/path/to/binary:function_name`
/// - `uretprobe:/path/to/binary:function_name`
/// - `uretprobe.s:/path/to/binary:function_name`
/// - `uprobe.multi:/path/to/binary:function_pattern`
/// - `uprobe.multi.s:/path/to/binary:function_pattern`
/// - `uretprobe.multi:/path/to/binary:function_pattern`
/// - `uretprobe.multi.s:/path/to/binary:function_pattern`
/// - `xdp:interface`, `xdp:interface:frags`, or `xdp:interface:drv:frags`
/// - `perf_event:software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N]`
/// - `socket_filter:udp4:127.0.0.1:31337`
/// - `sk_lookup:/proc/self/ns/net`
/// - `flow_dissector:/proc/self/ns/net`
/// - `sk_reuseport:select` or `sk_reuseport:migrate`
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
    let program_spec = ProgramSpec::parse(spec).map_err(parse_error)?;
    validate_program_spec(&program_spec)?;
    Ok(program_spec)
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
