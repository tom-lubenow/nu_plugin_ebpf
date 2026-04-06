use super::LoadError;
use crate::compiler::{EbpfProgramType, KernelTargetValidationKind, ProgramTargetKind};
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};
use crate::program_spec::{
    CgroupSkbTarget, CgroupSockAddrTarget, ProgramSpec, TcTarget, UprobeTarget,
};
use aya::programs::{CgroupSkbAttachType, CgroupSockAddrAttachType, TcAttachType};
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
        ProgramTargetKind::Tracepoint => validate_tracepoint_target(target),
        ProgramTargetKind::RawTracepoint => Ok(()),
        ProgramTargetKind::UserFunction => {
            UprobeTarget::parse(target)?;
            Ok(())
        }
        ProgramTargetKind::NetworkInterface => validate_network_interface_target(target),
        ProgramTargetKind::TrafficControlInterface => validate_tc_target(target),
        ProgramTargetKind::CgroupPathAttachType => validate_cgroup_skb_target(target),
        ProgramTargetKind::CgroupPathSockAddrAttachType => validate_cgroup_sock_addr_target(target),
    }
}

/// Parse a probe specification like "kprobe:sys_clone" or "tracepoint:syscalls/sys_enter_read"
///
/// Supported formats:
/// - `kprobe:function_name`
/// - `kretprobe:function_name`
/// - `fentry:function_name`
/// - `fexit:function_name`
/// - `tracepoint:category/name`
/// - `raw_tracepoint:name` or `raw_tp:name`
/// - `uprobe:/path/to/binary:function_name`
/// - `uretprobe:/path/to/binary:function_name`
/// - `xdp:interface`
/// - `tc:interface:ingress`
/// - `tc:interface:egress`
/// - `cgroup_skb:/path/to/cgroup:ingress`
/// - `cgroup_skb:/path/to/cgroup:egress`
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
        EbpfProgramType::Tc => Ok(ProgramSpec::Tc {
            target: TcTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSkb => Ok(ProgramSpec::CgroupSkb {
            target: CgroupSkbTarget::parse(target)?,
        }),
        EbpfProgramType::CgroupSockAddr => Ok(ProgramSpec::CgroupSockAddr {
            target: CgroupSockAddrTarget::parse(target)?,
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
