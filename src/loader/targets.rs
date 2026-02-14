use super::LoadError;
use crate::compiler::EbpfProgramType;
use crate::kernel_btf::{FunctionCheckResult, KernelBtf};

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
