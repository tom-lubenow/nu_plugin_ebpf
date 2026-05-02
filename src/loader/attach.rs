use super::*;
use aya::programs::perf_event::perf_hw_id;
use object::{Object as _, ObjectSymbol as _, SymbolKind as ObjectSymbolKind};
use std::io::BufRead as _;
use std::process::Command;

fn unsupported_live_attach_error(
    prog_type: crate::compiler::EbpfProgramType,
    requirements: &[crate::compiler::ProgramCompatibilityRequirement],
) -> LoadError {
    let attach_kind = prog_type.attach_kind();
    let detail = attach_kind
        .unsupported_live_attach_detail()
        .unwrap_or("this attach kind has no live attach implementation");
    let requirements = compatibility_requirements_detail(requirements);
    LoadError::Attach(format!(
        "live attach for {} programs is not supported by this loader yet; {}{}; use --dry-run to compile",
        prog_type.canonical_prefix(),
        detail,
        requirements
    ))
}

fn unsupported_cgroup_sock_addr_target_error(target: &CgroupSockAddrTarget) -> LoadError {
    let spec = ProgramSpec::CgroupSockAddr {
        target: target.clone(),
    };
    let requirements = compatibility_requirements_detail(&spec.compatibility_requirements());
    let policy = spec.live_attach_policy();
    let reason = policy
        .note
        .unwrap_or(crate::program_spec::CGROUP_SOCK_ADDR_UNIX_LIVE_ATTACH_UNSUPPORTED);
    LoadError::Attach(format!(
        "live attach for cgroup_sock_addr {} hooks is not supported by this loader yet; {}{}; use --dry-run to compile",
        target.attach_type_name(),
        reason,
        requirements
    ))
}

fn compatibility_requirements_detail(
    requirements: &[crate::compiler::ProgramCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                let mut detail = requirement.description().to_string();
                if let Some(minimum_kernel) = requirement.minimum_kernel() {
                    detail.push_str(&format!(" (kernel>={minimum_kernel})"));
                }
                detail
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; feature requirements: {descriptions}")
    }
}

fn map_compatibility_requirements_detail(
    requirements: &[crate::compiler::MapCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                format!(
                    "{} map support (kernel>={})",
                    requirement.kind().kernel_map_type_name(),
                    requirement.minimum_kernel()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; map requirements: {descriptions}")
    }
}

fn map_value_compatibility_requirements_detail(
    requirements: &[crate::compiler::MapValueCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                format!(
                    "{} (kernel>={})",
                    requirement.description(),
                    requirement.minimum_kernel()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; map-value requirements: {descriptions}")
    }
}

fn global_compatibility_requirements_detail(
    requirements: &[crate::compiler::GlobalCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                format!(
                    "{} (kernel>={})",
                    requirement.description(),
                    requirement.minimum_kernel()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; global requirements: {descriptions}")
    }
}

fn helper_compatibility_requirements_detail(
    requirements: &[crate::compiler::HelperCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                format!(
                    "{} helper support (kernel>={})",
                    requirement.helper().name(),
                    requirement.minimum_kernel()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; helper requirements: {descriptions}")
    }
}

fn kfunc_compatibility_requirements_detail(
    requirements: &[crate::compiler::KfuncCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                let mut detail = format!(
                    "{} kfunc support (kernel>={}",
                    requirement.name(),
                    requirement.minimum_kernel()
                );
                if let Some(maximum) = requirement.maximum_kernel_exclusive() {
                    detail.push_str(&format!(", kernel<{maximum}"));
                }
                detail.push(')');
                detail
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; kfunc requirements: {descriptions}")
    }
}

fn context_field_compatibility_requirements_detail(
    requirements: &[crate::compiler::ContextFieldCompatibilityRequirement],
) -> String {
    if requirements.is_empty() {
        String::new()
    } else {
        let descriptions = requirements
            .iter()
            .map(|requirement| {
                format!(
                    "ctx.{} context field support (kernel>={})",
                    requirement.field().display_name(),
                    requirement.minimum_kernel()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("; context-field requirements: {descriptions}")
    }
}

fn current_kernel_release() -> Option<String> {
    let output = Command::new("uname").arg("-r").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(super) fn kernel_minimum_requirement_detail(
    requirements: &[crate::compiler::ProgramCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::ProgramCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if crate::compiler::ProgramCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "parsed target requires kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_map_minimum_requirement_detail(
    requirements: &[crate::compiler::MapCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::MapCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if crate::compiler::MapCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "compiled maps require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        map_compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_map_value_minimum_requirement_detail(
    requirements: &[crate::compiler::MapValueCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::MapValueCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if crate::compiler::MapValueCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "compiled map-value fields require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        map_value_compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_global_minimum_requirement_detail(
    requirements: &[crate::compiler::GlobalCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::GlobalCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if crate::compiler::GlobalCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "compiled global data sections require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        global_compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_helper_minimum_requirement_detail(
    requirements: &[crate::compiler::HelperCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::HelperCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if crate::compiler::HelperCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "compiled helpers require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        helper_compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_kfunc_minimum_requirement_detail(
    requirements: &[crate::compiler::KfuncCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum =
        crate::compiler::KfuncCompatibilityRequirement::effective_minimum_kernel(requirements)?;
    if !crate::compiler::KfuncCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return Some(format!(
            "compiled kfuncs require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
            kfunc_compatibility_requirements_detail(requirements)
        ));
    }

    let unsupported = requirements
        .iter()
        .find(|requirement| !requirement.supports_kernel(current_kernel))?;
    let unavailable_from = unsupported.maximum_kernel_exclusive()?;
    Some(format!(
        "compiled kfuncs include kfuncs unavailable on kernel>={unavailable_from}; current kernel is {current_kernel}{}; use --dry-run to compile or use a compatible kernel",
        kfunc_compatibility_requirements_detail(requirements)
    ))
}

pub(super) fn kernel_context_field_minimum_requirement_detail(
    requirements: &[crate::compiler::ContextFieldCompatibilityRequirement],
    current_kernel: &str,
) -> Option<String> {
    let minimum = crate::compiler::ContextFieldCompatibilityRequirement::effective_minimum_kernel(
        requirements,
    )?;
    if crate::compiler::ContextFieldCompatibilityRequirement::kernel_version_at_least(
        current_kernel,
        minimum,
    ) {
        return None;
    }

    Some(format!(
        "compiled context fields require kernel>={minimum}; current kernel is {current_kernel}{}; use --dry-run to compile or use a newer kernel",
        context_field_compatibility_requirements_detail(requirements)
    ))
}

fn current_kernel_program_minimum_error(object: &crate::compiler::EbpfObject) -> Option<LoadError> {
    let current_kernel = current_kernel_release()?;
    let requirements = object.program_compatibility_requirements();
    kernel_minimum_requirement_detail(&requirements, &current_kernel).map(LoadError::Attach)
}

fn current_kernel_map_minimum_error(object: &crate::compiler::EbpfObject) -> Option<LoadError> {
    let requirements = object.map_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_map_minimum_requirement_detail(&requirements, &current_kernel).map(LoadError::Attach)
}

fn current_kernel_map_value_minimum_error(
    object: &crate::compiler::EbpfObject,
) -> Option<LoadError> {
    let requirements = object.map_value_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_map_value_minimum_requirement_detail(&requirements, &current_kernel)
        .map(LoadError::Attach)
}

fn current_kernel_global_minimum_error(object: &crate::compiler::EbpfObject) -> Option<LoadError> {
    let requirements = object.global_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_global_minimum_requirement_detail(&requirements, &current_kernel).map(LoadError::Attach)
}

fn current_kernel_helper_minimum_error(object: &crate::compiler::EbpfObject) -> Option<LoadError> {
    let requirements = object.helper_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_helper_minimum_requirement_detail(&requirements, &current_kernel).map(LoadError::Attach)
}

fn current_kernel_kfunc_minimum_error(object: &crate::compiler::EbpfObject) -> Option<LoadError> {
    let requirements = object.kfunc_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_kfunc_minimum_requirement_detail(&requirements, &current_kernel).map(LoadError::Attach)
}

fn current_kernel_context_field_minimum_error(
    object: &crate::compiler::EbpfObject,
) -> Option<LoadError> {
    let requirements = object.context_field_compatibility_requirements();
    if requirements.is_empty() {
        return None;
    }
    let current_kernel = current_kernel_release()?;
    kernel_context_field_minimum_requirement_detail(&requirements, &current_kernel)
        .map(LoadError::Attach)
}

const SYSCALL_SYMBOL_PREFIXES: &[&str] = &[
    "sys_",
    "__x64_sys_",
    "__x32_compat_sys_",
    "__ia32_compat_sys_",
    "__arm64_sys_",
    "__s390x_sys_",
    "__s390_sys_",
];
const MAX_EMULATED_KPROBE_MULTI_ATTACHES: usize = 1024;
const MAX_EMULATED_UPROBE_MULTI_ATTACHES: usize = 1024;

fn syscall_probe_candidate_names(syscall: &str) -> Vec<String> {
    let mut candidates = vec![syscall.to_string()];
    let already_prefixed = SYSCALL_SYMBOL_PREFIXES
        .iter()
        .any(|prefix| syscall.starts_with(prefix));

    if !already_prefixed {
        candidates.extend(
            SYSCALL_SYMBOL_PREFIXES
                .iter()
                .map(|prefix| format!("{prefix}{syscall}")),
        );
    }

    candidates
}

fn syscall_probe_symbols_from_names(syscall: &str, symbols: &HashSet<String>) -> Vec<String> {
    syscall_probe_candidate_names(syscall)
        .into_iter()
        .filter(|candidate| symbols.contains(candidate))
        .collect()
}

fn read_kernel_symbol_names() -> Result<HashSet<String>, LoadError> {
    let file = std::fs::File::open("/proc/kallsyms").map_err(|e| {
        LoadError::Attach(format!(
            "Failed to open /proc/kallsyms for syscall probe resolution: {e}"
        ))
    })?;
    let reader = std::io::BufReader::new(file);
    let mut symbols = HashSet::new();

    for line in reader.lines() {
        let line = line.map_err(|e| {
            LoadError::Attach(format!(
                "Failed to read /proc/kallsyms for syscall probe resolution: {e}"
            ))
        })?;
        if let Some(name) = line.split_whitespace().nth(2) {
            symbols.insert(name.to_string());
        }
    }

    Ok(symbols)
}

fn resolve_syscall_probe_symbols(syscall: &str) -> Result<Vec<String>, LoadError> {
    let symbols = read_kernel_symbol_names()?;
    let candidates = syscall_probe_symbols_from_names(syscall, &symbols);

    if candidates.is_empty() {
        return Err(LoadError::Attach(format!(
            "Failed to resolve syscall probe target '{syscall}' in /proc/kallsyms; tried {}",
            syscall_probe_candidate_names(syscall).join(", ")
        )));
    }

    Ok(candidates)
}

fn wildcard_pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n) = (0, 0);
    let mut star = None;
    let mut star_name = 0;

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_name = n;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_name += 1;
            n = star_name;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

fn kprobe_multi_symbols_from_names(pattern: &str, symbols: &HashSet<String>) -> Vec<String> {
    let mut matches: Vec<String> = symbols
        .iter()
        .filter(|symbol| wildcard_pattern_matches(pattern, symbol))
        .cloned()
        .collect();
    matches.sort();
    matches
}

fn resolve_kprobe_multi_symbols(pattern: &str) -> Result<Vec<String>, LoadError> {
    let symbols = read_kernel_symbol_names()?;
    let matches = kprobe_multi_symbols_from_names(pattern, &symbols);

    if matches.is_empty() {
        return Err(LoadError::Attach(format!(
            "Failed to resolve kprobe.multi pattern '{pattern}' in /proc/kallsyms"
        )));
    }
    if matches.len() > MAX_EMULATED_KPROBE_MULTI_ATTACHES {
        return Err(LoadError::Attach(format!(
            "kprobe.multi pattern '{pattern}' resolved to {} symbols, above this loader's safety cap of {}; refine the pattern or use --dry-run to compile",
            matches.len(),
            MAX_EMULATED_KPROBE_MULTI_ATTACHES
        )));
    }

    Ok(matches)
}

fn uprobe_multi_symbols_from_names(pattern: &str, symbols: &HashSet<String>) -> Vec<String> {
    let mut matches: Vec<String> = symbols
        .iter()
        .filter(|symbol| wildcard_pattern_matches(pattern, symbol))
        .cloned()
        .collect();
    matches.sort();
    matches
}

fn uprobe_symbol_names_from_elf_bytes(
    binary_path: &str,
    bytes: &[u8],
) -> Result<HashSet<String>, LoadError> {
    let file = object::File::parse(bytes).map_err(|e| {
        LoadError::Attach(format!(
            "Failed to parse uprobe.multi target binary {binary_path}: {e}"
        ))
    })?;

    let mut symbols = HashSet::new();
    for symbol in file.symbols() {
        if symbol.kind() == ObjectSymbolKind::Text
            && symbol.is_definition()
            && let Ok(name) = symbol.name()
            && !name.is_empty()
        {
            symbols.insert(name.to_string());
        }
    }
    for symbol in file.dynamic_symbols() {
        if symbol.kind() == ObjectSymbolKind::Text
            && symbol.is_definition()
            && let Ok(name) = symbol.name()
            && !name.is_empty()
        {
            symbols.insert(name.to_string());
        }
    }

    Ok(symbols)
}

fn read_uprobe_symbol_names(binary_path: &str) -> Result<HashSet<String>, LoadError> {
    let bytes = std::fs::read(binary_path).map_err(|e| {
        LoadError::Attach(format!(
            "Failed to read uprobe.multi target binary {binary_path}: {e}"
        ))
    })?;
    uprobe_symbol_names_from_elf_bytes(binary_path, &bytes)
}

fn resolve_uprobe_multi_symbols(
    target: &crate::program_spec::UprobeMultiTarget,
) -> Result<Vec<String>, LoadError> {
    let symbols = read_uprobe_symbol_names(&target.binary_path)?;
    let matches = uprobe_multi_symbols_from_names(&target.function_pattern, &symbols);

    if matches.is_empty() {
        return Err(LoadError::Attach(format!(
            "Failed to resolve uprobe.multi pattern '{}' in {}; no function symbols matched",
            target.function_pattern, target.binary_path
        )));
    }
    if matches.len() > MAX_EMULATED_UPROBE_MULTI_ATTACHES {
        return Err(LoadError::Attach(format!(
            "uprobe.multi pattern '{}' in {} resolved to {} symbols, above this loader's safety cap of {}; refine the pattern or use --dry-run to compile",
            target.function_pattern,
            target.binary_path,
            matches.len(),
            MAX_EMULATED_UPROBE_MULTI_ATTACHES
        )));
    }

    Ok(matches)
}

fn aya_load_compatible_object(object: &EbpfObject) -> EbpfObject {
    let mut object = object.clone();

    for program in &mut object.programs {
        match program.prog_type {
            crate::compiler::EbpfProgramType::Tcx => {
                // Aya 0.13 loads TCX programs through the SCHED_CLS classifier parser.
                // Preserve the public tcx/* model, but feed Aya a section it recognizes.
                program.section_name_override = Some("classifier".to_string());
            }
            crate::compiler::EbpfProgramType::Ksyscall => {
                // Aya's parser has kprobe/kretprobe sections but not libbpf's syscall aliases.
                program.section_name_override = Some("kprobe".to_string());
            }
            crate::compiler::EbpfProgramType::KretSyscall => {
                program.section_name_override = Some("kretprobe".to_string());
            }
            crate::compiler::EbpfProgramType::KprobeMulti => {
                // Aya 0.13 has no native kprobe.multi parser; live attach emulates it.
                program.section_name_override = Some("kprobe".to_string());
            }
            crate::compiler::EbpfProgramType::KretprobeMulti => {
                program.section_name_override = Some("kretprobe".to_string());
            }
            crate::compiler::EbpfProgramType::UprobeMulti => {
                // Aya 0.13 has no native uprobe.multi parser; live attach emulates it.
                program.section_name_override = Some(
                    match program.program_spec.as_ref() {
                        Some(ProgramSpec::UprobeMulti {
                            sleepable: true, ..
                        }) => "uprobe.s",
                        _ => "uprobe",
                    }
                    .to_string(),
                );
            }
            crate::compiler::EbpfProgramType::UretprobeMulti => {
                program.section_name_override = Some(
                    match program.program_spec.as_ref() {
                        Some(ProgramSpec::UretprobeMulti {
                            sleepable: true, ..
                        }) => "uretprobe.s",
                        _ => "uretprobe",
                    }
                    .to_string(),
                );
            }
            _ => {}
        }
    }

    object
}

impl EbpfState {
    fn next_probe_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Load and attach an eBPF program
    pub fn attach(&self, object: &EbpfObject) -> Result<u32, LoadError> {
        self.attach_with_pin(object, None)
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
        object: &EbpfObject,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        self.attach_with_pin_options(object, pin_group, AttachOptions::default())
    }

    pub fn attach_with_pin_options(
        &self,
        object: &EbpfObject,
        pin_group: Option<&str>,
        options: AttachOptions,
    ) -> Result<u32, LoadError> {
        match &object.kind {
            crate::compiler::EbpfObjectKind::Program => {
                self.attach_program_object(object, pin_group)
            }
            crate::compiler::EbpfObjectKind::StructOps {
                name,
                value_type_name,
            } => self.attach_struct_ops_object(object, pin_group, name, value_type_name, options),
        }
    }

    fn attach_program_object(
        &self,
        object: &EbpfObject,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        let program = object.primary_program().map_err(LoadError::from)?;
        let spec = program
            .parsed_program_spec()
            .cloned()
            .or_else(|| {
                ProgramSpec::from_program_type_target(program.prog_type, &program.target).ok()
            })
            .ok_or_else(|| {
                LoadError::Load(format!(
                    "Invalid {} target '{}'",
                    program.prog_type.canonical_prefix(),
                    program.target
                ))
            })?;
        let compatibility_requirements = object.program_compatibility_requirements();
        if !spec.live_attach_policy().loader_supported {
            if let ProgramSpec::CgroupSockAddr { target } = &spec {
                if target.is_unix() {
                    return Err(unsupported_cgroup_sock_addr_target_error(target));
                }
            }
            return Err(unsupported_live_attach_error(
                program.prog_type,
                &compatibility_requirements,
            ));
        }
        if let Some(err) = current_kernel_program_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_map_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_map_value_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_global_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_helper_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_kfunc_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_context_field_minimum_error(object) {
            return Err(err);
        }
        let syscall_probe_symbols = match &spec {
            ProgramSpec::Ksyscall { syscall } | ProgramSpec::KretSyscall { syscall } => {
                Some(resolve_syscall_probe_symbols(syscall)?)
            }
            _ => None,
        };
        let kprobe_multi_symbols = match &spec {
            ProgramSpec::KprobeMulti { pattern } | ProgramSpec::KretprobeMulti { pattern } => {
                Some(resolve_kprobe_multi_symbols(pattern)?)
            }
            _ => None,
        };
        let uprobe_multi_symbols = match &spec {
            ProgramSpec::UprobeMulti { target, .. }
            | ProgramSpec::UretprobeMulti { target, .. } => {
                Some(resolve_uprobe_multi_symbols(target)?)
            }
            _ => None,
        };

        // Generate ELF
        let load_object = aya_load_compatible_object(object);
        let elf_bytes = load_object.to_elf()?;

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

        let mut owned_socket = None;
        // Attach based on program type
        match program.prog_type.attach_kind() {
            ProgramAttachKind::Kprobe | ProgramAttachKind::Kretprobe => {
                let kprobe: &mut KProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.attach(&program.target, 0).map_err(|e| {
                    LoadError::Attach(format!(
                        "Failed to attach {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
            }
            ProgramAttachKind::KprobeMulti | ProgramAttachKind::KretprobeMulti => {
                let symbols = kprobe_multi_symbols.as_ref().unwrap_or_else(|| {
                    unreachable!("kprobe.multi attach kind must resolve target symbols")
                });
                let kprobe: &mut KProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                for symbol in symbols {
                    kprobe.attach(symbol, 0).map_err(|e| {
                        LoadError::Attach(format!(
                            "Failed to attach {} to symbol {symbol}: {e}",
                            program.prog_type.canonical_prefix()
                        ))
                    })?;
                }
            }
            ProgramAttachKind::Ksyscall | ProgramAttachKind::KretSyscall => {
                let symbols = syscall_probe_symbols.as_ref().unwrap_or_else(|| {
                    unreachable!("syscall attach kind must resolve syscall symbols")
                });
                let kprobe: &mut KProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                for symbol in symbols {
                    kprobe.attach(symbol, 0).map_err(|e| {
                        LoadError::Attach(format!(
                            "Failed to attach {} to syscall symbol {symbol}: {e}",
                            program.prog_type.canonical_prefix()
                        ))
                    })?;
                }
            }
            ProgramAttachKind::Fentry => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for fentry: {e}"))
                })?;
                let fentry: &mut FEntry = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to FEntry: {e}")))?;
                fentry
                    .load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load fentry: {e}")))?;
                fentry
                    .attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach fentry: {e}")))?;
            }
            ProgramAttachKind::Fexit => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for fexit: {e}"))
                })?;
                let fexit: &mut FExit = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to FExit: {e}")))?;
                fexit
                    .load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load fexit: {e}")))?;
                fexit
                    .attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach fexit: {e}")))?;
            }
            ProgramAttachKind::TpBtf => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for tp_btf: {e}"))
                })?;
                let tp_btf: &mut BtfTracePoint = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to BtfTracePoint: {e}"))
                })?;
                tp_btf
                    .load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load tp_btf: {e}")))?;
                tp_btf
                    .attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tp_btf: {e}")))?;
            }
            ProgramAttachKind::Tracepoint => {
                let (category, name) = spec.tracepoint_parts().unwrap_or_else(|| {
                    unreachable!("tracepoint attach kind must use tracepoint program spec")
                });

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
            ProgramAttachKind::RawTracepoint => {
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
            ProgramAttachKind::Uprobe | ProgramAttachKind::Uretprobe => {
                let target = spec.uprobe_target().unwrap_or_else(|| {
                    unreachable!("uprobe attach kind must use uprobe program spec")
                });
                let uprobe: &mut UProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                uprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                uprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| {
                        LoadError::Attach(format!(
                            "Failed to attach {}: {e}",
                            program.prog_type.canonical_prefix()
                        ))
                    })?;
            }
            ProgramAttachKind::UprobeMulti | ProgramAttachKind::UretprobeMulti => {
                let target = spec.uprobe_multi_target().unwrap_or_else(|| {
                    unreachable!("uprobe.multi attach kind must use uprobe.multi program spec")
                });
                let symbols = uprobe_multi_symbols.as_ref().unwrap_or_else(|| {
                    unreachable!("uprobe.multi attach kind must resolve target symbols")
                });
                let uprobe: &mut UProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                uprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                for symbol in symbols {
                    uprobe
                        .attach(Some(symbol.as_str()), 0, &target.binary_path, None)
                        .map_err(|e| {
                            LoadError::Attach(format!(
                                "Failed to attach {} to symbol {symbol} in {}: {e}",
                                program.prog_type.canonical_prefix(),
                                target.binary_path
                            ))
                        })?;
                }
            }
            ProgramAttachKind::Lsm => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for lsm: {e}"))
                })?;
                let lsm: &mut Lsm = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to Lsm: {e}")))?;
                lsm.load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load lsm: {e}")))?;
                lsm.attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach lsm: {e}")))?;
            }
            ProgramAttachKind::Xdp => {
                let target = spec
                    .xdp_target()
                    .unwrap_or_else(|| unreachable!("xdp attach kind must use xdp program spec"));
                let xdp: &mut Xdp = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to Xdp: {e}")))?;
                xdp.load()
                    .map_err(|e| LoadError::Load(format!("Failed to load xdp: {e}")))?;
                let flags = match target.attach_mode {
                    crate::program_spec::XdpAttachMode::Skb => XdpFlags::SKB_MODE,
                    crate::program_spec::XdpAttachMode::Driver => XdpFlags::DRV_MODE,
                    crate::program_spec::XdpAttachMode::Hardware => XdpFlags::HW_MODE,
                };
                xdp.attach(&target.interface, flags)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach xdp: {e}")))?;
            }
            ProgramAttachKind::PerfEvent => {
                let target = spec.perf_event_target().unwrap_or_else(|| {
                    unreachable!("perf_event attach kind must use perf_event program spec")
                });
                let perf_event: &mut PerfEvent = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to PerfEvent: {e}")))?;
                perf_event.load().map_err(|e| {
                    LoadError::Load(format!("Failed to load perf_event program: {e}"))
                })?;

                let (perf_type, perf_config) = match target.event {
                    PerfEventEvent::Software(event) => (
                        PerfTypeId::Software,
                        match event {
                            PerfEventSoftwareEvent::CpuClock => {
                                perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64
                            }
                            PerfEventSoftwareEvent::TaskClock => {
                                perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64
                            }
                            PerfEventSoftwareEvent::ContextSwitches => {
                                perf_sw_ids::PERF_COUNT_SW_CONTEXT_SWITCHES as u64
                            }
                            PerfEventSoftwareEvent::CpuMigrations => {
                                perf_sw_ids::PERF_COUNT_SW_CPU_MIGRATIONS as u64
                            }
                            PerfEventSoftwareEvent::PageFaults => {
                                perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS as u64
                            }
                            PerfEventSoftwareEvent::MinorFaults => {
                                perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MIN as u64
                            }
                            PerfEventSoftwareEvent::MajorFaults => {
                                perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MAJ as u64
                            }
                        },
                    ),
                    PerfEventEvent::Hardware(event) => (
                        PerfTypeId::Hardware,
                        match event {
                            PerfEventHardwareEvent::CpuCycles => {
                                perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64
                            }
                            PerfEventHardwareEvent::Instructions => {
                                perf_hw_id::PERF_COUNT_HW_INSTRUCTIONS as u64
                            }
                            PerfEventHardwareEvent::CacheReferences => {
                                perf_hw_id::PERF_COUNT_HW_CACHE_REFERENCES as u64
                            }
                            PerfEventHardwareEvent::CacheMisses => {
                                perf_hw_id::PERF_COUNT_HW_CACHE_MISSES as u64
                            }
                            PerfEventHardwareEvent::BranchInstructions => {
                                perf_hw_id::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64
                            }
                            PerfEventHardwareEvent::BranchMisses => {
                                perf_hw_id::PERF_COUNT_HW_BRANCH_MISSES as u64
                            }
                            PerfEventHardwareEvent::BusCycles => {
                                perf_hw_id::PERF_COUNT_HW_BUS_CYCLES as u64
                            }
                            PerfEventHardwareEvent::StalledCyclesFrontend => {
                                perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND as u64
                            }
                            PerfEventHardwareEvent::StalledCyclesBackend => {
                                perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_BACKEND as u64
                            }
                            PerfEventHardwareEvent::RefCpuCycles => {
                                perf_hw_id::PERF_COUNT_HW_REF_CPU_CYCLES as u64
                            }
                        },
                    ),
                };
                let sample_policy = match target.sample_policy {
                    PerfEventSamplePolicy::Period(period) => SamplePolicy::Period(period),
                    PerfEventSamplePolicy::Frequency(freq) => SamplePolicy::Frequency(freq),
                };

                match (target.cpu, target.pid) {
                    (Some(cpu), Some(pid)) => {
                        perf_event
                            .attach(
                                perf_type,
                                perf_config,
                                PerfEventScope::OneProcessOneCpu { cpu, pid },
                                sample_policy,
                                true,
                            )
                            .map_err(|e| {
                                LoadError::Attach(format!(
                                    "Failed to attach perf_event on pid {pid} cpu {cpu}: {e}"
                                ))
                            })?;
                    }
                    (None, Some(pid)) => {
                        perf_event
                            .attach(
                                perf_type,
                                perf_config,
                                PerfEventScope::OneProcessAnyCpu { pid },
                                sample_policy,
                                true,
                            )
                            .map_err(|e| {
                                LoadError::Attach(format!(
                                    "Failed to attach perf_event on pid {pid}: {e}"
                                ))
                            })?;
                    }
                    (Some(cpu), None) => {
                        perf_event
                            .attach(
                                perf_type,
                                perf_config,
                                PerfEventScope::AllProcessesOneCpu { cpu },
                                sample_policy,
                                true,
                            )
                            .map_err(|e| {
                                LoadError::Attach(format!(
                                    "Failed to attach perf_event on cpu {cpu}: {e}"
                                ))
                            })?;
                    }
                    (None, None) => {
                        let cpus = online_cpus().map_err(|(_, e)| {
                            LoadError::Attach(format!("Failed to enumerate online CPUs: {e}"))
                        })?;

                        for cpu in cpus {
                            perf_event
                                .attach(
                                    perf_type.clone(),
                                    perf_config,
                                    PerfEventScope::AllProcessesOneCpu { cpu },
                                    sample_policy.clone(),
                                    true,
                                )
                                .map_err(|e| {
                                    LoadError::Attach(format!(
                                        "Failed to attach perf_event on cpu {cpu}: {e}"
                                    ))
                                })?;
                        }
                    }
                }
            }
            ProgramAttachKind::SocketFilter => {
                let target = spec.socket_filter_target().unwrap_or_else(|| {
                    unreachable!("socket_filter attach kind must use socket_filter program spec")
                });
                let socket_filter: &mut SocketFilter = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to SocketFilter: {e}"))
                })?;
                socket_filter
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load socket_filter: {e}")))?;
                match target.socket_kind {
                    crate::program_spec::SocketFilterSocketKind::Udp4
                    | crate::program_spec::SocketFilterSocketKind::Udp6 => {
                        let socket = std::net::UdpSocket::bind((
                            target.bind_ip.as_str(),
                            target.bind_port,
                        ))
                        .map_err(|e| {
                            if e.kind() == ErrorKind::PermissionDenied {
                                LoadError::PermissionDenied
                            } else {
                                LoadError::Attach(format!(
                                    "Failed to bind UDP socket {}:{} for socket_filter: {e}",
                                    target.bind_ip, target.bind_port
                                ))
                            }
                        })?;
                        socket_filter.attach(&socket).map_err(|e| {
                            LoadError::Attach(format!("Failed to attach socket_filter: {e}"))
                        })?;
                        owned_socket = Some(OwnedSocket::Udp(socket));
                    }
                    crate::program_spec::SocketFilterSocketKind::Tcp4
                    | crate::program_spec::SocketFilterSocketKind::Tcp6 => {
                        let listener = std::net::TcpListener::bind((
                            target.bind_ip.as_str(),
                            target.bind_port,
                        ))
                        .map_err(|e| {
                            if e.kind() == ErrorKind::PermissionDenied {
                                LoadError::PermissionDenied
                            } else {
                                LoadError::Attach(format!(
                                    "Failed to bind TCP listener {}:{} for socket_filter: {e}",
                                    target.bind_ip, target.bind_port
                                ))
                            }
                        })?;
                        socket_filter.attach(&listener).map_err(|e| {
                            LoadError::Attach(format!("Failed to attach socket_filter: {e}"))
                        })?;
                        owned_socket = Some(OwnedSocket::TcpListener(listener));
                    }
                }
            }
            ProgramAttachKind::SkLookup => {
                let target = spec.sk_lookup_target().unwrap_or_else(|| {
                    unreachable!("sk_lookup attach kind must use sk_lookup program spec")
                });
                let netns = std::fs::File::open(&target.netns_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open network namespace path {}: {e}",
                            target.netns_path
                        ))
                    }
                })?;
                let sk_lookup: &mut SkLookup = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to SkLookup: {e}")))?;
                sk_lookup
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load sk_lookup: {e}")))?;
                sk_lookup
                    .attach(netns)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach sk_lookup: {e}")))?;
            }
            ProgramAttachKind::SkMsg => {
                let map_path = spec.pinned_map_path().unwrap_or_else(|| {
                    unreachable!("sk_msg attach kind must use sk_msg program spec")
                });
                let map = MapData::from_pin(map_path).map_err(|e| {
                    LoadError::Attach(format!("Failed to open pinned sockmap {}: {e}", map_path))
                })?;
                let map_type = map.info().and_then(|info| info.map_type()).map_err(|e| {
                    LoadError::Attach(format!("Failed to inspect pinned map {}: {e}", map_path))
                })?;
                if !matches!(map_type, MapType::SockMap | MapType::SockHash) {
                    return Err(LoadError::Attach(format!(
                        "sk_msg target must be a pinned sockmap or sockhash, got {:?}: {}",
                        map_type, map_path
                    )));
                }

                let sock_map_fd: &SockMapFd =
                    unsafe { &*(map.fd() as *const _ as *const SockMapFd) };
                let sk_msg: &mut SkMsg = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to SkMsg: {e}")))?;
                sk_msg
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load sk_msg: {e}")))?;
                sk_msg
                    .attach(sock_map_fd)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach sk_msg: {e}")))?;
            }
            ProgramAttachKind::SkSkb => {
                let map_path = spec.pinned_map_path().unwrap_or_else(|| {
                    unreachable!("sk_skb attach kind must use sk_skb program spec")
                });
                let map = MapData::from_pin(map_path).map_err(|e| {
                    LoadError::Attach(format!("Failed to open pinned sockmap {}: {e}", map_path))
                })?;
                let map_type = map.info().and_then(|info| info.map_type()).map_err(|e| {
                    LoadError::Attach(format!("Failed to inspect pinned map {}: {e}", map_path))
                })?;
                if !matches!(map_type, MapType::SockMap | MapType::SockHash) {
                    return Err(LoadError::Attach(format!(
                        "sk_skb target must be a pinned sockmap or sockhash, got {:?}: {}",
                        map_type, map_path
                    )));
                }

                let sock_map_fd: &SockMapFd =
                    unsafe { &*(map.fd() as *const _ as *const SockMapFd) };
                let sk_skb: &mut SkSkb = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to SkSkb: {e}")))?;
                sk_skb
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load sk_skb: {e}")))?;
                sk_skb
                    .attach(sock_map_fd)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach sk_skb: {e}")))?;
            }
            ProgramAttachKind::SkSkbParser => {
                let map_path = spec.pinned_map_path().unwrap_or_else(|| {
                    unreachable!("sk_skb_parser attach kind must use sk_skb_parser program spec")
                });
                let map = MapData::from_pin(map_path).map_err(|e| {
                    LoadError::Attach(format!("Failed to open pinned sockmap {}: {e}", map_path))
                })?;
                let map_type = map.info().and_then(|info| info.map_type()).map_err(|e| {
                    LoadError::Attach(format!("Failed to inspect pinned map {}: {e}", map_path))
                })?;
                if !matches!(map_type, MapType::SockMap | MapType::SockHash) {
                    return Err(LoadError::Attach(format!(
                        "sk_skb_parser target must be a pinned sockmap or sockhash, got {:?}: {}",
                        map_type, map_path
                    )));
                }

                let sock_map_fd: &SockMapFd =
                    unsafe { &*(map.fd() as *const _ as *const SockMapFd) };
                let sk_skb: &mut SkSkb = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to SkSkb: {e}")))?;
                sk_skb
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load sk_skb_parser: {e}")))?;
                sk_skb.attach(sock_map_fd).map_err(|e| {
                    LoadError::Attach(format!("Failed to attach sk_skb_parser: {e}"))
                })?;
            }
            ProgramAttachKind::CgroupDevice => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!("cgroup_device attach kind must use cgroup_device program spec")
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let cgroup_device: &mut CgroupDevice = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupDevice: {e}"))
                })?;
                cgroup_device
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_device: {e}")))?;
                cgroup_device
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| {
                        LoadError::Attach(format!("Failed to attach cgroup_device: {e}"))
                    })?;
            }
            ProgramAttachKind::SockOps => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!("sock_ops attach kind must use sock_ops program spec")
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let sock_ops: &mut SockOps = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to SockOps: {e}")))?;
                sock_ops
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load sock_ops: {e}")))?;
                sock_ops
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach sock_ops: {e}")))?;
            }
            ProgramAttachKind::Tc => {
                let target = spec
                    .tc_target()
                    .unwrap_or_else(|| unreachable!("tc attach kind must use tc program spec"));
                let classifier: &mut SchedClassifier = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to SchedClassifier: {e}"))
                })?;
                classifier
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load tc classifier: {e}")))?;
                match tc::qdisc_add_clsact(&target.interface) {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(LoadError::Attach(format!(
                            "Failed to add clsact qdisc on {}: {e}",
                            target.interface
                        )));
                    }
                }
                classifier
                    .attach(&target.interface, target.attach_type)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tc: {e}")))?;
            }
            ProgramAttachKind::Tcx => {
                let target = spec
                    .tc_target()
                    .unwrap_or_else(|| unreachable!("tcx attach kind must use tcx program spec"));
                let classifier: &mut SchedClassifier = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to SchedClassifier: {e}"))
                })?;
                classifier
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load tcx classifier: {e}")))?;
                classifier
                    .attach_with_options(
                        &target.interface,
                        target.attach_type,
                        TcAttachOptions::TcxOrder(LinkOrder::default()),
                    )
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tcx: {e}")))?;
            }
            ProgramAttachKind::CgroupSkb => {
                let target = spec.cgroup_skb_target().unwrap_or_else(|| {
                    unreachable!("cgroup_skb attach kind must use cgroup_skb program spec")
                });
                let cgroup = std::fs::File::open(&target.cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            target.cgroup_path
                        ))
                    }
                })?;
                let cgroup_skb: &mut CgroupSkb = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to CgroupSkb: {e}")))?;
                cgroup_skb
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_skb: {e}")))?;
                cgroup_skb
                    .attach(cgroup, target.attach_type, CgroupAttachMode::Single)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach cgroup_skb: {e}")))?;
            }
            ProgramAttachKind::CgroupSock => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!("cgroup_sock attach kind must use cgroup_sock program spec")
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let cgroup_sock: &mut CgroupSock = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupSock: {e}"))
                })?;
                cgroup_sock
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_sock: {e}")))?;
                cgroup_sock
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach cgroup_sock: {e}")))?;
            }
            ProgramAttachKind::CgroupSysctl => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!("cgroup_sysctl attach kind must use cgroup_sysctl program spec")
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let cgroup_sysctl: &mut CgroupSysctl = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupSysctl: {e}"))
                })?;
                cgroup_sysctl
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_sysctl: {e}")))?;
                cgroup_sysctl
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| {
                        LoadError::Attach(format!("Failed to attach cgroup_sysctl: {e}"))
                    })?;
            }
            ProgramAttachKind::CgroupSockopt => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!("cgroup_sockopt attach kind must use cgroup_sockopt program spec")
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let cgroup_sockopt: &mut CgroupSockopt = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupSockopt: {e}"))
                })?;
                cgroup_sockopt
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_sockopt: {e}")))?;
                cgroup_sockopt
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| {
                        LoadError::Attach(format!("Failed to attach cgroup_sockopt: {e}"))
                    })?;
            }
            ProgramAttachKind::CgroupSockAddr => {
                let cgroup_path = spec.cgroup_path().unwrap_or_else(|| {
                    unreachable!(
                        "cgroup_sock_addr attach kind must use cgroup_sock_addr program spec"
                    )
                });
                let cgroup = std::fs::File::open(cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            cgroup_path
                        ))
                    }
                })?;
                let cgroup_sock_addr: &mut CgroupSockAddr = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupSockAddr: {e}"))
                })?;
                cgroup_sock_addr.load().map_err(|e| {
                    LoadError::Load(format!("Failed to load cgroup_sock_addr: {e}"))
                })?;
                cgroup_sock_addr
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| {
                        LoadError::Attach(format!("Failed to attach cgroup_sock_addr: {e}"))
                    })?;
            }
            ProgramAttachKind::LircMode2 => {
                let target = spec.lirc_mode2_target().unwrap_or_else(|| {
                    unreachable!("lirc_mode2 attach kind must use lirc_mode2 program spec")
                });
                let device = std::fs::File::open(&target.device_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open lirc device {}: {e}",
                            target.device_path
                        ))
                    }
                })?;
                let lirc: &mut LircMode2 = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to LircMode2: {e}")))?;
                lirc.load()
                    .map_err(|e| LoadError::Load(format!("Failed to load lirc_mode2: {e}")))?;
                lirc.attach(&device)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach lirc_mode2: {e}")))?;
            }
            ProgramAttachKind::RawTracepointWritable
            | ProgramAttachKind::FmodRet
            | ProgramAttachKind::LsmCgroup
            | ProgramAttachKind::Netkit
            | ProgramAttachKind::TcAction
            | ProgramAttachKind::SkReuseport
            | ProgramAttachKind::FlowDissector
            | ProgramAttachKind::Netfilter
            | ProgramAttachKind::Lwt
            | ProgramAttachKind::Extension
            | ProgramAttachKind::Syscall
            | ProgramAttachKind::Iter => {
                return Err(unsupported_live_attach_error(
                    program.prog_type,
                    &compatibility_requirements,
                ));
            }
            ProgramAttachKind::StructOps => {
                return Err(LoadError::Load(
                    "struct_ops callbacks are not directly attachable; emit them through a struct_ops object instead"
                        .to_string(),
                ));
            }
        }

        // Check for maps
        let has_ringbuf = ebpf.map("events").is_some();
        let has_counter_map = ebpf.map("counters").is_some();
        let has_string_counter_map = ebpf.map("str_counters").is_some();
        let has_bytes_counter_map = ebpf.map("bytes_counters").is_some();
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
        let probe_spec = format!(
            "{}:{}",
            program.prog_type.canonical_prefix(),
            program.target
        );

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
            aya_ebpf: Some(ebpf),
            struct_ops: None,
            owned_socket,
            has_ringbuf,
            has_counter_map,
            has_string_counter_map,
            has_bytes_counter_map,
            has_histogram_map,
            has_kstack_map,
            has_ustack_map,
            ringbuf,
            event_schema: program.event_schema.clone(),
            bytes_counter_key_schema: program.bytes_counter_key_schema.clone(),
            generic_map_key_types: program.generic_map_key_types.clone(),
            generic_map_max_entries: program.generic_map_max_entries.clone(),
            generic_map_value_types: program.generic_map_value_types.clone(),
            generic_map_value_semantics: program.generic_map_value_semantics.clone(),
            pin_group: pin_group_owned,
        };

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }

    fn attach_struct_ops_object(
        &self,
        object: &EbpfObject,
        pin_group: Option<&str>,
        name: &str,
        value_type_name: &str,
        options: AttachOptions,
    ) -> Result<u32, LoadError> {
        if pin_group.is_some() {
            return Err(LoadError::Load(
                "struct_ops objects do not yet support pinned map sharing".to_string(),
            ));
        }

        let spec = ProgramSpec::StructOps {
            value_type_name: value_type_name.to_string(),
        };
        let policy = spec.live_attach_policy();
        if policy.requires_opt_in && !options.allow_unsafe_struct_ops {
            let reason = policy
                .note
                .unwrap_or("live attach requires explicit opt-in");
            return Err(LoadError::Attach(format!(
                "live attach for struct_ops {value_type_name} requires explicit opt-in; {reason}; use --dry-run to compile or pass --unsafe-struct-ops for an intentional live load"
            )));
        }

        if let Some(err) = current_kernel_program_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_map_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_map_value_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_global_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_helper_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_kfunc_minimum_error(object) {
            return Err(err);
        }
        if let Some(err) = current_kernel_context_field_minimum_error(object) {
            return Err(err);
        }

        let elf_bytes = object.to_elf()?;
        let handle = LibbpfStructOpsHandle::load_and_attach(elf_bytes, name)?;
        let id = self.next_probe_id();

        let active_probe = ActiveProbe {
            id,
            probe_spec: format!("struct_ops:{name}:{value_type_name}"),
            attached_at: Instant::now(),
            aya_ebpf: None,
            struct_ops: Some(handle),
            owned_socket: None,
            has_ringbuf: false,
            has_counter_map: false,
            has_string_counter_map: false,
            has_bytes_counter_map: false,
            has_histogram_map: false,
            has_kstack_map: false,
            has_ustack_map: false,
            ringbuf: None,
            event_schema: None,
            bytes_counter_key_schema: None,
            generic_map_key_types: HashMap::new(),
            generic_map_max_entries: HashMap::new(),
            generic_map_value_types: HashMap::new(),
            generic_map_value_semantics: HashMap::new(),
            pin_group: None,
        };

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya_obj::Object as AyaObject;
    use std::collections::HashSet;

    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};
    use crate::compiler::{EbpfProgram, EbpfProgramType};

    #[test]
    fn test_aya_load_compatible_object_rewrites_tcx_section() {
        let mut builder = EbpfBuilder::new();
        builder
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
            .push(EbpfInsn::exit());
        let object =
            EbpfProgram::new(EbpfProgramType::Tcx, "lo:ingress", "main", builder).into_object();

        assert_eq!(
            object
                .primary_program()
                .expect("object should have a primary program")
                .section_name()
                .expect("tcx section should resolve"),
            "tcx/ingress"
        );

        let load_object = aya_load_compatible_object(&object);

        assert_eq!(
            object
                .primary_program()
                .expect("original object should remain unchanged")
                .section_name()
                .expect("tcx section should resolve"),
            "tcx/ingress"
        );
        assert_eq!(
            load_object
                .primary_program()
                .expect("load object should have a primary program")
                .section_name()
                .expect("loader section should resolve"),
            "classifier"
        );

        let elf = load_object
            .to_elf()
            .expect("loader-compatible object should emit");
        let parsed = AyaObject::parse(&elf).expect("Aya should parse rewritten TCX object");
        assert!(parsed.programs.contains_key("main"));
    }

    #[test]
    fn test_aya_load_compatible_object_rewrites_syscall_sections() {
        for (prog_type, expected_public, expected_loader) in [
            (EbpfProgramType::Ksyscall, "ksyscall/nanosleep", "kprobe"),
            (
                EbpfProgramType::KretSyscall,
                "kretsyscall/nanosleep",
                "kretprobe",
            ),
        ] {
            let mut builder = EbpfBuilder::new();
            builder
                .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
                .push(EbpfInsn::exit());
            let object = EbpfProgram::new(prog_type, "nanosleep", "main", builder).into_object();

            assert_eq!(
                object
                    .primary_program()
                    .expect("object should have a primary program")
                    .section_name()
                    .expect("syscall section should resolve"),
                expected_public
            );

            let load_object = aya_load_compatible_object(&object);
            assert_eq!(
                load_object
                    .primary_program()
                    .expect("load object should have a primary program")
                    .section_name()
                    .expect("loader section should resolve"),
                expected_loader
            );

            let elf = load_object
                .to_elf()
                .expect("loader-compatible object should emit");
            let parsed = AyaObject::parse(&elf).expect("Aya should parse rewritten syscall object");
            assert!(parsed.programs.contains_key("main"));
        }
    }

    #[test]
    fn test_aya_load_compatible_object_rewrites_kprobe_multi_sections() {
        for (prog_type, expected_public, expected_loader) in [
            (EbpfProgramType::KprobeMulti, "kprobe.multi/vfs_*", "kprobe"),
            (
                EbpfProgramType::KretprobeMulti,
                "kretprobe.multi/vfs_*",
                "kretprobe",
            ),
        ] {
            let mut builder = EbpfBuilder::new();
            builder
                .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
                .push(EbpfInsn::exit());
            let object = EbpfProgram::new(prog_type, "vfs_*", "main", builder).into_object();

            assert_eq!(
                object
                    .primary_program()
                    .expect("object should have a primary program")
                    .section_name()
                    .expect("multi-probe section should resolve"),
                expected_public
            );

            let load_object = aya_load_compatible_object(&object);
            assert_eq!(
                load_object
                    .primary_program()
                    .expect("load object should have a primary program")
                    .section_name()
                    .expect("loader section should resolve"),
                expected_loader
            );

            let elf = load_object
                .to_elf()
                .expect("loader-compatible object should emit");
            let parsed =
                AyaObject::parse(&elf).expect("Aya should parse rewritten multi-probe object");
            assert!(parsed.programs.contains_key("main"));
        }
    }

    #[test]
    fn test_aya_load_compatible_object_rewrites_uprobe_multi_sections() {
        for (spec_text, prog_type, expected_public, expected_loader) in [
            (
                "uprobe.multi:/bin/bash:read*",
                EbpfProgramType::UprobeMulti,
                "uprobe.multi//bin/bash:read*",
                "uprobe",
            ),
            (
                "uprobe.multi.s:/bin/bash:read*",
                EbpfProgramType::UprobeMulti,
                "uprobe.multi.s//bin/bash:read*",
                "uprobe.s",
            ),
            (
                "uretprobe.multi:/bin/bash:read*",
                EbpfProgramType::UretprobeMulti,
                "uretprobe.multi//bin/bash:read*",
                "uretprobe",
            ),
            (
                "uretprobe.multi.s:/bin/bash:read*",
                EbpfProgramType::UretprobeMulti,
                "uretprobe.multi.s//bin/bash:read*",
                "uretprobe.s",
            ),
        ] {
            let mut builder = EbpfBuilder::new();
            builder
                .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
                .push(EbpfInsn::exit());
            let spec = ProgramSpec::parse(spec_text).expect("uprobe.multi spec should parse");
            let object = EbpfProgram::new(prog_type, spec.target_string(), "main", builder)
                .with_program_spec(spec)
                .into_object();

            assert_eq!(
                object
                    .primary_program()
                    .expect("object should have a primary program")
                    .section_name()
                    .expect("multi-probe section should resolve"),
                expected_public
            );

            let load_object = aya_load_compatible_object(&object);
            assert_eq!(
                load_object
                    .primary_program()
                    .expect("load object should have a primary program")
                    .section_name()
                    .expect("loader section should resolve"),
                expected_loader
            );

            let elf = load_object
                .to_elf()
                .expect("loader-compatible object should emit");
            let parsed =
                AyaObject::parse(&elf).expect("Aya should parse rewritten user multi-probe object");
            assert!(parsed.programs.contains_key("main"));
        }
    }

    #[test]
    fn test_syscall_probe_symbols_from_names_handles_abi_wrappers() {
        let symbols = HashSet::from([
            "__x64_sys_openat".to_string(),
            "__ia32_compat_sys_openat".to_string(),
            "__x64_sys_close".to_string(),
        ]);

        assert_eq!(
            syscall_probe_symbols_from_names("openat", &symbols),
            vec![
                "__x64_sys_openat".to_string(),
                "__ia32_compat_sys_openat".to_string()
            ]
        );
        assert_eq!(
            syscall_probe_symbols_from_names("__x64_sys_close", &symbols),
            vec!["__x64_sys_close".to_string()]
        );
    }

    #[test]
    fn test_kprobe_multi_symbols_from_names_matches_wildcards() {
        let symbols = HashSet::from([
            "vfs_read".to_string(),
            "vfs_write".to_string(),
            "vfs_statx".to_string(),
            "xfs_read".to_string(),
        ]);

        assert_eq!(
            kprobe_multi_symbols_from_names("vfs_*", &symbols),
            vec![
                "vfs_read".to_string(),
                "vfs_statx".to_string(),
                "vfs_write".to_string()
            ]
        );
        assert_eq!(
            kprobe_multi_symbols_from_names("vfs_?ead", &symbols),
            vec!["vfs_read".to_string()]
        );
        assert!(kprobe_multi_symbols_from_names("tcp_*", &symbols).is_empty());
    }

    #[test]
    fn test_uprobe_multi_symbols_from_names_matches_wildcards() {
        let symbols = HashSet::from([
            "read".to_string(),
            "read_exact".to_string(),
            "pread64".to_string(),
            "write".to_string(),
        ]);

        assert_eq!(
            uprobe_multi_symbols_from_names("read*", &symbols),
            vec!["read".to_string(), "read_exact".to_string()]
        );
        assert_eq!(
            uprobe_multi_symbols_from_names("?read64", &symbols),
            vec!["pread64".to_string()]
        );
        assert!(uprobe_multi_symbols_from_names("open*", &symbols).is_empty());
    }

    #[test]
    fn test_uprobe_symbol_names_from_elf_bytes_reads_text_symbols() {
        let mut builder = EbpfBuilder::new();
        builder
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
            .push(EbpfInsn::exit());
        let object = EbpfProgram::new(EbpfProgramType::Uprobe, "/bin/bash:read", "main", builder)
            .into_object();
        let elf = object.to_elf().expect("test ELF should emit");

        let symbols = uprobe_symbol_names_from_elf_bytes("test-object", &elf)
            .expect("test ELF symbols should parse");

        assert!(symbols.contains("main"));
    }
}
