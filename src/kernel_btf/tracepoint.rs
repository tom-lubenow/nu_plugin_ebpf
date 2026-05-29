//! Tracepoint context information from kernel BTF

use super::types::{FieldInfo, TypeInfo};

const SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL: &str = "4.7";
const SYSCALL_TRACEPOINT_FALLBACK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h";
const OPENAT2_MIN_KERNEL: &str = "5.6";
const OPENAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/fs/open.c";

/// Source used to construct a tracepoint context layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracepointContextSource {
    TracefsFormat,
    WellKnownSyscallFallback,
}

impl TracepointContextSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::TracefsFormat => "tracefs-format",
            Self::WellKnownSyscallFallback => "well-known-syscall-fallback",
        }
    }

    pub fn minimum_kernel(self) -> Option<&'static str> {
        match self {
            Self::TracefsFormat => None,
            // BPF tracepoint programs require Linux 4.7. The syscall tracepoint
            // layout predates that, but 4.7 is the earliest useful eBPF floor.
            Self::WellKnownSyscallFallback => Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
        }
    }

    pub fn minimum_kernel_source(self) -> Option<&'static str> {
        match self {
            Self::TracefsFormat => None,
            Self::WellKnownSyscallFallback => Some(SYSCALL_TRACEPOINT_FALLBACK_SOURCE),
        }
    }
}

/// Tracepoint context layout from kernel BTF
///
/// Tracepoints have structured contexts (not pt_regs like kprobes).
/// The context is a struct named `trace_event_raw_<tracepoint_name>`.
#[derive(Debug, Clone)]
pub struct TracepointContext {
    /// The full struct name (e.g., "trace_event_raw_sys_enter")
    pub struct_name: String,
    /// The tracepoint category (e.g., "syscalls")
    pub category: String,
    /// The tracepoint name (e.g., "sys_enter_openat")
    pub name: String,
    /// Available fields in the context
    pub fields: Vec<FieldInfo>,
    /// Total size of the context struct
    pub size: usize,
    /// Where the layout metadata came from.
    pub source: TracepointContextSource,
    /// Path to the tracefs format file when this layout was read from tracefs.
    pub source_path: Option<String>,
    /// Compatibility floor for this specific tracepoint layout, when known.
    pub minimum_kernel: Option<&'static str>,
    /// Source for the compatibility floor.
    pub minimum_kernel_source: Option<&'static str>,
}

impl TracepointContext {
    /// Create a new tracepoint context
    pub fn new(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
    ) -> Self {
        Self::new_with_source(
            category,
            name,
            struct_name,
            fields,
            size,
            TracepointContextSource::TracefsFormat,
            None,
        )
    }

    /// Create a new tracepoint context with explicit provenance.
    pub fn new_with_source(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
        source: TracepointContextSource,
        source_path: Option<String>,
    ) -> Self {
        Self::new_with_source_and_minimum_kernel(
            category,
            name,
            struct_name,
            fields,
            size,
            source,
            source_path,
            source.minimum_kernel(),
            source.minimum_kernel_source(),
        )
    }

    /// Create a new tracepoint context with explicit provenance and compatibility metadata.
    pub fn new_with_source_and_minimum_kernel(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
        source: TracepointContextSource,
        source_path: Option<String>,
        minimum_kernel: Option<&'static str>,
        minimum_kernel_source: Option<&'static str>,
    ) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            struct_name: struct_name.into(),
            fields,
            size,
            source,
            source_path,
            minimum_kernel,
            minimum_kernel_source,
        }
    }

    /// Minimum kernel for the specific tracepoint, including syscall existence
    /// when the layout came from a well-known syscall fallback.
    pub fn minimum_kernel(&self) -> Option<&'static str> {
        self.minimum_kernel
    }

    /// Source for the specific tracepoint compatibility floor.
    pub fn minimum_kernel_source(&self) -> Option<&'static str> {
        self.minimum_kernel_source
    }

    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Check if a field exists
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }

    /// Get field names for error messages
    pub fn field_names(&self) -> Vec<&str> {
        self.fields.iter().map(|f| f.name.as_str()).collect()
    }
}

/// Well-known syscall tracepoint contexts
///
/// These are fallback definitions for common tracepoints when BTF lookup fails.
/// Based on kernel's include/trace/events/syscalls.h
impl TracepointContext {
    /// Create context for sys_enter tracepoints
    ///
    /// Layout: trace_event_raw_sys_enter { trace_entry ent; long id; unsigned long args[6]; }
    pub fn sys_enter(name: &str) -> Self {
        // trace_entry is 8 bytes (type u16 + flags u8 + preempt_count u8 + pid i32)
        // Then: id (8 bytes), args[6] (48 bytes)
        let mut fields = vec![
            FieldInfo {
                name: "id".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 8, // After trace_entry
                size: 8,
                bitfield: None,
            },
            FieldInfo {
                name: "args".into(),
                type_info: TypeInfo::Array {
                    element: Box::new(TypeInfo::Int {
                        size: 8,
                        signed: false,
                    }),
                    len: 6,
                },
                offset: 16, // After id
                size: 48,
                bitfield: None,
            },
        ];
        fields.extend(Self::well_known_sys_enter_arg_fields(name));

        let (minimum_kernel, minimum_kernel_source) = Self::syscall_fallback_minimum_kernel(name);

        Self::new_with_source_and_minimum_kernel(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            64, // 8 + 8 + 48
            TracepointContextSource::WellKnownSyscallFallback,
            None,
            minimum_kernel,
            minimum_kernel_source,
        )
    }

    fn syscall_fallback_minimum_kernel(name: &str) -> (Option<&'static str>, Option<&'static str>) {
        let syscall = name
            .strip_prefix("sys_enter_")
            .or_else(|| name.strip_prefix("sys_exit_"));
        match syscall {
            Some("openat2") => (Some(OPENAT2_MIN_KERNEL), Some(OPENAT2_SOURCE)),
            _ => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(SYSCALL_TRACEPOINT_FALLBACK_SOURCE),
            ),
        }
    }

    fn sys_enter_arg_field(index: usize, name: &str, type_info: TypeInfo) -> Option<FieldInfo> {
        if index >= 6 {
            return None;
        }
        Some(FieldInfo {
            name: name.into(),
            type_info,
            offset: 16 + index * 8,
            size: 8,
            bitfield: None,
        })
    }

    fn syscall_arg_int(signed: bool) -> TypeInfo {
        TypeInfo::Int { size: 8, signed }
    }

    fn syscall_arg_user_ptr() -> TypeInfo {
        TypeInfo::Ptr {
            target: Box::new(TypeInfo::Unknown),
            is_user: true,
        }
    }

    fn well_known_sys_enter_arg_fields(name: &str) -> Vec<FieldInfo> {
        let Some(syscall) = name.strip_prefix("sys_enter_") else {
            return Vec::new();
        };
        let fields: Vec<(&str, TypeInfo)> = match syscall {
            "read" | "write" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("buf", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
            ],
            "close" => vec![("fd", Self::syscall_arg_int(false))],
            "openat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "openat2" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("how", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
            ],
            "execve" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("argv", Self::syscall_arg_user_ptr()),
                ("envp", Self::syscall_arg_user_ptr()),
            ],
            _ => return Vec::new(),
        };

        fields
            .iter()
            .enumerate()
            .filter_map(|(idx, (name, ty))| Self::sys_enter_arg_field(idx, name, ty.clone()))
            .collect()
    }

    /// Create context for sys_exit tracepoints
    ///
    /// Layout: trace_event_raw_sys_exit { trace_entry ent; long id; long ret; }
    pub fn sys_exit(name: &str) -> Self {
        let fields = vec![
            FieldInfo {
                name: "id".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 8,
                size: 8,
                bitfield: None,
            },
            FieldInfo {
                name: "ret".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 16,
                size: 8,
                bitfield: None,
            },
        ];

        let (minimum_kernel, minimum_kernel_source) = Self::syscall_fallback_minimum_kernel(name);

        Self::new_with_source_and_minimum_kernel(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            24,
            TracepointContextSource::WellKnownSyscallFallback,
            None,
            minimum_kernel,
            minimum_kernel_source,
        )
    }
}
