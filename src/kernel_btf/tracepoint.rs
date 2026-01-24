//! Tracepoint context information from kernel BTF

use super::types::{FieldInfo, TypeInfo};

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
        Self {
            category: category.into(),
            name: name.into(),
            struct_name: struct_name.into(),
            fields,
            size,
        }
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
        let fields = vec![
            FieldInfo {
                name: "id".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 8, // After trace_entry
                size: 8,
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
            },
        ];

        Self::new(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            64, // 8 + 8 + 48
        )
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
            },
            FieldInfo {
                name: "ret".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 16,
                size: 8,
            },
        ];

        Self::new(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            24,
        )
    }
}
