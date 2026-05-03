use std::fs;
use std::path::Path;

use super::{BtfError, FieldInfo, KernelBtf, TracepointContext, TypeInfo};

impl KernelBtf {
    /// Find the tracefs events directory
    pub(super) fn find_tracefs_events() -> Option<String> {
        // Try common locations for tracefs
        let paths = [
            "/sys/kernel/tracing/events",
            "/sys/kernel/debug/tracing/events",
        ];

        for path in paths {
            if Path::new(path).is_dir() {
                return Some(path.to_string());
            }
        }

        None
    }

    /// Check if tracefs is available
    pub fn has_tracefs(&self) -> bool {
        self.tracefs_events_path.is_some()
    }

    ///
    /// Returns the context layout including field offsets.
    pub fn get_tracepoint_context(
        &self,
        category: &str,
        name: &str,
    ) -> Result<TracepointContext, BtfError> {
        let cache_key = format!("{}/{}", category, name);

        // Check cache first
        {
            let cache = self.tracepoint_cache.read().unwrap();
            if let Some(ctx) = cache.get(&cache_key) {
                return Ok(ctx.clone());
            }
        }

        // Try to read from tracefs
        let ctx = self
            .read_tracepoint_format(category, name)
            .or_else(|_| self.get_wellknown_tracepoint(category, name))?;

        // Cache the result
        {
            let mut cache = self.tracepoint_cache.write().unwrap();
            cache.insert(cache_key, ctx.clone());
        }

        Ok(ctx)
    }

    /// Read tracepoint format from tracefs
    fn read_tracepoint_format(
        &self,
        category: &str,
        name: &str,
    ) -> Result<TracepointContext, BtfError> {
        let events_path = self
            .tracefs_events_path
            .as_ref()
            .ok_or(BtfError::NotAvailable)?;

        let format_path = format!("{}/{}/{}/format", events_path, category, name);
        let content = fs::read_to_string(&format_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BtfError::TracepointNotFound {
                    category: category.into(),
                    name: name.into(),
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                BtfError::TracefsError(format!(
                    "Permission denied reading {}. Try running with sudo.",
                    format_path
                ))
            } else {
                BtfError::TracefsError(e.to_string())
            }
        })?;

        self.parse_format_file(&content, category, name)
    }

    /// Parse a tracefs format file
    ///
    /// Format files look like:
    /// ```text
    /// name: sys_enter_openat
    /// ID: 633
    /// format:
    ///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
    ///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
    ///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
    ///         field:int common_pid;   offset:4;       size:4; signed:1;
    ///
    ///         field:int __syscall_nr; offset:8;       size:4; signed:1;
    ///         field:int dfd;  offset:16;      size:8; signed:0;
    ///         field:const char * filename;    offset:24;      size:8; signed:0;
    /// ```
    pub(super) fn parse_format_file(
        &self,
        content: &str,
        category: &str,
        name: &str,
    ) -> Result<TracepointContext, BtfError> {
        let mut fields = Vec::new();
        let mut max_offset = 0usize;
        let mut in_format_section = false;

        for line in content.lines() {
            let line = line.trim();

            if line == "format:" {
                in_format_section = true;
                continue;
            }

            if !in_format_section {
                continue;
            }

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Parse field line: "field:TYPE NAME; offset:N; size:N; signed:N;"
            if let Some(field) = self.parse_tracepoint_field_line(line, category, name) {
                // Skip common fields (internal tracing header)
                if field.name.starts_with("common_") {
                    continue;
                }

                let end = field.offset + field.size;
                if end > max_offset {
                    max_offset = end;
                }

                fields.push(field);
            }
        }

        if fields.is_empty() {
            return Err(BtfError::FormatParseError(
                "No fields found in format file".into(),
            ));
        }

        Ok(TracepointContext::new(
            category,
            name,
            format!("trace_event_raw_{}", name),
            fields,
            max_offset,
        ))
    }

    /// Parse a single field line from a format file
    pub(super) fn parse_field_line(&self, line: &str) -> Option<FieldInfo> {
        self.parse_field_line_with_context(line, None)
    }

    fn parse_tracepoint_field_line(
        &self,
        line: &str,
        category: &str,
        name: &str,
    ) -> Option<FieldInfo> {
        self.parse_field_line_with_context(line, Some((category, name)))
    }

    fn parse_field_line_with_context(
        &self,
        line: &str,
        tracepoint: Option<(&str, &str)>,
    ) -> Option<FieldInfo> {
        // field:TYPE NAME; offset:N; size:N; signed:N;
        if !line.starts_with("field:") {
            return None;
        }

        let mut field_type = String::new();
        let mut field_name = String::new();
        let mut offset = 0usize;
        let mut size = 0usize;
        let mut signed = false;

        for part in line.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some(rest) = part.strip_prefix("field:") {
                // Parse "TYPE NAME" or "TYPE NAME[N]"
                // The name is the last word, type is everything before
                let rest = rest.trim();
                if let Some(last_space) = rest.rfind(|c: char| c.is_whitespace()) {
                    field_type = rest[..last_space].trim().to_string();
                    field_name = rest[last_space..].trim().to_string();
                    while let Some(stripped) = field_name.strip_prefix('*') {
                        field_type.push_str(" *");
                        field_name = stripped.trim_start().to_string();
                    }
                    // Remove array suffix from name if present
                    if let Some(bracket) = field_name.find('[') {
                        field_name.truncate(bracket);
                    }
                }
            } else if let Some(rest) = part.strip_prefix("offset:") {
                offset = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = part.strip_prefix("size:") {
                size = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = part.strip_prefix("signed:") {
                signed = rest.trim() == "1";
            }
        }

        if field_name.is_empty() || size == 0 {
            return None;
        }

        let type_info = self.infer_type_from_format(&field_type, size, signed, tracepoint);

        Some(FieldInfo {
            name: field_name,
            type_info,
            offset,
            size,
            bitfield: None,
        })
    }

    /// Infer TypeInfo from format file type string
    fn infer_type_from_format(
        &self,
        type_str: &str,
        size: usize,
        signed: bool,
        tracepoint: Option<(&str, &str)>,
    ) -> TypeInfo {
        // Handle pointer types
        if type_str.contains('*') {
            return TypeInfo::Ptr {
                target: Box::new(TypeInfo::Unknown),
                is_user: type_str.contains("__user")
                    || Self::tracepoint_pointer_is_userspace(tracepoint),
            };
        }

        // Handle array types (detected by looking at size vs typical sizes)
        // For syscall args: unsigned long args[6] has size 48
        if type_str.contains('[') || (size > 8 && size.is_multiple_of(8)) {
            let elem_size = 8; // Assume 64-bit elements
            let len = size / elem_size;
            return TypeInfo::Array {
                element: Box::new(TypeInfo::Int {
                    size: elem_size,
                    signed,
                }),
                len,
            };
        }

        // Handle integer types
        TypeInfo::Int { size, signed }
    }

    fn tracepoint_pointer_is_userspace(tracepoint: Option<(&str, &str)>) -> bool {
        let Some((category, name)) = tracepoint else {
            return false;
        };

        // The syscall tracefs format often prints ABI pointer arguments as
        // `const char * filename` without preserving the original `__user`
        // spelling. On syscall-entry tracepoints, pointer-valued arguments are
        // userspace addresses even when that annotation is missing.
        category == "syscalls" && name.starts_with("sys_enter")
    }

    /// Get well-known tracepoint context when tracefs lookup fails
    fn get_wellknown_tracepoint(
        &self,
        category: &str,
        name: &str,
    ) -> Result<TracepointContext, BtfError> {
        // Handle common syscall tracepoints with known layouts
        if category == "syscalls" {
            if name.starts_with("sys_enter") {
                return Ok(TracepointContext::sys_enter(name));
            }
            if name.starts_with("sys_exit") {
                return Ok(TracepointContext::sys_exit(name));
            }
        }

        // No well-known fallback available
        Err(BtfError::TracepointNotFound {
            category: category.into(),
            name: name.into(),
        })
    }

    /// Check if a tracepoint exists
    pub fn tracepoint_exists(&self, category: &str, name: &str) -> bool {
        if let Some(ref events_path) = self.tracefs_events_path {
            let path = format!("{}/{}/{}", events_path, category, name);
            Path::new(&path).is_dir()
        } else {
            false
        }
    }

    /// List available tracepoints in a category
    pub fn list_tracepoints(&self, category: &str) -> Vec<String> {
        let mut tracepoints = Vec::new();

        if let Some(ref events_path) = self.tracefs_events_path {
            let category_path = format!("{}/{}", events_path, category);
            if let Ok(entries) = fs::read_dir(&category_path) {
                for entry in entries.flatten() {
                    if entry.path().is_dir()
                        && let Some(name) = entry.file_name().to_str()
                    {
                        tracepoints.push(name.to_string());
                    }
                }
            }
        }

        tracepoints.sort();
        tracepoints
    }
}
