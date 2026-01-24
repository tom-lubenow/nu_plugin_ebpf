//! Kernel BTF service
//!
//! Provides access to kernel type information for eBPF programs.
//! Uses multiple sources:
//! - Tracefs format files for tracepoint layouts
//! - Kernel BTF for function validation (future)
//! - Well-known fallback layouts for common tracepoints

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

use btf::Btf;

use super::pt_regs::{PtRegsError, PtRegsOffsets, fallback_offsets, offsets_from_btf};
use super::tracepoint::TracepointContext;
use super::types::{FieldInfo, TypeInfo};

/// Global kernel BTF instance
static KERNEL_BTF: OnceLock<KernelBtf> = OnceLock::new();

/// Errors that can occur when working with kernel BTF
#[derive(Debug, Clone)]
pub enum BtfError {
    /// BTF is not available on this system
    NotAvailable,
    /// Failed to read tracefs
    TracefsError(String),
    /// Type not found
    TypeNotFound(String),
    /// Tracepoint not found
    TracepointNotFound { category: String, name: String },
    /// Failed to parse format file
    FormatParseError(String),
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtfError::NotAvailable => write!(f, "Kernel type information not available"),
            BtfError::TracefsError(msg) => write!(f, "Tracefs error: {}", msg),
            BtfError::TypeNotFound(name) => write!(f, "Type '{}' not found", name),
            BtfError::TracepointNotFound { category, name } => {
                write!(f, "Tracepoint '{}/{}' not found", category, name)
            }
            BtfError::FormatParseError(msg) => write!(f, "Format parse error: {}", msg),
        }
    }
}

impl std::error::Error for BtfError {}

/// Result of checking if a function exists
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionCheckResult {
    /// Function exists and can be probed
    Exists,
    /// Function does not exist (with suggestions for similar names)
    NotFound { suggestions: Vec<String> },
    /// Cannot validate - need elevated privileges to read function list
    NeedsSudo,
    /// Cannot validate - function list not available (old kernel, etc.)
    CannotValidate,
}

/// Result of reading the function list (internal use)
#[derive(Clone)]
enum FunctionListResult {
    /// Successfully loaded function list
    Loaded(Vec<String>),
    /// File exists but couldn't be read (permission denied)
    PermissionDenied,
    /// File doesn't exist or path not configured
    NotAvailable,
}

/// Service for querying kernel type information
///
/// This is a singleton that provides access to:
/// - Tracepoint context layouts from tracefs
/// - Well-known fallback layouts for common tracepoints
/// - Function existence checks for kprobe validation
pub struct KernelBtf {
    /// Path to tracefs events directory
    tracefs_events_path: Option<String>,
    /// Path to available_filter_functions file
    available_filter_functions_path: Option<String>,
    /// Cached tracepoint contexts
    tracepoint_cache: RwLock<HashMap<String, TracepointContext>>,
    /// Cached function list result (lazy loaded)
    function_cache: RwLock<Option<FunctionListResult>>,
    /// Cached pt_regs offsets (lazy loaded)
    pt_regs_cache: RwLock<Option<Result<PtRegsOffsets, PtRegsError>>>,
}

impl KernelBtf {
    /// Get the global kernel BTF instance
    pub fn get() -> &'static KernelBtf {
        KERNEL_BTF.get_or_init(|| {
            // Find tracefs mount point
            let tracefs_path = Self::find_tracefs_events();
            let filter_funcs_path = Self::find_available_filter_functions();

            KernelBtf {
                tracefs_events_path: tracefs_path,
                available_filter_functions_path: filter_funcs_path,
                tracepoint_cache: RwLock::new(HashMap::new()),
                function_cache: RwLock::new(None),
                pt_regs_cache: RwLock::new(None),
            }
        })
    }

    /// Find the tracefs events directory
    fn find_tracefs_events() -> Option<String> {
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

    /// Find the available_filter_functions file
    fn find_available_filter_functions() -> Option<String> {
        let paths = [
            "/sys/kernel/tracing/available_filter_functions",
            "/sys/kernel/debug/tracing/available_filter_functions",
        ];

        for path in paths {
            if Path::new(path).is_file() {
                return Some(path.to_string());
            }
        }

        None
    }

    /// Check if tracefs is available
    pub fn has_tracefs(&self) -> bool {
        self.tracefs_events_path.is_some()
    }

    /// Check if function validation is available
    pub fn has_function_list(&self) -> bool {
        self.available_filter_functions_path.is_some()
    }

    /// Resolve pt_regs argument/return offsets from kernel BTF, with fallback support.
    pub fn pt_regs_offsets(&self) -> Result<PtRegsOffsets, PtRegsError> {
        {
            let cache = self.pt_regs_cache.read().unwrap();
            if let Some(ref cached) = *cache {
                return cached.clone();
            }
        }

        let resolved = self.resolve_pt_regs_offsets();

        {
            let mut cache = self.pt_regs_cache.write().unwrap();
            *cache = Some(resolved.clone());
        }

        resolved
    }

    fn resolve_pt_regs_offsets(&self) -> Result<PtRegsOffsets, PtRegsError> {
        let offsets = self
            .load_kernel_btf()
            .and_then(|btf| offsets_from_btf(&btf));

        match offsets {
            Ok(offsets) => Ok(offsets),
            Err(err) => match fallback_offsets() {
                Some(fallback) => Ok(fallback),
                None => Err(PtRegsError::new(format!(
                    "{err}; no fallback offsets for this architecture"
                ))),
            },
        }
    }

    fn load_kernel_btf(&self) -> Result<Btf, PtRegsError> {
        let path = "/sys/kernel/btf/vmlinux";
        Btf::from_file(path).map_err(|e| PtRegsError::new(format!("failed to parse {path}: {e}")))
    }

    /// Load the list of available kernel functions (lazy, cached)
    fn load_function_list(&self) -> FunctionListResult {
        // Check if already loaded
        {
            let cache = self.function_cache.read().unwrap();
            if let Some(ref result) = *cache {
                return result.clone();
            }
        }

        // Load from file
        let result = self.read_available_functions();

        // Cache the result
        {
            let mut cache = self.function_cache.write().unwrap();
            *cache = Some(result.clone());
        }

        result
    }

    /// Read available functions from tracefs
    fn read_available_functions(&self) -> FunctionListResult {
        let path = match &self.available_filter_functions_path {
            Some(p) => p,
            None => return FunctionListResult::NotAvailable,
        };

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return if e.kind() == std::io::ErrorKind::PermissionDenied {
                    FunctionListResult::PermissionDenied
                } else {
                    FunctionListResult::NotAvailable
                };
            }
        };

        // Each line is a function name, possibly with module info like "func_name [module]"
        // We extract just the function name
        let funcs = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                // Handle "func_name [module]" format
                let func_name = line.split_whitespace().next()?;
                Some(func_name.to_string())
            })
            .collect();

        FunctionListResult::Loaded(funcs)
    }

    /// Check if a kernel function exists and can be probed
    ///
    /// Returns a FunctionCheckResult indicating whether the function exists,
    /// doesn't exist (with suggestions), or validation is not possible.
    pub fn check_function(&self, name: &str) -> FunctionCheckResult {
        if self.available_filter_functions_path.is_none() {
            return FunctionCheckResult::CannotValidate;
        }

        match self.load_function_list() {
            FunctionListResult::PermissionDenied => FunctionCheckResult::NeedsSudo,
            FunctionListResult::NotAvailable => FunctionCheckResult::CannotValidate,
            FunctionListResult::Loaded(ref funcs) if funcs.is_empty() => {
                // Empty file - can't validate
                FunctionCheckResult::CannotValidate
            }
            FunctionListResult::Loaded(ref funcs) => {
                if funcs.iter().any(|f| f == name) {
                    FunctionCheckResult::Exists
                } else {
                    let suggestions = self.find_similar_functions(funcs, name, 3);
                    FunctionCheckResult::NotFound { suggestions }
                }
            }
        }
    }

    /// Find similar function names using edit distance
    fn find_similar_functions(&self, funcs: &[String], name: &str, max: usize) -> Vec<String> {
        let mut candidates: Vec<(String, usize)> = funcs
            .iter()
            .filter_map(|f| {
                let dist = Self::edit_distance(name, f);
                // Only consider functions within a reasonable edit distance
                // Allow more distance for longer function names
                let max_dist = (name.len() / 3).clamp(2, 5);
                if dist <= max_dist {
                    Some((f.clone(), dist))
                } else {
                    None
                }
            })
            .collect();

        // Sort by edit distance (closest first)
        candidates.sort_by_key(|(_, dist)| *dist);

        // Return top N
        candidates
            .into_iter()
            .take(max)
            .map(|(name, _)| name)
            .collect()
    }

    /// Calculate Levenshtein edit distance between two strings
    fn edit_distance(a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        let a_len = a_chars.len();
        let b_len = b_chars.len();

        if a_len == 0 {
            return b_len;
        }
        if b_len == 0 {
            return a_len;
        }

        // Use two rows instead of full matrix for memory efficiency
        let mut prev_row: Vec<usize> = (0..=b_len).collect();
        let mut curr_row: Vec<usize> = vec![0; b_len + 1];

        for (i, a_char) in a_chars.iter().enumerate() {
            curr_row[0] = i + 1;

            for (j, b_char) in b_chars.iter().enumerate() {
                let cost = if a_char == b_char { 0 } else { 1 };
                curr_row[j + 1] = (prev_row[j + 1] + 1) // deletion
                    .min(curr_row[j] + 1) // insertion
                    .min(prev_row[j] + cost); // substitution
            }

            std::mem::swap(&mut prev_row, &mut curr_row);
        }

        prev_row[b_len]
    }

    /// Get the tracepoint context for a given category/name
    ///
    /// For example: `get_tracepoint_context("syscalls", "sys_enter_openat")`
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
    fn parse_format_file(
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
            if let Some(field) = self.parse_field_line(line) {
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
    fn parse_field_line(&self, line: &str) -> Option<FieldInfo> {
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

        let type_info = self.infer_type_from_format(&field_type, size, signed);

        Some(FieldInfo {
            name: field_name,
            type_info,
            offset,
            size,
        })
    }

    /// Infer TypeInfo from format file type string
    fn infer_type_from_format(&self, type_str: &str, size: usize, signed: bool) -> TypeInfo {
        // Handle pointer types
        if type_str.contains('*') {
            return TypeInfo::Ptr {
                target: Box::new(TypeInfo::Unknown),
                is_user: type_str.contains("__user"),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_service() -> KernelBtf {
        KernelBtf {
            tracefs_events_path: None,
            available_filter_functions_path: None,
            tracepoint_cache: RwLock::new(HashMap::new()),
            function_cache: RwLock::new(None),
            pt_regs_cache: RwLock::new(None),
        }
    }

    #[test]
    fn test_parse_field_line() {
        let service = make_test_service();

        // Test integer field
        let field = service
            .parse_field_line("field:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;")
            .unwrap();
        assert_eq!(field.name, "__syscall_nr");
        assert_eq!(field.offset, 8);
        assert_eq!(field.size, 4);
        assert!(matches!(
            field.type_info,
            TypeInfo::Int {
                size: 4,
                signed: true
            }
        ));

        // Test pointer field
        let field = service
            .parse_field_line("field:const char * filename;\toffset:24;\tsize:8;\tsigned:0;")
            .unwrap();
        assert_eq!(field.name, "filename");
        assert_eq!(field.offset, 24);
        assert!(field.type_info.is_ptr());

        // Test array field
        let field = service
            .parse_field_line("field:unsigned long args[6];\toffset:16;\tsize:48;\tsigned:0;")
            .unwrap();
        assert_eq!(field.name, "args");
        assert_eq!(field.size, 48);
        assert!(matches!(field.type_info, TypeInfo::Array { len: 6, .. }));
    }

    #[test]
    fn test_parse_format_file() {
        let service = make_test_service();

        let content = r#"name: sys_enter_openat
ID: 633
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;
"#;

        let ctx = service
            .parse_format_file(content, "syscalls", "sys_enter_openat")
            .unwrap();

        assert_eq!(ctx.category, "syscalls");
        assert_eq!(ctx.name, "sys_enter_openat");

        // Should have 5 non-common fields
        assert_eq!(ctx.fields.len(), 5);

        // Check specific fields
        let syscall_nr = ctx.get_field("__syscall_nr").unwrap();
        assert_eq!(syscall_nr.offset, 8);

        let filename = ctx.get_field("filename").unwrap();
        assert_eq!(filename.offset, 24);
        assert!(filename.type_info.is_ptr());
    }

    #[test]
    fn test_wellknown_sys_enter() {
        let ctx = TracepointContext::sys_enter("sys_enter_openat");
        assert_eq!(ctx.category, "syscalls");
        assert!(ctx.has_field("id"));
        assert!(ctx.has_field("args"));
    }

    #[test]
    fn test_edit_distance() {
        // Identical strings
        assert_eq!(KernelBtf::edit_distance("hello", "hello"), 0);

        // Single character difference
        assert_eq!(KernelBtf::edit_distance("hello", "hallo"), 1);

        // Typo: transposition-like (two edits in edit distance)
        assert_eq!(KernelBtf::edit_distance("sys_clone", "sys_claone"), 1);

        // Missing character
        assert_eq!(KernelBtf::edit_distance("sys_read", "sys_rea"), 1);

        // Extra character
        assert_eq!(KernelBtf::edit_distance("sys_read", "sys_readd"), 1);

        // Completely different
        assert!(KernelBtf::edit_distance("sys_read", "do_fork") > 5);

        // Empty strings
        assert_eq!(KernelBtf::edit_distance("", "abc"), 3);
        assert_eq!(KernelBtf::edit_distance("abc", ""), 3);
    }

    #[test]
    fn test_check_function_graceful_degradation() {
        let service = make_test_service();
        // When function list is not available, should return CannotValidate
        assert_eq!(
            service.check_function("any_function"),
            FunctionCheckResult::CannotValidate
        );
    }
}
