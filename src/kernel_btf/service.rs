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
use btf::btf::{FlattenedType, Type};

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
    /// Failed to parse kernel BTF
    KernelBtfError(String),
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
            BtfError::KernelBtfError(msg) => write!(f, "Kernel BTF error: {}", msg),
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

/// Coarse argument shape inferred from kernel BTF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgShape {
    Scalar,
    Pointer,
}

/// Coarse return shape inferred from kernel BTF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRetShape {
    Void,
    Scalar,
    PointerMaybeNull,
}

/// Best-effort kfunc signature inferred from kernel BTF.
///
/// This is intentionally coarse and only captures arity plus pointer-vs-scalar
/// argument kinds, with coarse return-kind inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KfuncSignatureHint {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_shapes: [KfuncArgShape; 5],
    pub ret_shape: KfuncRetShape,
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
    /// Cached mapping of kfunc names to nullable pointer argument indices.
    kfunc_nullable_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to scalar argument indices that must be known constants.
    kfunc_known_const_scalar_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to scalar argument indices that must be positive (> 0).
    kfunc_positive_scalar_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer->size argument relationships.
    kfunc_pointer_size_arg_cache: RwLock<Option<HashMap<String, Vec<(usize, usize)>>>>,
    /// Cached mapping of kfunc names to inferred coarse signatures.
    kfunc_signature_hint_cache: RwLock<Option<HashMap<String, KfuncSignatureHint>>>,
}

impl KernelBtf {
    const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

    fn is_bpf_kfunc(ty: &FlattenedType) -> bool {
        ty.decl_tags.iter().any(|(_, tag)| tag == "bpf_kfunc")
    }

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
                kfunc_nullable_arg_cache: RwLock::new(None),
                kfunc_known_const_scalar_arg_cache: RwLock::new(None),
                kfunc_positive_scalar_arg_cache: RwLock::new(None),
                kfunc_pointer_size_arg_cache: RwLock::new(None),
                kfunc_signature_hint_cache: RwLock::new(None),
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
        let path = Self::KERNEL_BTF_PATH;
        Btf::from_file(path).map_err(|e| PtRegsError::new(format!("failed to parse {path}: {e}")))
    }

    fn load_kernel_btf_for_query(&self) -> Result<Btf, BtfError> {
        let path = Self::KERNEL_BTF_PATH;
        if !Path::new(path).is_file() {
            return Err(BtfError::NotAvailable);
        }
        Btf::from_file(path).map_err(|e| BtfError::KernelBtfError(e.to_string()))
    }

    fn load_kfunc_return_type_id_map(&self) -> Result<HashMap<u32, u32>, BtfError> {
        let raw = fs::read(Self::KERNEL_BTF_PATH).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to read {}: {e}", Self::KERNEL_BTF_PATH))
        })?;
        parse_function_return_type_ids_from_raw_btf(&raw).ok_or_else(|| {
            BtfError::KernelBtfError(
                "failed to parse raw kernel BTF function proto return ids".into(),
            )
        })
    }

    /// Resolve a kfunc name to its kernel BTF function ID.
    pub fn resolve_kfunc_btf_id(&self, kfunc_name: &str) -> Result<u32, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        for ty in btf.get_types() {
            if ty.is_function && ty.name.as_deref() == Some(kfunc_name) {
                return Ok(ty.type_id);
            }
        }
        Err(BtfError::TypeNotFound(kfunc_name.to_string()))
    }

    fn load_kfunc_nullable_arg_map(&self) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut nullable_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__nullable") || param_name.ends_with("__opt")
                }) {
                    nullable_args.push(arg_idx);
                }
            }
            if !nullable_args.is_empty() {
                map.insert(name.clone(), nullable_args);
            }
        }
        Ok(map)
    }

    /// Returns whether `kfunc_name` argument `arg_idx` is nullable in local kernel BTF.
    pub fn kfunc_pointer_arg_is_nullable(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_nullable_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|nullable_args| nullable_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_nullable_arg_map().unwrap_or_default();
        let is_nullable = map
            .get(kfunc_name)
            .is_some_and(|nullable_args| nullable_args.contains(&arg_idx));

        let mut cache = self.kfunc_nullable_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_nullable
    }

    fn load_kfunc_signature_hint_map(
        &self,
    ) -> Result<HashMap<String, KfuncSignatureHint>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let mut map: HashMap<String, KfuncSignatureHint> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            if proto.params.len() > 5 {
                continue;
            }
            // BTF varargs are represented by a terminal unnamed param with type_id=0.
            if proto
                .params
                .last()
                .is_some_and(|p| p.type_id == 0 && p.name.is_none())
            {
                continue;
            }
            let mut arg_shapes = [KfuncArgShape::Scalar; 5];
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                if btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0)
                {
                    arg_shapes[arg_idx] = KfuncArgShape::Pointer;
                }
            }
            let ret_shape = function_ret_type_ids
                .get(&ty.type_id)
                .copied()
                .map(|ret_type_id| infer_kfunc_ret_shape(&btf, ret_type_id))
                .unwrap_or(KfuncRetShape::Scalar);
            map.insert(
                name.clone(),
                KfuncSignatureHint {
                    min_args: proto.params.len(),
                    max_args: proto.params.len(),
                    arg_shapes,
                    ret_shape,
                },
            );
        }
        Ok(map)
    }

    fn load_kfunc_known_const_scalar_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut known_const_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__szk") || param_name.ends_with("__k")
                }) {
                    known_const_args.push(arg_idx);
                }
            }
            if !known_const_args.is_empty() {
                map.insert(name.clone(), known_const_args);
            }
        }
        Ok(map)
    }

    fn load_kfunc_positive_scalar_arg_map(&self) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut positive_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__sz") || param_name.ends_with("__szk")
                }) {
                    positive_args.push(arg_idx);
                }
            }
            if !positive_args.is_empty() {
                map.insert(name.clone(), positive_args);
            }
        }
        Ok(map)
    }

    fn kfunc_size_param_base_name(param_name: &str) -> Option<&str> {
        let base = param_name
            .strip_suffix("__szk")
            .or_else(|| param_name.strip_suffix("__sz"))?;
        if base.is_empty() {
            return None;
        }
        Some(base)
    }

    fn load_kfunc_pointer_size_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<(usize, usize)>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut pointer_args_by_name: HashMap<String, usize> = HashMap::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if param.type_id == 0 {
                    continue;
                }
                let is_pointer = btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0);
                if is_pointer {
                    pointer_args_by_name
                        .entry(param_name.to_string())
                        .or_insert(arg_idx);
                }
            }

            let mut ptr_size_pairs: Vec<(usize, usize)> = Vec::new();
            for (size_arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                let Some(base) = Self::kfunc_size_param_base_name(param_name) else {
                    continue;
                };
                let Some(ptr_arg_idx) = pointer_args_by_name.get(base).copied() else {
                    continue;
                };
                if !ptr_size_pairs
                    .iter()
                    .any(|(ptr, size)| *ptr == ptr_arg_idx && *size == size_arg_idx)
                {
                    ptr_size_pairs.push((ptr_arg_idx, size_arg_idx));
                }
            }

            if !ptr_size_pairs.is_empty() {
                map.insert(name.clone(), ptr_size_pairs);
            }
        }
        Ok(map)
    }

    /// Returns a best-effort coarse kfunc signature inferred from local kernel BTF.
    pub fn kfunc_signature_hint(&self, kfunc_name: &str) -> Option<KfuncSignatureHint> {
        {
            let cache = self.kfunc_signature_hint_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self.load_kfunc_signature_hint_map().unwrap_or_default();
        let hint = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_signature_hint_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        hint
    }

    /// Returns whether `kfunc_name` scalar argument `arg_idx` must be known constant.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `*__szk` / `*__k`.
    pub fn kfunc_scalar_arg_requires_known_const(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_known_const_scalar_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|known_const_args| known_const_args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_known_const_scalar_arg_map()
            .unwrap_or_default();
        let is_known_const = map
            .get(kfunc_name)
            .is_some_and(|known_const_args| known_const_args.contains(&arg_idx));

        let mut cache = self.kfunc_known_const_scalar_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_known_const
    }

    /// Returns whether `kfunc_name` scalar argument `arg_idx` must be positive.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `*__sz` / `*__szk`.
    pub fn kfunc_scalar_arg_requires_positive(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_positive_scalar_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|positive_args| positive_args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_positive_scalar_arg_map()
            .unwrap_or_default();
        let is_positive = map
            .get(kfunc_name)
            .is_some_and(|positive_args| positive_args.contains(&arg_idx));

        let mut cache = self.kfunc_positive_scalar_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_positive
    }

    /// Returns the scalar size-argument index paired with a pointer argument, if available.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `arg` + `arg__sz`/`arg__szk`.
    pub fn kfunc_pointer_arg_size_arg(&self, kfunc_name: &str, arg_idx: usize) -> Option<usize> {
        {
            let cache = self.kfunc_pointer_size_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
                    .map(|(_, size)| *size);
            }
        }

        let map = self.load_kfunc_pointer_size_arg_map().unwrap_or_default();
        let size_arg = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
            .map(|(_, size)| *size);

        let mut cache = self.kfunc_pointer_size_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        size_arg
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
            // If we can't read tracefs due to permissions, skip validation.
            // The actual BPF loading will fail with a proper error if the function doesn't exist.
            // This allows CAP_BPF/CAP_PERFMON to work without also needing tracefs read access.
            FunctionListResult::PermissionDenied => FunctionCheckResult::CannotValidate,
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

#[derive(Clone, Copy)]
enum BtfEndianness {
    Little,
    Big,
}

fn infer_kfunc_ret_shape(btf: &Btf, ret_type_id: u32) -> KfuncRetShape {
    if ret_type_id == 0 {
        return KfuncRetShape::Void;
    }
    if btf
        .get_type_by_id(ret_type_id)
        .is_ok_and(|ret_ty| ret_ty.num_refs > 0)
    {
        return KfuncRetShape::PointerMaybeNull;
    }
    KfuncRetShape::Scalar
}

fn parse_function_return_type_ids_from_raw_btf(raw: &[u8]) -> Option<HashMap<u32, u32>> {
    let endianness = detect_btf_endianness(raw)?;
    let hdr_len = read_u32(raw, 4, endianness)?;
    let type_off = read_u32(raw, 8, endianness)?;
    let type_len = read_u32(raw, 12, endianness)?;

    let type_start = hdr_len.checked_add(type_off)?;
    let type_end = type_start.checked_add(type_len)?;
    if type_end as usize > raw.len() {
        return None;
    }

    let mut func_to_proto: HashMap<u32, u32> = HashMap::new();
    let mut proto_to_ret: HashMap<u32, u32> = HashMap::new();
    let mut type_id: u32 = 1;
    let mut cursor: u32 = type_start;

    while cursor < type_end {
        let header_end = cursor.checked_add(12)?;
        if header_end > type_end {
            return None;
        }
        let info = read_u32(raw, cursor as usize + 4, endianness)?;
        let size_type = read_u32(raw, cursor as usize + 8, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        if kind == 12 {
            // BTF_KIND_FUNC: size_type is function prototype type ID.
            func_to_proto.insert(type_id, size_type);
        } else if kind == 13 {
            // BTF_KIND_FUNC_PROTO: size_type is return type ID.
            proto_to_ret.insert(type_id, size_type);
        }

        let payload_len = btf_kind_payload_len(kind, vlen)?;
        cursor = header_end.checked_add(payload_len)?;
        if cursor > type_end {
            return None;
        }
        type_id = type_id.checked_add(1)?;
    }

    if cursor != type_end {
        return None;
    }

    let mut out = HashMap::with_capacity(func_to_proto.len());
    for (func_type_id, proto_type_id) in func_to_proto {
        if let Some(ret_type_id) = proto_to_ret.get(&proto_type_id).copied() {
            out.insert(func_type_id, ret_type_id);
        }
    }
    Some(out)
}

fn detect_btf_endianness(raw: &[u8]) -> Option<BtfEndianness> {
    if raw.len() < 2 {
        return None;
    }
    let magic_le = u16::from_le_bytes([raw[0], raw[1]]);
    if magic_le == 0xeb9f {
        return Some(BtfEndianness::Little);
    }
    let magic_be = u16::from_be_bytes([raw[0], raw[1]]);
    if magic_be == 0xeb9f {
        return Some(BtfEndianness::Big);
    }
    None
}

fn read_u32(raw: &[u8], offset: usize, endianness: BtfEndianness) -> Option<u32> {
    let bytes = raw.get(offset..offset.checked_add(4)?)?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(match endianness {
        BtfEndianness::Little => u32::from_le_bytes(arr),
        BtfEndianness::Big => u32::from_be_bytes(arr),
    })
}

fn btf_kind_payload_len(kind: u32, vlen: u32) -> Option<u32> {
    match kind {
        1 => Some(4),                    // BTF_KIND_INT
        2 => Some(0),                    // BTF_KIND_PTR
        3 => Some(12),                   // BTF_KIND_ARRAY
        4 | 5 => vlen.checked_mul(12),   // BTF_KIND_STRUCT / UNION
        6 => vlen.checked_mul(8),        // BTF_KIND_ENUM
        7 => Some(0),                    // BTF_KIND_FWD
        8 | 9 | 10 | 11 | 12 => Some(0), // TYPEDEF / VOLATILE / CONST / RESTRICT / FUNC
        13 => vlen.checked_mul(8),       // BTF_KIND_FUNC_PROTO
        14 => Some(4),                   // BTF_KIND_VAR
        15 => vlen.checked_mul(12),      // BTF_KIND_DATASEC
        16 => Some(0),                   // BTF_KIND_FLOAT
        17 => Some(8),                   // BTF_KIND_DECL_TAG
        18 => Some(0),                   // BTF_KIND_TYPE_TAG
        19 => vlen.checked_mul(12),      // BTF_KIND_ENUM64
        _ => None,
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
            kfunc_nullable_arg_cache: RwLock::new(None),
            kfunc_known_const_scalar_arg_cache: RwLock::new(None),
            kfunc_positive_scalar_arg_cache: RwLock::new(None),
            kfunc_pointer_size_arg_cache: RwLock::new(None),
            kfunc_signature_hint_cache: RwLock::new(None),
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

    #[test]
    fn test_kfunc_nullable_query_graceful_without_btf() {
        let service = make_test_service();
        assert!(!service.kfunc_pointer_arg_is_nullable("definitely_not_a_kfunc", 0));
        assert!(!service.kfunc_pointer_arg_is_nullable("definitely_not_a_kfunc", 1));
    }

    #[test]
    fn test_kfunc_signature_hint_query_graceful_without_btf() {
        let service = make_test_service();
        assert_eq!(
            service.kfunc_signature_hint("__nu_plugin_ebpf_missing_kfunc__"),
            None
        );
    }

    #[test]
    fn test_kfunc_known_const_scalar_arg_query_graceful_without_btf() {
        let service = make_test_service();
        assert!(!service.kfunc_scalar_arg_requires_known_const("definitely_not_a_kfunc", 0));
        assert!(!service.kfunc_scalar_arg_requires_known_const("definitely_not_a_kfunc", 3));
    }

    #[test]
    fn test_kfunc_positive_scalar_arg_query_graceful_without_btf() {
        let service = make_test_service();
        assert!(!service.kfunc_scalar_arg_requires_positive("definitely_not_a_kfunc", 0));
        assert!(!service.kfunc_scalar_arg_requires_positive("definitely_not_a_kfunc", 3));
    }

    #[test]
    fn test_kfunc_pointer_size_arg_query_graceful_without_btf() {
        let service = make_test_service();
        assert_eq!(
            service.kfunc_pointer_arg_size_arg("definitely_not_a_kfunc", 0),
            None
        );
        assert_eq!(
            service.kfunc_pointer_arg_size_arg("definitely_not_a_kfunc", 2),
            None
        );
    }

    #[test]
    fn test_kfunc_size_param_base_name() {
        assert_eq!(
            KernelBtf::kfunc_size_param_base_name("buf__sz"),
            Some("buf")
        );
        assert_eq!(
            KernelBtf::kfunc_size_param_base_name("buffer__szk"),
            Some("buffer")
        );
        assert_eq!(KernelBtf::kfunc_size_param_base_name("size"), None);
        assert_eq!(KernelBtf::kfunc_size_param_base_name("__sz"), None);
        assert_eq!(KernelBtf::kfunc_size_param_base_name("__szk"), None);
    }

    fn push_u16(buf: &mut Vec<u8>, value: u16, endianness: BtfEndianness) {
        match endianness {
            BtfEndianness::Little => buf.extend_from_slice(&value.to_le_bytes()),
            BtfEndianness::Big => buf.extend_from_slice(&value.to_be_bytes()),
        }
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32, endianness: BtfEndianness) {
        match endianness {
            BtfEndianness::Little => buf.extend_from_slice(&value.to_le_bytes()),
            BtfEndianness::Big => buf.extend_from_slice(&value.to_be_bytes()),
        }
    }

    fn make_minimal_raw_btf_with_type_headers(
        endianness: BtfEndianness,
        type_headers: &[(u32, u32)],
    ) -> Vec<u8> {
        let hdr_len = 24u32;
        let type_len = (type_headers.len() as u32) * 12;
        let str_off = type_len;
        let str_len = 1u32;

        let mut out = Vec::new();
        push_u16(&mut out, 0xeb9f, endianness);
        out.push(1); // version
        out.push(0); // flags
        push_u32(&mut out, hdr_len, endianness);
        push_u32(&mut out, 0, endianness); // type_off
        push_u32(&mut out, type_len, endianness);
        push_u32(&mut out, str_off, endianness);
        push_u32(&mut out, str_len, endianness);

        for (info, size_type) in type_headers {
            push_u32(&mut out, 0, endianness); // name_off
            push_u32(&mut out, *info, endianness);
            push_u32(&mut out, *size_type, endianness);
        }

        out.push(0); // string section null terminator
        out
    }

    #[test]
    fn test_parse_raw_btf_function_return_type_ids_little_endian() {
        let type_headers = [
            ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
            (13u32 << 24, 0),       // BTF_KIND_FUNC_PROTO -> void return
        ];
        let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Little, &type_headers);
        let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
            .expect("expected return-type map from raw BTF");
        assert_eq!(parsed.get(&1).copied(), Some(0));
    }

    #[test]
    fn test_parse_raw_btf_function_return_type_ids_pointer_return() {
        let type_headers = [
            ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
            (13u32 << 24, 3),       // BTF_KIND_FUNC_PROTO -> pointer return type id 3
            (2u32 << 24, 0),        // BTF_KIND_PTR
        ];
        let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Little, &type_headers);
        let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
            .expect("expected return-type map from raw BTF");
        assert_eq!(parsed.get(&1).copied(), Some(3));
    }

    #[test]
    fn test_parse_raw_btf_function_return_type_ids_big_endian() {
        let type_headers = [
            ((12u32 << 24) | 1, 2), // BTF_KIND_FUNC -> proto id 2
            (13u32 << 24, 0),       // BTF_KIND_FUNC_PROTO -> void return
        ];
        let raw = make_minimal_raw_btf_with_type_headers(BtfEndianness::Big, &type_headers);
        let parsed = parse_function_return_type_ids_from_raw_btf(&raw)
            .expect("expected return-type map from raw BTF");
        assert_eq!(parsed.get(&1).copied(), Some(0));
    }
}
