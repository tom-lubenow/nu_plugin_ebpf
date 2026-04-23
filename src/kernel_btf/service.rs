//! Kernel BTF service
//!
//! Provides access to kernel type information for eBPF programs.
//! Uses multiple sources:
//! - Tracefs format files for tracepoint layouts
//! - Kernel BTF for function validation (future)
//! - Well-known fallback layouts for common tracepoints

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

use btf::Btf;
use btf::btf::{FlattenedType, Type};

use super::pt_regs::{PtRegsError, PtRegsOffsets, fallback_offsets, offsets_from_btf};
use super::tracepoint::TracepointContext;
use super::types::{BitfieldInfo, FieldInfo, TypeInfo};

mod function_list;
mod kfunc_heuristics;
mod kfunc_metadata;
mod raw_btf;
mod tracepoints;
mod trampoline;

#[cfg(test)]
use raw_btf::BtfEndianness;
use raw_btf::{
    parse_declared_type_sizes_from_raw_btf, parse_function_proto_return_type_ids_from_raw_btf,
    parse_function_return_type_ids_from_raw_btf, parse_pointer_target_type_ids_from_raw_btf,
};

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

/// Named kernel enum definition resolved from kernel BTF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelEnumInfo {
    pub is_signed: bool,
    pub entries: Vec<(String, i64)>,
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

/// Coarse pointer reference-family inferred from kernel BTF pointee type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncPointerRefFamily {
    Task,
    Cgroup,
    Inode,
    Cpumask,
    CryptoCtx,
    File,
    Socket,
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

/// Coarse kind for a value carried in a trampoline context slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrampolineValueKind {
    Scalar,
    Pointer { user_space: bool },
    Aggregate { size_bytes: usize },
}

/// BTF-resolved slot information for a trampoline argument or return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolineValueSpec {
    pub slot_index: usize,
    pub kind: TrampolineValueKind,
}

/// Resolved field projection within a by-value trampoline aggregate.
#[derive(Debug, Clone)]
pub struct TrampolineFieldProjection {
    pub path: Vec<TrampolineFieldPathSegment>,
    pub type_info: TypeInfo,
}

/// Bitfield extraction metadata for a resolved trampoline field segment.
pub type TrampolineBitfieldInfo = BitfieldInfo;

/// One requested selector in a trampoline field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrampolineFieldSelector {
    Field(String),
    Index(usize),
}

/// One resolved segment in a trampoline field projection path.
#[derive(Debug, Clone)]
pub struct TrampolineFieldPathSegment {
    pub offset_bytes: usize,
    pub type_info: TypeInfo,
    pub bitfield: Option<TrampolineBitfieldInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrampolineFieldLayout {
    slot_index: usize,
    slot_count: usize,
    value: Option<TrampolineValueSpec>,
    unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrampolineFunctionLayout {
    args: Vec<TrampolineFieldLayout>,
    retval: Option<TrampolineFieldLayout>,
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
    /// Cached raw BTF declared sizes for aggregate type IDs.
    raw_type_size_cache: RwLock<Option<Result<HashMap<u32, u32>, BtfError>>>,
    /// Cached raw BTF pointer target IDs.
    raw_pointer_target_cache: RwLock<Option<Result<HashMap<u32, u32>, BtfError>>>,
    /// Cached per-function trampoline layouts for BTF-backed tracing programs.
    trampoline_layout_cache: RwLock<HashMap<String, Result<TrampolineFunctionLayout, BtfError>>>,
    /// Cached per-callback trampoline layouts for struct_ops callbacks.
    struct_ops_layout_cache:
        RwLock<HashMap<(String, String), Result<TrampolineFunctionLayout, BtfError>>>,
    /// Cached mapping of kfunc names to nullable pointer argument indices.
    kfunc_nullable_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to const-qualified pointer argument indices.
    kfunc_const_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer argument indices that require user-space pointers.
    kfunc_user_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer argument indices that require stack pointers.
    kfunc_stack_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer argument indices that require kernel pointers.
    kfunc_kernel_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer argument ref families.
    kfunc_pointer_ref_family_cache:
        RwLock<Option<HashMap<String, Vec<(usize, KfuncPointerRefFamily)>>>>,
    /// Cached mapping of kfunc names to return-value ref families.
    kfunc_return_ref_family_cache: RwLock<Option<HashMap<String, KfuncPointerRefFamily>>>,
    /// Cached mapping of kfunc names to inferred release-arg indices.
    kfunc_release_ref_arg_index_cache: RwLock<Option<HashMap<String, usize>>>,
    /// Cached mapping of kfunc names to scalar argument indices that must be known constants.
    kfunc_known_const_scalar_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to scalar argument indices that must be positive (> 0).
    kfunc_positive_scalar_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer->size argument relationships.
    kfunc_pointer_size_arg_cache: RwLock<Option<HashMap<String, Vec<(usize, usize)>>>>,
    /// Cached mapping of kfunc names to pointer args that require stack-slot base pointers.
    kfunc_stack_slot_base_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer args inferred as by-reference out parameters.
    kfunc_out_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to pointer args inferred as by-reference input parameters.
    kfunc_in_pointer_arg_cache: RwLock<Option<HashMap<String, Vec<usize>>>>,
    /// Cached mapping of kfunc names to stack-object pointer argument metadata.
    /// Tuple format: `(arg_idx, pointee_type_id, pointee_type_name)`.
    kfunc_stack_object_arg_cache: RwLock<Option<HashMap<String, Vec<(usize, u32, String)>>>>,
    /// Cached mapping of kfunc names to pointer argument fixed access sizes.
    kfunc_pointer_fixed_size_cache: RwLock<Option<HashMap<String, Vec<(usize, usize)>>>>,
    /// Cached mapping of kfunc names to inferred coarse signatures.
    kfunc_signature_hint_cache: RwLock<Option<HashMap<String, KfuncSignatureHint>>>,
}

impl KernelBtf {
    const TP_BTF_HIDDEN_ARG_COUNT: usize = 1;

    fn lsm_hook_function_name(hook_name: &str) -> String {
        format!("bpf_lsm_{hook_name}")
    }

    fn tp_btf_type_name(tracepoint_name: &str) -> String {
        format!("btf_trace_{tracepoint_name}")
    }

    fn tp_btf_raw_arg_index(arg_idx: usize) -> usize {
        arg_idx + Self::TP_BTF_HIDDEN_ARG_COUNT
    }

    fn tp_btf_user_arg_index(raw_idx: usize) -> Option<usize> {
        raw_idx.checked_sub(Self::TP_BTF_HIDDEN_ARG_COUNT)
    }

    fn resolve_named_trampoline_callable<'a>(
        btf: &'a Btf,
        callable_name: &str,
    ) -> Result<&'a FlattenedType, BtfError> {
        if let Some(ty) = btf
            .get_types()
            .iter()
            .find(|ty| ty.is_function && ty.name.as_deref() == Some(callable_name))
        {
            return Ok(ty);
        }
        let ty = btf
            .get_type_by_name(callable_name)
            .map_err(|_| BtfError::TypeNotFound(callable_name.to_string()))?;
        if !matches!(ty.base_type, Type::FunctionProto(_)) {
            return Err(BtfError::KernelBtfError(format!(
                "callable '{}' is missing a function prototype in kernel BTF",
                callable_name
            )));
        }
        Ok(ty)
    }

    fn function_arg_index_by_name(
        function_ty: &FlattenedType,
        function_name: &str,
        arg_name: &str,
    ) -> Result<Option<usize>, BtfError> {
        let Type::FunctionProto(proto) = &function_ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "function '{}' is missing a function prototype in kernel BTF",
                function_name
            )));
        };

        Ok(proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .enumerate()
            .find_map(|(idx, param)| (param.name.as_deref() == Some(arg_name)).then_some(idx)))
    }

    const TRAMPOLINE_POINTER_TYPE_DEPTH: usize = 2;

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
                raw_type_size_cache: RwLock::new(None),
                raw_pointer_target_cache: RwLock::new(None),
                trampoline_layout_cache: RwLock::new(HashMap::new()),
                struct_ops_layout_cache: RwLock::new(HashMap::new()),
                kfunc_nullable_arg_cache: RwLock::new(None),
                kfunc_const_pointer_arg_cache: RwLock::new(None),
                kfunc_user_pointer_arg_cache: RwLock::new(None),
                kfunc_stack_pointer_arg_cache: RwLock::new(None),
                kfunc_kernel_pointer_arg_cache: RwLock::new(None),
                kfunc_pointer_ref_family_cache: RwLock::new(None),
                kfunc_return_ref_family_cache: RwLock::new(None),
                kfunc_release_ref_arg_index_cache: RwLock::new(None),
                kfunc_known_const_scalar_arg_cache: RwLock::new(None),
                kfunc_positive_scalar_arg_cache: RwLock::new(None),
                kfunc_pointer_size_arg_cache: RwLock::new(None),
                kfunc_stack_slot_base_arg_cache: RwLock::new(None),
                kfunc_out_pointer_arg_cache: RwLock::new(None),
                kfunc_in_pointer_arg_cache: RwLock::new(None),
                kfunc_stack_object_arg_cache: RwLock::new(None),
                kfunc_pointer_fixed_size_cache: RwLock::new(None),
                kfunc_signature_hint_cache: RwLock::new(None),
            }
        })
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

    fn load_function_proto_return_type_id_map(&self) -> Result<HashMap<u32, u32>, BtfError> {
        let raw = fs::read(Self::KERNEL_BTF_PATH).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to read {}: {e}", Self::KERNEL_BTF_PATH))
        })?;
        parse_function_proto_return_type_ids_from_raw_btf(&raw).ok_or_else(|| {
            BtfError::KernelBtfError(
                "failed to parse raw kernel BTF function proto return ids".into(),
            )
        })
    }

    fn load_raw_type_size_map(&self) -> Result<HashMap<u32, u32>, BtfError> {
        {
            let cache = self.raw_type_size_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.clone();
            }
        }

        let raw = fs::read(Self::KERNEL_BTF_PATH).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to read {}: {e}", Self::KERNEL_BTF_PATH))
        })?;
        let map = parse_declared_type_sizes_from_raw_btf(&raw).ok_or_else(|| {
            BtfError::KernelBtfError("failed to parse raw kernel BTF type sizes".into())
        });

        let mut cache = self.raw_type_size_cache.write().unwrap();
        *cache = Some(map.clone());
        map
    }

    fn load_raw_pointer_target_map(&self) -> Result<HashMap<u32, u32>, BtfError> {
        {
            let cache = self.raw_pointer_target_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.clone();
            }
        }

        let raw = fs::read(Self::KERNEL_BTF_PATH).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to read {}: {e}", Self::KERNEL_BTF_PATH))
        })?;
        let map = parse_pointer_target_type_ids_from_raw_btf(&raw).ok_or_else(|| {
            BtfError::KernelBtfError("failed to parse raw kernel BTF pointer targets".into())
        });

        let mut cache = self.raw_pointer_target_cache.write().unwrap();
        *cache = Some(map.clone());
        map
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

    /// Resolve a typed trampoline argument slot for an attached function.
    ///
    /// Returns `Ok(None)` when the function exists but does not have that argument.
    /// Returns an error if the argument exists but has an unsupported by-value type.
    pub fn function_trampoline_arg(
        &self,
        function_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TrampolineValueSpec>, BtfError> {
        let layout = self.function_trampoline_layout(function_name)?;
        let Some(field) = layout.args.get(arg_idx) else {
            return Ok(None);
        };
        if let Some(value) = field.value {
            return Ok(Some(value));
        }
        Err(BtfError::KernelBtfError(format!(
            "argument {} for '{}' uses an unsupported trampoline type: {}",
            arg_idx,
            function_name,
            field
                .unsupported_reason
                .as_deref()
                .unwrap_or("unknown layout")
        )))
    }

    /// Resolve a typed trampoline argument slot for an LSM hook.
    pub fn lsm_hook_arg(
        &self,
        hook_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TrampolineValueSpec>, BtfError> {
        self.function_trampoline_arg(&Self::lsm_hook_function_name(hook_name), arg_idx)
    }

    /// Resolve a typed trampoline argument slot for a `tp_btf` tracepoint.
    ///
    /// Returns `Ok(None)` when the tracepoint exists but does not have that argument.
    pub fn tp_btf_arg(
        &self,
        tracepoint_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TrampolineValueSpec>, BtfError> {
        self.function_trampoline_arg(
            &Self::tp_btf_type_name(tracepoint_name),
            Self::tp_btf_raw_arg_index(arg_idx),
        )
    }

    /// Resolve a typed trampoline argument slot for a `struct_ops` callback.
    ///
    /// Returns `Ok(None)` when the callback exists but does not have that argument.
    /// Returns an error if the argument exists but has an unsupported by-value type.
    pub fn struct_ops_callback_arg(
        &self,
        value_type_name: &str,
        callback_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TrampolineValueSpec>, BtfError> {
        let layout = self.struct_ops_callback_layout(value_type_name, callback_name)?;
        let Some(field) = layout.args.get(arg_idx) else {
            return Ok(None);
        };
        if let Some(value) = field.value {
            return Ok(Some(value));
        }
        Err(BtfError::KernelBtfError(format!(
            "argument {} for struct_ops callback '{}.{}' uses an unsupported trampoline type: {}",
            arg_idx,
            value_type_name,
            callback_name,
            field
                .unsupported_reason
                .as_deref()
                .unwrap_or("unknown layout")
        )))
    }

    /// Resolve the exact kernel-BTF type for a trampoline argument.
    ///
    /// Returns `Ok(None)` when the function exists but does not have that argument.
    pub fn function_trampoline_arg_type_info(
        &self,
        function_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TypeInfo>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Type::FunctionProto(proto) = &ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "function '{}' is missing a function prototype in kernel BTF",
                function_name
            )));
        };

        let Some(param) = proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .nth(arg_idx)
        else {
            return Ok(None);
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        let param_ty = btf.get_type_by_id(param.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                param.type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &param_ty, &raw_type_sizes, &raw_pointer_targets)
            .map(Some)
    }

    /// Resolve the exact kernel-BTF type for an LSM hook argument.
    pub fn lsm_hook_arg_type_info(
        &self,
        hook_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TypeInfo>, BtfError> {
        self.function_trampoline_arg_type_info(&Self::lsm_hook_function_name(hook_name), arg_idx)
    }

    /// Resolve the exact kernel-BTF type for a `tp_btf` tracepoint argument.
    pub fn tp_btf_arg_type_info(
        &self,
        tracepoint_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TypeInfo>, BtfError> {
        self.function_trampoline_arg_type_info(
            &Self::tp_btf_type_name(tracepoint_name),
            Self::tp_btf_raw_arg_index(arg_idx),
        )
    }

    /// Resolve the argument index for a named trampoline function parameter.
    ///
    /// Returns `Ok(None)` when the function exists but does not have a
    /// parameter with the requested name.
    pub fn function_trampoline_arg_index_by_name(
        &self,
        function_name: &str,
        arg_name: &str,
    ) -> Result<Option<usize>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        Self::function_arg_index_by_name(function_ty, function_name, arg_name)
    }

    /// Resolve the argument index for a named LSM hook parameter.
    ///
    /// Returns `Ok(None)` when the hook exists but does not have a
    /// parameter with the requested name.
    pub fn lsm_hook_arg_index_by_name(
        &self,
        hook_name: &str,
        arg_name: &str,
    ) -> Result<Option<usize>, BtfError> {
        self.function_trampoline_arg_index_by_name(
            &Self::lsm_hook_function_name(hook_name),
            arg_name,
        )
    }

    /// Resolve the argument index for a named `tp_btf` parameter.
    pub fn tp_btf_arg_index_by_name(
        &self,
        tracepoint_name: &str,
        arg_name: &str,
    ) -> Result<Option<usize>, BtfError> {
        Ok(self
            .function_trampoline_arg_index_by_name(
                &Self::tp_btf_type_name(tracepoint_name),
                arg_name,
            )?
            .and_then(Self::tp_btf_user_arg_index))
    }

    /// Resolve the exact kernel-BTF type for a `struct_ops` callback argument.
    ///
    /// Returns `Ok(None)` when the callback exists but does not have that argument.
    pub fn struct_ops_callback_arg_type_info(
        &self,
        value_type_name: &str,
        callback_name: &str,
        arg_idx: usize,
    ) -> Result<Option<TypeInfo>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let callback_ty =
            Self::resolve_struct_ops_callback_member_type(&btf, value_type_name, callback_name)?;
        let Type::FunctionProto(proto) = &callback_ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is missing a function prototype in kernel BTF",
                value_type_name, callback_name
            )));
        };

        let Some(param) = proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .nth(arg_idx)
        else {
            return Ok(None);
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        let param_ty = btf.get_type_by_id(param.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                param.type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &param_ty, &raw_type_sizes, &raw_pointer_targets)
            .map(Some)
    }

    fn resolve_struct_ops_callback_named_function<'a>(
        btf: &'a Btf,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<&'a FlattenedType, BtfError> {
        let function_name = format!("{}__{}", value_type_name, callback_name);
        btf.get_types()
            .iter()
            .find(|ty| ty.is_function && ty.name.as_deref() == Some(function_name.as_str()))
            .ok_or(BtfError::TypeNotFound(function_name))
    }

    /// Resolve the argument index for a named `struct_ops` callback parameter.
    ///
    /// Returns `Ok(None)` when the callback exists but does not have a parameter
    /// with the requested name.
    pub fn struct_ops_callback_arg_index_by_name(
        &self,
        value_type_name: &str,
        callback_name: &str,
        arg_name: &str,
    ) -> Result<Option<usize>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let callback_fn =
            Self::resolve_struct_ops_callback_named_function(&btf, value_type_name, callback_name)?;
        let Type::FunctionProto(proto) = &callback_fn.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback function '{}__{}' is missing a function prototype in kernel BTF",
                value_type_name, callback_name
            )));
        };

        Ok(proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .enumerate()
            .find_map(|(idx, param)| (param.name.as_deref() == Some(arg_name)).then_some(idx)))
    }

    /// Resolve the exact kernel-BTF return type for a `struct_ops` callback.
    ///
    /// Returns `Ok(None)` when the callback returns `void`.
    pub fn struct_ops_callback_ret_type_info(
        &self,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<Option<TypeInfo>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_proto_ret_type_ids = self.load_function_proto_return_type_id_map()?;
        let callback_ty =
            Self::resolve_struct_ops_callback_member_type(&btf, value_type_name, callback_name)?;
        let Some(ret_type_id) = function_proto_ret_type_ids
            .get(&callback_ty.type_id)
            .copied()
        else {
            return Ok(None);
        };
        if ret_type_id == 0 {
            return Ok(None);
        }

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        let ret_ty = btf.get_type_by_id(ret_type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                ret_type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &ret_ty, &raw_type_sizes, &raw_pointer_targets)
            .map(Some)
    }

    /// Resolve a typed trampoline return-value slot for an attached function.
    ///
    /// Returns `Ok(None)` when the function returns `void`.
    /// Returns an error if the return value exists but has an unsupported by-value type.
    pub fn function_trampoline_ret(
        &self,
        function_name: &str,
    ) -> Result<Option<TrampolineValueSpec>, BtfError> {
        let layout = self.function_trampoline_layout(function_name)?;
        let Some(field) = layout.retval.as_ref() else {
            return Ok(None);
        };
        if let Some(value) = field.value {
            return Ok(Some(value));
        }
        Err(BtfError::KernelBtfError(format!(
            "return value for '{}' uses an unsupported trampoline type: {}",
            function_name,
            field
                .unsupported_reason
                .as_deref()
                .unwrap_or("unknown layout")
        )))
    }

    /// Resolve the exact kernel-BTF type for a trampoline return value.
    ///
    /// Returns `Ok(None)` when the function returns `void`.
    pub fn function_trampoline_ret_type_info(
        &self,
        function_name: &str,
    ) -> Result<Option<TypeInfo>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Some(ret_type_id) = function_ret_type_ids.get(&ty.type_id).copied() else {
            return Ok(None);
        };
        if ret_type_id == 0 {
            return Ok(None);
        }

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        let ret_ty = btf.get_type_by_id(ret_type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                ret_type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &ret_ty, &raw_type_sizes, &raw_pointer_targets)
            .map(Some)
    }

    /// Validate that a function target is attachable via an fentry trampoline.
    pub fn validate_fentry_target(&self, function_name: &str) -> Result<(), BtfError> {
        let layout = self.function_trampoline_layout(function_name)?;
        for (idx, arg) in layout.args.iter().enumerate() {
            if arg.value.is_none() {
                return Err(BtfError::KernelBtfError(format!(
                    "fentry target '{}' uses unsupported trampoline argument {}: {}",
                    function_name,
                    idx,
                    arg.unsupported_reason
                        .as_deref()
                        .unwrap_or("unknown layout")
                )));
            }
        }
        Ok(())
    }

    /// Validate that a `tp_btf` target is attachable.
    pub fn validate_tp_btf_target(&self, tracepoint_name: &str) -> Result<(), BtfError> {
        let callable_name = Self::tp_btf_type_name(tracepoint_name);
        let layout = self.function_trampoline_layout(&callable_name)?;
        for (idx, arg) in layout
            .args
            .iter()
            .enumerate()
            .skip(Self::TP_BTF_HIDDEN_ARG_COUNT)
        {
            if arg.value.is_none() {
                return Err(BtfError::KernelBtfError(format!(
                    "tp_btf target '{}' uses unsupported argument {}: {}",
                    tracepoint_name,
                    idx - Self::TP_BTF_HIDDEN_ARG_COUNT,
                    arg.unsupported_reason
                        .as_deref()
                        .unwrap_or("unknown layout")
                )));
            }
        }
        Ok(())
    }

    /// Validate that an LSM hook target is attachable.
    pub fn validate_lsm_hook_target(&self, hook_name: &str) -> Result<(), BtfError> {
        let function_name = Self::lsm_hook_function_name(hook_name);
        let layout = self.function_trampoline_layout(&function_name)?;
        for (idx, arg) in layout.args.iter().enumerate() {
            if arg.value.is_none() {
                return Err(BtfError::KernelBtfError(format!(
                    "lsm target '{}' uses unsupported argument {}: {}",
                    hook_name,
                    idx,
                    arg.unsupported_reason
                        .as_deref()
                        .unwrap_or("unknown layout")
                )));
            }
        }
        Ok(())
    }

    /// Validate that a function target is attachable via an fexit trampoline.
    pub fn validate_fexit_target(&self, function_name: &str) -> Result<(), BtfError> {
        let layout = self.function_trampoline_layout(function_name)?;
        for (idx, arg) in layout.args.iter().enumerate() {
            if arg.value.is_none() {
                return Err(BtfError::KernelBtfError(format!(
                    "fexit target '{}' uses unsupported trampoline argument {}: {}",
                    function_name,
                    idx,
                    arg.unsupported_reason
                        .as_deref()
                        .unwrap_or("unknown layout")
                )));
            }
        }

        if let Some(retval) = layout.retval.as_ref() {
            match retval.value {
                Some(TrampolineValueSpec {
                    kind: TrampolineValueKind::Aggregate { .. },
                    ..
                }) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "fexit target '{}' has a by-value aggregate return, which kernel trampolines on this system do not support",
                        function_name
                    )));
                }
                None => {
                    return Err(BtfError::KernelBtfError(format!(
                        "fexit target '{}' uses unsupported return trampoline type: {}",
                        function_name,
                        retval
                            .unsupported_reason
                            .as_deref()
                            .unwrap_or("unknown layout")
                    )));
                }
                Some(_) => {}
            }
        }

        Ok(())
    }

    /// Validate the BTF slot layout needed by an fmod_ret trampoline.
    ///
    /// The kernel also restricts `BPF_MODIFY_RETURN` to allow-error-injection
    /// functions or registered modify-return kfuncs; live attach is not exposed
    /// yet, so this check only proves the compiler can model args and retval.
    pub fn validate_fmod_ret_target(&self, function_name: &str) -> Result<(), BtfError> {
        self.validate_fexit_target(function_name)
    }

    /// Resolve a named field path within a by-value trampoline argument.
    ///
    /// Returns `Ok(None)` when the function exists but does not have that argument.
    pub fn function_trampoline_arg_field(
        &self,
        function_name: &str,
        arg_idx: usize,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<Option<TrampolineFieldProjection>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Type::FunctionProto(proto) = &ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "function '{}' is missing a function prototype in kernel BTF",
                function_name
            )));
        };

        let Some(param) = proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .nth(arg_idx)
        else {
            return Ok(None);
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        self.resolve_trampoline_field_projection(
            &btf,
            param.type_id,
            field_path,
            &raw_type_sizes,
            &raw_pointer_targets,
        )
        .map(Some)
    }

    /// Resolve a named field path within an LSM hook argument.
    pub fn lsm_hook_arg_field(
        &self,
        hook_name: &str,
        arg_idx: usize,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<Option<TrampolineFieldProjection>, BtfError> {
        self.function_trampoline_arg_field(
            &Self::lsm_hook_function_name(hook_name),
            arg_idx,
            field_path,
        )
    }

    /// Resolve a named field path within a `tp_btf` tracepoint argument.
    pub fn tp_btf_arg_field(
        &self,
        tracepoint_name: &str,
        arg_idx: usize,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<Option<TrampolineFieldProjection>, BtfError> {
        self.function_trampoline_arg_field(
            &Self::tp_btf_type_name(tracepoint_name),
            Self::tp_btf_raw_arg_index(arg_idx),
            field_path,
        )
    }

    /// Resolve a named field path within a `struct_ops` callback argument.
    ///
    /// Returns `Ok(None)` when the callback exists but does not have that argument.
    pub fn struct_ops_callback_arg_field(
        &self,
        value_type_name: &str,
        callback_name: &str,
        arg_idx: usize,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<Option<TrampolineFieldProjection>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let callback_ty =
            Self::resolve_struct_ops_callback_member_type(&btf, value_type_name, callback_name)?;
        let Type::FunctionProto(proto) = &callback_ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is missing a function prototype in kernel BTF",
                value_type_name, callback_name
            )));
        };

        let Some(param) = proto
            .params
            .iter()
            .take_while(|param| param.type_id != 0)
            .nth(arg_idx)
        else {
            return Ok(None);
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        self.resolve_trampoline_field_projection(
            &btf,
            param.type_id,
            field_path,
            &raw_type_sizes,
            &raw_pointer_targets,
        )
        .map(Some)
    }

    /// Resolve a named field path within a by-value trampoline return value.
    ///
    /// Returns `Ok(None)` when the function returns `void`.
    pub fn function_trampoline_ret_field(
        &self,
        function_name: &str,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<Option<TrampolineFieldProjection>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Some(ret_type_id) = function_ret_type_ids.get(&ty.type_id).copied() else {
            return Ok(None);
        };
        if ret_type_id == 0 {
            return Ok(None);
        }

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        self.resolve_trampoline_field_projection(
            &btf,
            ret_type_id,
            field_path,
            &raw_type_sizes,
            &raw_pointer_targets,
        )
        .map(Some)
    }

    /// Resolve a field path from an arbitrary kernel BTF type id.
    pub fn kernel_type_field_projection(
        &self,
        root_type_id: u32,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<TrampolineFieldProjection, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        self.resolve_trampoline_field_projection(
            &btf,
            root_type_id,
            field_path,
            &raw_type_sizes,
            &raw_pointer_targets,
        )
    }

    /// Resolve a field path from an arbitrary named kernel BTF type.
    pub fn kernel_named_type_field_projection(
        &self,
        type_name: &str,
        field_path: &[TrampolineFieldSelector],
    ) -> Result<TrampolineFieldProjection, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = btf
            .get_type_by_name(type_name)
            .map_err(|_| BtfError::TypeNotFound(type_name.to_string()))?;
        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        self.resolve_trampoline_field_projection(
            &btf,
            ty.type_id,
            field_path,
            &raw_type_sizes,
            &raw_pointer_targets,
        )
    }

    /// Resolve the recursive representable type layout for a named kernel BTF type.
    pub fn kernel_named_type_info(&self, type_name: &str) -> Result<TypeInfo, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = btf
            .get_type_by_name(type_name)
            .map_err(|_| BtfError::TypeNotFound(type_name.to_string()))?;
        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_pointer_targets = self.load_raw_pointer_target_map().unwrap_or_default();
        Self::type_info_from_btf_type(&btf, &ty, &raw_type_sizes, &raw_pointer_targets)
    }

    /// Resolve the size in bytes of a named kernel BTF type.
    pub fn kernel_named_type_size_bytes(&self, type_name: &str) -> Result<usize, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = btf
            .get_type_by_name(type_name)
            .map_err(|_| BtfError::TypeNotFound(type_name.to_string()))?;
        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let raw_size_bytes = raw_type_sizes
            .get(&ty.type_id)
            .copied()
            .map(|size| size as usize);
        Self::trampoline_size_bytes(&btf, &ty, raw_size_bytes)
    }

    /// Resolve a named kernel enum definition and its entries from kernel BTF.
    pub fn kernel_named_enum_info(&self, type_name: &str) -> Result<KernelEnumInfo, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = btf
            .get_type_by_name(type_name)
            .map_err(|_| BtfError::TypeNotFound(type_name.to_string()))?;
        match &ty.base_type {
            Type::Enum32(enum_ty) | Type::Enum64(enum_ty) => Ok(KernelEnumInfo {
                is_signed: enum_ty.is_signed,
                entries: enum_ty
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(idx, entry)| {
                        (
                            entry
                                .name
                                .clone()
                                .unwrap_or_else(|| format!("<anonymous:{idx}>")),
                            entry.value,
                        )
                    })
                    .collect(),
            }),
            other => Err(BtfError::KernelBtfError(format!(
                "named kernel BTF type '{}' is not an enum: {:?}",
                type_name, other
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
