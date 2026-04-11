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

#[cfg(test)]
use raw_btf::BtfEndianness;
use raw_btf::{
    parse_declared_type_sizes_from_raw_btf, parse_function_proto_return_type_ids_from_raw_btf,
    parse_function_return_type_ids_from_raw_btf,
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
    /// Cached per-function trampoline layouts for fentry/fexit/tp_btf style programs.
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
    fn lsm_hook_function_name(hook_name: &str) -> String {
        format!("bpf_lsm_{hook_name}")
    }

    fn tp_btf_type_name(tracepoint_name: &str) -> String {
        format!("btf_trace_{tracepoint_name}")
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
        self.function_trampoline_arg(&Self::tp_btf_type_name(tracepoint_name), arg_idx)
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
        let param_ty = btf.get_type_by_id(param.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                param.type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &param_ty, &raw_type_sizes).map(Some)
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
        self.function_trampoline_arg_type_info(&Self::tp_btf_type_name(tracepoint_name), arg_idx)
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
        self.function_trampoline_arg_index_by_name(
            &Self::tp_btf_type_name(tracepoint_name),
            arg_name,
        )
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
        let param_ty = btf.get_type_by_id(param.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                param.type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &param_ty, &raw_type_sizes).map(Some)
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
        let ret_ty = btf.get_type_by_id(ret_type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                ret_type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &ret_ty, &raw_type_sizes).map(Some)
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
        let ret_ty = btf.get_type_by_id(ret_type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                ret_type_id, e
            ))
        })?;
        Self::type_info_from_btf_type(&btf, &ret_ty, &raw_type_sizes).map(Some)
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
        for (idx, arg) in layout.args.iter().enumerate() {
            if arg.value.is_none() {
                return Err(BtfError::KernelBtfError(format!(
                    "tp_btf target '{}' uses unsupported argument {}: {}",
                    tracepoint_name,
                    idx,
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
        self.resolve_trampoline_field_projection(&btf, param.type_id, field_path, &raw_type_sizes)
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
            arg_idx,
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
        self.resolve_trampoline_field_projection(&btf, param.type_id, field_path, &raw_type_sizes)
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
        self.resolve_trampoline_field_projection(&btf, ret_type_id, field_path, &raw_type_sizes)
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
        self.resolve_trampoline_field_projection(&btf, root_type_id, field_path, &raw_type_sizes)
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
        self.resolve_trampoline_field_projection(&btf, ty.type_id, field_path, &raw_type_sizes)
    }

    /// Resolve the recursive representable type layout for a named kernel BTF type.
    pub fn kernel_named_type_info(&self, type_name: &str) -> Result<TypeInfo, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let ty = btf
            .get_type_by_name(type_name)
            .map_err(|_| BtfError::TypeNotFound(type_name.to_string()))?;
        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        Self::type_info_from_btf_type(&btf, &ty, &raw_type_sizes)
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

    fn function_trampoline_layout(
        &self,
        function_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        {
            let cache = self.trampoline_layout_cache.read().unwrap();
            if let Some(layout) = cache.get(function_name) {
                return layout.clone();
            }
        }

        let layout = self.compute_function_trampoline_layout(function_name);

        let mut cache = self.trampoline_layout_cache.write().unwrap();
        cache.insert(function_name.to_string(), layout.clone());
        layout
    }

    fn compute_function_trampoline_layout(
        &self,
        function_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let ty = Self::resolve_named_trampoline_callable(&btf, function_name)?;
        let Type::FunctionProto(proto) = &ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "function '{}' is missing a function prototype in kernel BTF",
                function_name
            )));
        };

        let mut next_slot = 0usize;
        let mut args = Vec::with_capacity(proto.params.len());
        for param in &proto.params {
            // BTF varargs are represented by a terminal unnamed param with type_id=0.
            if param.type_id == 0 {
                break;
            }
            let raw_size_bytes = self
                .load_raw_type_size_map()
                .ok()
                .and_then(|sizes| sizes.get(&param.type_id).copied())
                .map(|size| size as usize);
            let layout =
                Self::trampoline_field_layout(&btf, param.type_id, next_slot, raw_size_bytes)?;
            next_slot = next_slot.checked_add(layout.slot_count).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "trampoline layout for '{}' overflowed slot accounting",
                    function_name
                ))
            })?;
            args.push(layout);
        }

        let retval = match function_ret_type_ids.get(&ty.type_id).copied() {
            Some(0) | None => None,
            Some(ret_type_id) => {
                let raw_size_bytes = self
                    .load_raw_type_size_map()
                    .ok()
                    .and_then(|sizes| sizes.get(&ret_type_id).copied())
                    .map(|size| size as usize);
                Some(Self::trampoline_field_layout(
                    &btf,
                    ret_type_id,
                    next_slot,
                    raw_size_bytes,
                )?)
            }
        };

        Ok(TrampolineFunctionLayout { args, retval })
    }

    fn struct_ops_callback_layout(
        &self,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let key = (value_type_name.to_string(), callback_name.to_string());
        {
            let cache = self.struct_ops_layout_cache.read().unwrap();
            if let Some(layout) = cache.get(&key) {
                return layout.clone();
            }
        }

        let layout = self.compute_struct_ops_callback_layout(value_type_name, callback_name);

        let mut cache = self.struct_ops_layout_cache.write().unwrap();
        cache.insert(key, layout.clone());
        layout
    }

    fn compute_struct_ops_callback_layout(
        &self,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<TrampolineFunctionLayout, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let callback_ty =
            Self::resolve_struct_ops_callback_member_type(&btf, value_type_name, callback_name)?;
        let Type::FunctionProto(proto) = &callback_ty.base_type else {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is missing a function prototype in kernel BTF",
                value_type_name, callback_name
            )));
        };

        let raw_type_sizes = self.load_raw_type_size_map().unwrap_or_default();
        let mut next_slot = 0usize;
        let mut args = Vec::with_capacity(proto.params.len());
        for param in &proto.params {
            if param.type_id == 0 {
                break;
            }
            let raw_size_bytes = raw_type_sizes
                .get(&param.type_id)
                .copied()
                .map(|size| size as usize);
            let layout =
                Self::trampoline_field_layout(&btf, param.type_id, next_slot, raw_size_bytes)?;
            next_slot = next_slot.checked_add(layout.slot_count).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "trampoline layout for struct_ops callback '{}.{}' overflowed slot accounting",
                    value_type_name, callback_name
                ))
            })?;
            args.push(layout);
        }

        Ok(TrampolineFunctionLayout { args, retval: None })
    }

    fn resolve_struct_ops_callback_member_type(
        btf: &Btf,
        value_type_name: &str,
        callback_name: &str,
    ) -> Result<FlattenedType, BtfError> {
        let ty = btf
            .get_type_by_name(value_type_name)
            .map_err(|_| BtfError::TypeNotFound(value_type_name.to_string()))?;

        let member = match &ty.base_type {
            Type::Struct(struct_ty) | Type::Union(struct_ty) => struct_ty
                .members
                .iter()
                .find(|member| member.name.as_deref() == Some(callback_name))
                .ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "kernel BTF type '{}' has no callback member '{}'",
                        value_type_name, callback_name
                    ))
                })?,
            other => {
                return Err(BtfError::KernelBtfError(format!(
                    "kernel BTF type '{}' is not a struct/union (got {:?})",
                    value_type_name, other
                )));
            }
        };

        let member_ty = btf.get_type_by_id(member.type_id).map_err(|e| {
            BtfError::KernelBtfError(format!(
                "failed to resolve kernel BTF type {}: {}",
                member.type_id, e
            ))
        })?;
        if member_ty.num_refs == 0 {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' is not a function pointer",
                value_type_name, callback_name
            )));
        }
        if !matches!(member_ty.base_type, Type::FunctionProto(_)) {
            return Err(BtfError::KernelBtfError(format!(
                "struct_ops callback '{}.{}' does not resolve to a function prototype",
                value_type_name, callback_name
            )));
        }

        Ok(member_ty.clone())
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

    /// Returns whether `kfunc_name` pointer argument `arg_idx` is const-qualified.
    pub fn kfunc_pointer_arg_is_const(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_const_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|const_args| const_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_const_pointer_arg_map().unwrap_or_default();
        let is_const = map
            .get(kfunc_name)
            .is_some_and(|const_args| const_args.contains(&arg_idx));

        let mut cache = self.kfunc_const_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_const
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires user-space pointers.
    pub fn kfunc_pointer_arg_requires_user(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_user_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|user_args| user_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_user_pointer_arg_map().unwrap_or_default();
        let requires_user = map
            .get(kfunc_name)
            .is_some_and(|user_args| user_args.contains(&arg_idx));

        let mut cache = self.kfunc_user_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_user
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires stack pointers.
    pub fn kfunc_pointer_arg_requires_stack(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_stack_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|stack_args| stack_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_stack_pointer_arg_map().unwrap_or_default();
        let requires_stack = map
            .get(kfunc_name)
            .is_some_and(|stack_args| stack_args.contains(&arg_idx));

        let mut cache = self.kfunc_stack_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_stack
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires kernel-space pointers.
    pub fn kfunc_pointer_arg_requires_kernel(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_kernel_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|kernel_args| kernel_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_kernel_pointer_arg_map().unwrap_or_default();
        let requires_kernel = map
            .get(kfunc_name)
            .is_some_and(|kernel_args| kernel_args.contains(&arg_idx));

        let mut cache = self.kfunc_kernel_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_kernel
    }

    /// Returns inferred pointer ref-family metadata for `kfunc_name` argument `arg_idx`.
    pub fn kfunc_pointer_arg_ref_family(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<KfuncPointerRefFamily> {
        {
            let cache = self.kfunc_pointer_ref_family_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(idx, _)| *idx == arg_idx))
                    .map(|(_, family)| *family);
            }
        }

        let map = self.load_kfunc_pointer_ref_family_map().unwrap_or_default();
        let ref_family = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(idx, _)| *idx == arg_idx))
            .map(|(_, family)| *family);

        let mut cache = self.kfunc_pointer_ref_family_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        ref_family
    }

    /// Returns inferred return-value ref-family metadata for `kfunc_name`.
    pub fn kfunc_return_ref_family(&self, kfunc_name: &str) -> Option<KfuncPointerRefFamily> {
        {
            let cache = self.kfunc_return_ref_family_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self.load_kfunc_return_ref_family_map().unwrap_or_default();
        let ref_family = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_return_ref_family_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        ref_family
    }

    /// Returns inferred release-argument index for `kfunc_name` if unambiguous in local BTF.
    pub fn kfunc_release_ref_arg_index(&self, kfunc_name: &str) -> Option<usize> {
        {
            let cache = self.kfunc_release_ref_arg_index_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self
            .load_kfunc_release_ref_arg_index_map()
            .unwrap_or_default();
        let arg_idx = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_release_ref_arg_index_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        arg_idx
    }

    fn flattened_base_type_bits(btf: &Btf, base_type: &Type) -> Option<u32> {
        match base_type {
            Type::Integer(int_ty) => Some(int_ty.bits),
            Type::Float(float_ty) => Some(float_ty.bits),
            Type::Enum32(_) => Some(32),
            Type::Enum64(_) => Some(64),
            Type::Array(array_ty) => btf
                .get_type_by_id(array_ty.elem_type_id)
                .ok()
                .and_then(|elem_ty| elem_ty.bits.checked_mul(array_ty.num_elements)),
            Type::Struct(struct_ty) | Type::Union(struct_ty) => {
                let mut max_bits: u32 = 0;
                for member in &struct_ty.members {
                    let member_bits = if let Some(bitfield_bits) = member.bits {
                        bitfield_bits
                    } else {
                        btf.get_type_by_id(member.type_id).ok()?.bits
                    };
                    let end = member.offset.checked_add(member_bits)?;
                    max_bits = max_bits.max(end);
                }
                Some(max_bits)
            }
            Type::Void | Type::Fwd(_) | Type::FunctionProto(_) | Type::DataSection(_) => None,
            Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::Function(_)
            | Type::Variable(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => None,
        }
    }

    fn trampoline_field_layout(
        btf: &Btf,
        type_id: u32,
        slot_index: usize,
        raw_size_bytes: Option<usize>,
    ) -> Result<TrampolineFieldLayout, BtfError> {
        let ty = btf.get_type_by_id(type_id).map_err(|e| {
            BtfError::KernelBtfError(format!("failed to resolve kernel BTF type {type_id}: {e}"))
        })?;
        let slot_count = Self::trampoline_slot_count(btf, &ty, raw_size_bytes)?;
        let value = Self::trampoline_value_kind(btf, &ty, raw_size_bytes)
            .map(|kind| TrampolineValueSpec { slot_index, kind });
        let unsupported_reason = value
            .is_none()
            .then(|| Self::trampoline_unsupported_reason(&ty));
        Ok(TrampolineFieldLayout {
            slot_index,
            slot_count,
            value,
            unsupported_reason,
        })
    }

    fn trampoline_size_bytes(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Result<usize, BtfError> {
        if ty.num_refs > 0 {
            return Ok(8);
        }
        if matches!(ty.base_type, Type::Struct(_) | Type::Union(_))
            && let Some(size) = raw_size_bytes
        {
            return Ok(size);
        }
        let bits = Self::flattened_base_type_bits(btf, &ty.base_type)
            .or_else(|| (ty.bits > 0).then_some(ty.bits))
            .ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "missing size information for trampoline type '{}'",
                    ty.name.as_deref().unwrap_or("<anonymous>")
                ))
            })?;
        usize::try_from(bits.div_ceil(8)).map_err(|_| {
            BtfError::KernelBtfError(format!(
                "size overflow for trampoline type '{}'",
                ty.name.as_deref().unwrap_or("<anonymous>")
            ))
        })
    }

    fn trampoline_slot_count(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Result<usize, BtfError> {
        let size_bytes = Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?;
        match size_bytes {
            1 | 2 | 4 | 8 => Ok(1),
            16 => Ok(2),
            _ => Err(BtfError::KernelBtfError(format!(
                "trampoline type '{}' uses unsupported {}-byte by-value layout",
                ty.name.as_deref().unwrap_or("<anonymous>"),
                size_bytes
            ))),
        }
    }

    fn trampoline_value_kind(
        btf: &Btf,
        ty: &FlattenedType,
        raw_size_bytes: Option<usize>,
    ) -> Option<TrampolineValueKind> {
        if ty.num_refs > 0 {
            return Some(TrampolineValueKind::Pointer {
                user_space: Self::has_user_type_tag(&ty.type_tags),
            });
        }

        match &ty.base_type {
            Type::Integer(_) | Type::Float(_) | Type::Enum32(_) | Type::Enum64(_) => {
                Some(TrampolineValueKind::Scalar)
            }
            Type::Array(_) | Type::Struct(_) | Type::Union(_) => {
                let size_bytes = Self::trampoline_size_bytes(btf, ty, raw_size_bytes).ok()?;
                Some(TrampolineValueKind::Aggregate { size_bytes })
            }
            Type::Void
            | Type::Fwd(_)
            | Type::Function(_)
            | Type::FunctionProto(_)
            | Type::Variable(_)
            | Type::DataSection(_) => None,
            Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => Some(TrampolineValueKind::Scalar),
        }
    }

    fn trampoline_unsupported_reason(ty: &FlattenedType) -> String {
        let type_name = ty.name.as_deref().unwrap_or("<anonymous>");
        match &ty.base_type {
            Type::Array(_) => format!("by-value array type '{type_name}'"),
            Type::Struct(_) | Type::Union(_) => format!("by-value aggregate type '{type_name}'"),
            Type::Void => "void type".to_string(),
            _ => format!("type '{type_name}'"),
        }
    }

    fn resolve_trampoline_field_projection(
        &self,
        btf: &Btf,
        root_type_id: u32,
        field_path: &[TrampolineFieldSelector],
        raw_type_sizes: &HashMap<u32, u32>,
    ) -> Result<TrampolineFieldProjection, BtfError> {
        if field_path.is_empty() {
            return Err(BtfError::KernelBtfError(
                "empty trampoline field path".to_string(),
            ));
        }

        let mut current_ty = btf
            .get_type_by_id(root_type_id)
            .map_err(|e| {
                BtfError::KernelBtfError(format!(
                    "failed to resolve kernel BTF type {}: {}",
                    root_type_id, e
                ))
            })?
            .clone();
        let mut path = Vec::with_capacity(field_path.len());

        let path_desc = Self::format_trampoline_field_path(field_path);
        for segment in field_path {
            while current_ty.num_refs > 1 && !matches!(segment, TrampolineFieldSelector::Index(_)) {
                let mut deref_ty = current_ty.clone();
                deref_ty.num_refs -= 1;
                path.push(TrampolineFieldPathSegment {
                    offset_bytes: 0,
                    type_info: Self::type_info_from_btf_type(btf, &deref_ty, raw_type_sizes)?,
                    bitfield: None,
                });
                current_ty = deref_ty;
            }
            let ty_name = current_ty.name.as_deref().unwrap_or("<anonymous>");
            let (next_ty, offset_bytes, bitfield, next_type_info) = match (
                segment,
                &current_ty.base_type,
            ) {
                (TrampolineFieldSelector::Field(segment), Type::Struct(struct_ty))
                | (TrampolineFieldSelector::Field(segment), Type::Union(struct_ty)) => {
                    let member = struct_ty
                        .members
                        .iter()
                        .find(|member| member.name.as_deref() == Some(segment.as_str()))
                        .ok_or_else(|| {
                            BtfError::KernelBtfError(format!(
                                "trampoline aggregate type '{}' has no field '{}'",
                                ty_name, segment
                            ))
                        })?;

                    let member_ty = btf
                        .get_type_by_id(member.type_id)
                        .map_err(|e| {
                            BtfError::KernelBtfError(format!(
                                "failed to resolve kernel BTF type {}: {}",
                                member.type_id, e
                            ))
                        })?
                        .clone();
                    let member_type_info =
                        Self::type_info_from_btf_type(btf, &member_ty, raw_type_sizes)?;

                    let (offset_bytes, bitfield) = if let Some(bit_size) =
                        member.bits.filter(|bits| *bits != 0)
                    {
                        if !matches!(member_type_info, TypeInfo::Int { .. }) {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' uses unsupported storage type {:?}",
                                ty_name, segment, member_type_info
                            )));
                        }

                        let raw_size_bytes = raw_type_sizes
                            .get(&member.type_id)
                            .copied()
                            .map(|size| size as usize);
                        let storage_size_bytes =
                            Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?;
                        let storage_bits =
                            u32::try_from(storage_size_bytes.checked_mul(8).ok_or_else(|| {
                                BtfError::KernelBtfError(format!(
                                    "size overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?)
                            .map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "size overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?;
                        if storage_bits == 0 {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' has zero-sized storage",
                                ty_name, segment
                            )));
                        }
                        let storage_base_bits = (member.offset / storage_bits)
                            .checked_mul(storage_bits)
                            .ok_or_else(|| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?;
                        let bit_offset = member.offset.checked_sub(storage_base_bits).ok_or_else(
                            || {
                                BtfError::KernelBtfError(format!(
                                    "offset underflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            },
                        )?;
                        let end_bits = bit_offset.checked_add(bit_size).ok_or_else(|| {
                            BtfError::KernelBtfError(format!(
                                "size overflow while resolving trampoline bitfield '{}.{}'",
                                ty_name, segment
                            ))
                        })?;
                        if end_bits > storage_bits {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline bitfield '{}.{}' spans multiple storage units",
                                ty_name, segment
                            )));
                        }
                        (
                            usize::try_from(storage_base_bits / 8).map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline bitfield '{}.{}'",
                                    ty_name, segment
                                ))
                            })?,
                            Some(TrampolineBitfieldInfo {
                                bit_offset,
                                bit_size,
                            }),
                        )
                    } else {
                        if member.offset % 8 != 0 {
                            return Err(BtfError::KernelBtfError(format!(
                                "trampoline field '{}.{}' is not byte-aligned",
                                ty_name, segment
                            )));
                        }
                        (
                            usize::try_from(member.offset / 8).map_err(|_| {
                                BtfError::KernelBtfError(format!(
                                    "offset overflow while resolving trampoline field '{}.{}'",
                                    ty_name, segment
                                ))
                            })?,
                            None,
                        )
                    };

                    (member_ty, offset_bytes, bitfield, Some(member_type_info))
                }
                (TrampolineFieldSelector::Field(segment), Type::Array(_)) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline array type '{}' does not have a field '{}'; use a numeric index",
                        ty_name, segment
                    )));
                }
                (TrampolineFieldSelector::Field(_), _) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline field path '{}' requires a struct/union or array, got '{}'",
                        path_desc, ty_name
                    )));
                }
                (TrampolineFieldSelector::Index(index), _) if current_ty.num_refs > 0 => {
                    let mut elem_ty = current_ty.clone();
                    elem_ty.num_refs -= 1;
                    let raw_size_bytes = raw_type_sizes
                        .get(&elem_ty.type_id)
                        .copied()
                        .map(|size| size as usize);
                    let elem_size_bytes =
                        Self::trampoline_size_bytes(btf, &elem_ty, raw_size_bytes)?;
                    let offset_bytes = index.checked_mul(elem_size_bytes).ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline field '{}'",
                            path_desc
                        ))
                    })?;
                    (elem_ty, offset_bytes, None, None)
                }
                (TrampolineFieldSelector::Index(index), Type::Array(array_ty)) => {
                    let num_elements = array_ty.num_elements as usize;
                    if *index >= num_elements {
                        return Err(BtfError::KernelBtfError(format!(
                            "trampoline array type '{}' index {} is out of bounds (len {})",
                            ty_name, index, num_elements
                        )));
                    }
                    let elem_ty = btf
                        .get_type_by_id(array_ty.elem_type_id)
                        .map_err(|e| {
                            BtfError::KernelBtfError(format!(
                                "failed to resolve kernel BTF type {}: {}",
                                array_ty.elem_type_id, e
                            ))
                        })?
                        .clone();
                    let raw_size_bytes = raw_type_sizes
                        .get(&array_ty.elem_type_id)
                        .copied()
                        .map(|size| size as usize);
                    let elem_size_bytes =
                        Self::trampoline_size_bytes(btf, &elem_ty, raw_size_bytes)?;
                    let offset_bytes = index.checked_mul(elem_size_bytes).ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline field '{}'",
                            path_desc
                        ))
                    })?;
                    (elem_ty, offset_bytes, None, None)
                }
                (TrampolineFieldSelector::Index(index), _) => {
                    return Err(BtfError::KernelBtfError(format!(
                        "trampoline field path '{}' cannot index {} on non-array type '{}'",
                        path_desc, index, ty_name
                    )));
                }
            };

            path.push(TrampolineFieldPathSegment {
                offset_bytes,
                type_info: match next_type_info {
                    Some(type_info) => type_info,
                    None => Self::type_info_from_btf_type(btf, &next_ty, raw_type_sizes)?,
                },
                bitfield,
            });
            current_ty = next_ty;
        }

        let type_info = path
            .last()
            .map(|segment| segment.type_info.clone())
            .ok_or_else(|| {
                BtfError::KernelBtfError("empty trampoline field projection".to_string())
            })?;

        Ok(TrampolineFieldProjection { path, type_info })
    }

    fn format_trampoline_field_path(field_path: &[TrampolineFieldSelector]) -> String {
        let mut out = String::new();
        for (idx, segment) in field_path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match segment {
                TrampolineFieldSelector::Field(name) => out.push_str(name),
                TrampolineFieldSelector::Index(index) => out.push_str(&index.to_string()),
            }
        }
        out
    }

    fn type_info_from_btf_type(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
    ) -> Result<TypeInfo, BtfError> {
        let mut active_type_ids = HashSet::new();
        Self::type_info_from_btf_type_inner(
            btf,
            ty,
            raw_type_sizes,
            &mut active_type_ids,
            Self::TRAMPOLINE_POINTER_TYPE_DEPTH,
        )
    }

    fn recursive_type_info_fallback(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
    ) -> Result<TypeInfo, BtfError> {
        let raw_size_bytes = raw_type_sizes
            .get(&ty.type_id)
            .copied()
            .map(|size| size as usize);
        match &ty.base_type {
            Type::Struct(_) | Type::Union(_) => Ok(TypeInfo::Struct {
                name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                btf_type_id: Some(ty.type_id),
                size: Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?,
                fields: Vec::new(),
            }),
            _ => Ok(TypeInfo::Unknown),
        }
    }

    fn type_info_from_btf_type_inner(
        btf: &Btf,
        ty: &FlattenedType,
        raw_type_sizes: &HashMap<u32, u32>,
        active_type_ids: &mut HashSet<u32>,
        pointer_type_depth: usize,
    ) -> Result<TypeInfo, BtfError> {
        let raw_size_bytes = raw_type_sizes
            .get(&ty.type_id)
            .copied()
            .map(|size| size as usize);
        if ty.num_refs > 0 {
            let mut pointee_ty = ty.clone();
            pointee_ty.num_refs -= 1;
            let target = if pointer_type_depth == 0
                || (pointee_ty.num_refs == 0 && active_type_ids.contains(&pointee_ty.type_id))
            {
                Self::recursive_type_info_fallback(btf, &pointee_ty, raw_type_sizes)?
            } else {
                Self::type_info_from_btf_type_inner(
                    btf,
                    &pointee_ty,
                    raw_type_sizes,
                    active_type_ids,
                    pointer_type_depth - 1,
                )?
            };
            return Ok(TypeInfo::Ptr {
                target: Box::new(target),
                is_user: Self::has_user_type_tag(&ty.type_tags),
            });
        }

        if !active_type_ids.insert(ty.type_id) {
            return Self::recursive_type_info_fallback(btf, ty, raw_type_sizes);
        }

        let result = match &ty.base_type {
            Type::Integer(int_ty) => Ok(TypeInfo::Int {
                size: usize::try_from(int_ty.bits.div_ceil(8)).map_err(|_| {
                    BtfError::KernelBtfError(format!(
                        "size overflow for integer trampoline field '{}'",
                        ty.name.as_deref().unwrap_or("<anonymous>")
                    ))
                })?,
                signed: int_ty.is_signed,
            }),
            Type::Enum32(_) => Ok(TypeInfo::Int {
                size: 4,
                signed: false,
            }),
            Type::Enum64(_) => Ok(TypeInfo::Int {
                size: 8,
                signed: false,
            }),
            Type::Array(array_ty) => {
                let elem_ty = btf.get_type_by_id(array_ty.elem_type_id).map_err(|e| {
                    BtfError::KernelBtfError(format!(
                        "failed to resolve array element type {}: {}",
                        array_ty.elem_type_id, e
                    ))
                })?;
                Ok(TypeInfo::Array {
                    element: Box::new(Self::type_info_from_btf_type_inner(
                        btf,
                        &elem_ty,
                        raw_type_sizes,
                        active_type_ids,
                        pointer_type_depth,
                    )?),
                    len: array_ty.num_elements as usize,
                })
            }
            Type::Struct(struct_ty) => {
                let size = Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?;
                Ok(TypeInfo::Struct {
                    name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                    btf_type_id: Some(ty.type_id),
                    size,
                    fields: Self::struct_field_infos_from_btf_type(
                        btf,
                        struct_ty,
                        size,
                        raw_type_sizes,
                        active_type_ids,
                        pointer_type_depth,
                    )?,
                })
            }
            Type::Union(_) => Ok(TypeInfo::Struct {
                name: ty.name.clone().unwrap_or_else(|| "<anonymous>".to_string()),
                btf_type_id: Some(ty.type_id),
                size: Self::trampoline_size_bytes(btf, ty, raw_size_bytes)?,
                fields: Vec::new(),
            }),
            Type::Void => Ok(TypeInfo::Void),
            Type::Float(_)
            | Type::Fwd(_)
            | Type::FunctionProto(_)
            | Type::DataSection(_)
            | Type::Pointer(_)
            | Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::Function(_)
            | Type::Variable(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => Ok(TypeInfo::Unknown),
        };

        active_type_ids.remove(&ty.type_id);
        result
    }

    fn struct_field_infos_from_btf_type(
        btf: &Btf,
        struct_ty: &btf::btf::Struct,
        struct_size: usize,
        raw_type_sizes: &HashMap<u32, u32>,
        active_type_ids: &mut HashSet<u32>,
        pointer_type_depth: usize,
    ) -> Result<Vec<FieldInfo>, BtfError> {
        let mut fields = Vec::with_capacity(struct_ty.members.len());
        for member in &struct_ty.members {
            let Some(name) = member.name.clone() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let member_ty = btf.get_type_by_id(member.type_id).map_err(|e| {
                BtfError::KernelBtfError(format!(
                    "failed to resolve kernel BTF type {}: {}",
                    member.type_id, e
                ))
            })?;
            let type_info = Self::type_info_from_btf_type_inner(
                btf,
                &member_ty,
                raw_type_sizes,
                active_type_ids,
                pointer_type_depth,
            )?;
            let raw_size_bytes = raw_type_sizes
                .get(&member.type_id)
                .copied()
                .map(|size| size as usize);
            let (offset, size, bitfield) = if let Some(bit_size) =
                member.bits.filter(|bits| *bits != 0)
            {
                if !matches!(type_info, TypeInfo::Int { .. }) {
                    continue;
                }
                let storage_size = Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?;
                let storage_bits = u32::try_from(storage_size.checked_mul(8).ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?)
                .map_err(|_| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?;
                if storage_bits == 0 {
                    continue;
                }
                let storage_base_bits = (member.offset / storage_bits)
                    .checked_mul(storage_bits)
                    .ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?;
                let bit_offset = member
                    .offset
                    .checked_sub(storage_base_bits)
                    .ok_or_else(|| {
                        BtfError::KernelBtfError(format!(
                            "offset underflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?;
                let end_bits = bit_offset.checked_add(bit_size).ok_or_else(|| {
                    BtfError::KernelBtfError(format!(
                        "size overflow while resolving trampoline aggregate member '{}'",
                        name
                    ))
                })?;
                if end_bits > storage_bits {
                    continue;
                }
                (
                    usize::try_from(storage_base_bits / 8).map_err(|_| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?,
                    storage_size,
                    Some(BitfieldInfo {
                        bit_offset,
                        bit_size,
                    }),
                )
            } else {
                if member.offset % 8 != 0 {
                    continue;
                }
                (
                    usize::try_from(member.offset / 8).map_err(|_| {
                        BtfError::KernelBtfError(format!(
                            "offset overflow while resolving trampoline aggregate member '{}'",
                            name
                        ))
                    })?,
                    Self::trampoline_size_bytes(btf, &member_ty, raw_size_bytes)?,
                    None,
                )
            };
            let end = offset.checked_add(size).ok_or_else(|| {
                BtfError::KernelBtfError(format!(
                    "size overflow while resolving trampoline aggregate member '{}'",
                    name
                ))
            })?;
            if end > struct_size {
                continue;
            }

            fields.push(FieldInfo {
                name,
                type_info,
                offset,
                size,
                bitfield,
            });
        }

        Ok(fields)
    }

    fn pointer_pointee_size_bytes(btf: &Btf, param_type_id: u32) -> Option<usize> {
        let param_ty = btf.get_type_by_id(param_type_id).ok()?;
        if param_ty.num_refs == 0 {
            return None;
        }
        if param_ty.num_refs > 1 {
            return Some(8);
        }
        let bits = Self::flattened_base_type_bits(btf, &param_ty.base_type)?;
        if bits == 0 {
            return None;
        }
        usize::try_from(bits.div_ceil(8)).ok()
    }

    fn load_kfunc_pointer_fixed_size_map(
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

            let mut pointer_args_with_dynamic_sizes: HashSet<usize> = HashSet::new();
            for param in &proto.params {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                let Some(base) = Self::kfunc_size_param_base_name(param_name) else {
                    continue;
                };
                if let Some(ptr_arg_idx) = pointer_args_by_name.get(base).copied() {
                    pointer_args_with_dynamic_sizes.insert(ptr_arg_idx);
                }
            }

            let mut fixed_size_args: Vec<(usize, usize)> = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if pointer_args_with_dynamic_sizes.contains(&arg_idx) {
                    continue;
                }
                let Some(size_bytes) = Self::pointer_pointee_size_bytes(&btf, param.type_id) else {
                    continue;
                };
                if size_bytes == 0 {
                    continue;
                }
                fixed_size_args.push((arg_idx, size_bytes));
            }

            if !fixed_size_args.is_empty() {
                map.insert(name.clone(), fixed_size_args);
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

    /// Returns the inferred fixed access size for a pointer argument, if available.
    ///
    /// This is inferred from the local kernel BTF pointee type when no
    /// name-paired dynamic `*__sz`/`*__szk` argument exists.
    pub fn kfunc_pointer_arg_fixed_size(&self, kfunc_name: &str, arg_idx: usize) -> Option<usize> {
        {
            let cache = self.kfunc_pointer_fixed_size_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
                    .map(|(_, size)| *size);
            }
        }

        let map = self.load_kfunc_pointer_fixed_size_map().unwrap_or_default();
        let size = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
            .map(|(_, size)| *size);

        let mut cache = self.kfunc_pointer_fixed_size_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        size
    }

    /// Returns whether `kfunc_name` pointer arg should be a stack-slot base when in stack space.
    pub fn kfunc_pointer_arg_requires_stack_slot_base(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> bool {
        {
            let cache = self.kfunc_stack_slot_base_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_stack_slot_base_arg_map()
            .unwrap_or_default();
        let requires_base = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_stack_slot_base_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_base
    }

    /// Returns whether `kfunc_name` pointer arg appears to be an output parameter by name.
    pub fn kfunc_pointer_arg_is_named_out(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_out_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_out_pointer_arg_map().unwrap_or_default();
        let is_named_out = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_out_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_named_out
    }

    /// Returns whether `kfunc_name` pointer arg appears to be an input parameter by name.
    pub fn kfunc_pointer_arg_is_named_in(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_in_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_in_pointer_arg_map().unwrap_or_default();
        let is_named_in = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_in_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_named_in
    }

    /// Returns the inferred stack-object pointee type name for a pointer argument, if any.
    pub fn kfunc_pointer_arg_stack_object_type_name(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<String> {
        {
            let cache = self.kfunc_stack_object_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
                    .map(|(_, _, type_name)| type_name.clone());
            }
        }

        let map = self.load_kfunc_stack_object_arg_map().unwrap_or_default();
        let type_name = map
            .get(kfunc_name)
            .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
            .map(|(_, _, type_name)| type_name.clone());

        let mut cache = self.kfunc_stack_object_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        type_name
    }

    /// Returns the inferred stack-object pointee type ID for a pointer argument, if any.
    pub fn kfunc_pointer_arg_stack_object_type_id(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<u32> {
        {
            let cache = self.kfunc_stack_object_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
                    .map(|(_, type_id, _)| *type_id);
            }
        }

        let map = self.load_kfunc_stack_object_arg_map().unwrap_or_default();
        let type_id = map
            .get(kfunc_name)
            .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
            .map(|(_, type_id, _)| *type_id);

        let mut cache = self.kfunc_stack_object_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        type_id
    }
}

#[cfg(test)]
mod tests;
