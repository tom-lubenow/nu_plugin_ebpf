//! Verifier-Compatible Core (VCC) IR
//!
//! VCC is a minimal, typed core language that makes pointer-sensitive
//! operations explicit. Its invariants are designed to mirror the eBPF
//! verifier so that violations are caught before codegen.
//!
//! Core invariants (initial draft):
//! - Pointer arithmetic is explicit (`PtrAdd`) and never encoded as `BinOp`.
//! - `BinOp` operates on scalars only (no pointer + pointer).
//! - Stack pointer arithmetic requires bounded scalar offsets.
//! - Loads/stores require pointer operands and must respect stack bounds.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::compiler::cfg::CFG;
use crate::compiler::ctx_field_schema::ContextFieldLoadGuard;
use crate::compiler::instruction::{
    BpfHelper, HelperArgKind, HelperDynptrArgRole, HelperRetKind, HelperSignature, KfuncArgKind,
    KfuncIterFamily, KfuncIterLifecycleOp, KfuncRefKind, KfuncRetKind, KfuncSignature,
    KfuncUnknownDynptrArg, KfuncUnknownDynptrArgRole, KfuncUnknownDynptrCopy,
    KfuncUnknownIterLifecycle, KfuncUnknownStackObjectCopy, KfuncUnknownStackObjectLifecycle,
    KfuncUnknownStackObjectLifecycleOp, helper_acquire_ref_kind, helper_pointer_arg_ref_kind,
    helper_release_ref_kind, kfunc_acquire_ref_kind, kfunc_allowed_while_lock_held,
    kfunc_arg_requires_known_zero as kfunc_arg_requires_known_zero_shared,
    kfunc_bpf_spin_lock_protected_graph_root_arg,
    kfunc_iter_lifecycle as kfunc_iter_lifecycle_shared,
    kfunc_pointer_arg_allows_const_zero as kfunc_pointer_arg_allows_const_zero_shared,
    kfunc_pointer_arg_fixed_size as kfunc_pointer_arg_fixed_size_shared,
    kfunc_pointer_arg_min_access_size as kfunc_pointer_arg_min_access_size_shared,
    kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
    kfunc_pointer_arg_requires_raw_context as kfunc_pointer_arg_requires_raw_context_shared,
    kfunc_pointer_arg_requires_stack as kfunc_pointer_arg_requires_stack_shared,
    kfunc_pointer_arg_requires_stack_or_map as kfunc_pointer_arg_requires_stack_or_map_shared,
    kfunc_pointer_arg_requires_stack_slot_base as kfunc_pointer_arg_requires_stack_slot_base_shared,
    kfunc_pointer_arg_requires_user as kfunc_pointer_arg_requires_user_shared,
    kfunc_pointer_arg_size_from_scalar as kfunc_pointer_arg_size_from_scalar_shared,
    kfunc_ref_kind_from_bpf_type_name, kfunc_release_ref_arg_index, kfunc_release_ref_kind,
    kfunc_scalar_arg_requires_known_const as kfunc_scalar_arg_requires_known_const_shared,
    kfunc_scalar_arg_requires_positive as kfunc_scalar_arg_requires_positive_shared,
    kfunc_semantics, kfunc_supports_local_map_fd as kfunc_supports_local_map_fd_shared,
    kfunc_unknown_dynptr_args as kfunc_unknown_dynptr_args_shared,
    kfunc_unknown_dynptr_copy as kfunc_unknown_dynptr_copy_shared,
    kfunc_unknown_stack_object_copy as kfunc_unknown_stack_object_copy_shared,
    kfunc_unknown_stack_object_lifecycle as kfunc_unknown_stack_object_lifecycle_shared,
};
use crate::compiler::mir::{
    AddressSpace, BYTES_COUNTER_MAP_NAME, BinOpKind, COUNTER_MAP_NAME, CtxField,
    HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME, MapKind, MapOpKind, MapRef, MirFunction, MirInst, MirType,
    MirValue, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME, ScalarValueRange, StackSlotId,
    StackSlotKind, StringAppendType, SubfunctionId, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME,
    UnaryOpKind, VReg,
};
use crate::compiler::passes::{ListLowering, MirPass};
use crate::compiler::type_infer::validate_program_capabilities_for_info;
use crate::compiler::{ProbeContext, ProgramTypeInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VccReg(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VccBlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccAddrSpace {
    Stack(StackSlotId),
    MapValue,
    Packet,
    Context,
    RingBuf,
    Kernel,
    KernelBtf,
    User,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VccBounds {
    pub min: i64,
    pub max: i64,
    pub limit: i64,
}

const UNKNOWN_PACKET_LIMIT: i64 = i64::MAX / 4;
const UNKNOWN_CONTEXT_BUFFER_LIMIT: i64 = i64::MAX / 4;

impl VccBounds {
    fn shifted(self, offset: VccRange) -> Option<VccBounds> {
        let new_min = self.min.saturating_add(offset.min);
        let new_max = self.max.saturating_add(offset.max);
        if new_min < 0 || new_max > self.limit {
            return None;
        }
        Some(VccBounds {
            min: new_min,
            max: new_max,
            limit: self.limit,
        })
    }

    fn shifted_with_size(self, offset: i64, size: i64) -> Option<VccBounds> {
        if size <= 0 {
            return None;
        }
        let new_min = self.min.saturating_add(offset);
        let new_max = self
            .max
            .saturating_add(offset)
            .saturating_add(size.saturating_sub(1));
        if new_min < 0 || new_max > self.limit {
            return None;
        }
        Some(VccBounds {
            min: new_min,
            max: new_max,
            limit: self.limit,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccValue {
    Reg(VccReg),
    Imm(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccTypeClass {
    Scalar,
    Bool,
    Ptr,
    Unknown,
    Uninit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccNullability {
    NonNull,
    MaybeNull,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccPacketCtxField {
    Data,
    DataMeta,
    DataEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VccPointerInfo {
    pub space: VccAddrSpace,
    pub nullability: VccNullability,
    pub bounds: Option<VccBounds>,
    pub packet_root: Option<VccReg>,
    pub packet_root_field: Option<VccPacketCtxField>,
    pub packet_ctx_field: Option<VccPacketCtxField>,
    pub packet_end: bool,
    pub map_root: Option<VccReg>,
    pub context_buffer_root: Option<VccReg>,
    pub context_buffer_end: bool,
    pub ringbuf_ref: Option<VccReg>,
    pub kfunc_ref: Option<VccReg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VccRange {
    pub min: i64,
    pub max: i64,
}

impl VccRange {
    fn add(self, other: VccRange) -> VccRange {
        VccRange {
            min: self.min.saturating_add(other.min),
            max: self.max.saturating_add(other.max),
        }
    }

    fn sub(self, other: VccRange) -> VccRange {
        VccRange {
            min: self.min.saturating_sub(other.max),
            max: self.max.saturating_sub(other.min),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VccValueType {
    Uninit,
    Unknown,
    StalePacketPtr,
    Bool,
    Scalar { range: Option<VccRange> },
    Ptr(VccPointerInfo),
}

impl VccValueType {
    fn class(&self) -> VccTypeClass {
        match self {
            VccValueType::Uninit => VccTypeClass::Uninit,
            VccValueType::Unknown => VccTypeClass::Unknown,
            VccValueType::StalePacketPtr => VccTypeClass::Unknown,
            VccValueType::Bool => VccTypeClass::Bool,
            VccValueType::Scalar { .. } => VccTypeClass::Scalar,
            VccValueType::Ptr(_) => VccTypeClass::Ptr,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VccInst {
    Const {
        dst: VccReg,
        value: i64,
    },
    Copy {
        dst: VccReg,
        src: VccValue,
    },
    Assume {
        dst: VccReg,
        ty: VccValueType,
        ctx_field_source: Option<CtxField>,
    },
    CtxFieldSource {
        reg: VccReg,
        field: CtxField,
    },
    ScalarAlias {
        dst: VccReg,
        src: VccReg,
    },
    MapLookupSource {
        root: VccReg,
        map: MapRef,
        key: VccReg,
    },
    AmbiguousMapLookupSource {
        root: VccReg,
    },
    MapFdSource {
        map_fd: VccReg,
        map: MapRef,
    },
    AssertMapFdMatchesMapValue {
        map_value: VccReg,
        map_fd: VccReg,
        map_value_label: String,
        map_fd_label: String,
        call: String,
    },
    AssertScalar {
        value: VccValue,
        op: Option<&'static str>,
    },
    AssertPositive {
        value: VccValue,
        message: String,
    },
    AssertConstEq {
        value: VccValue,
        expected: i64,
        message: String,
    },
    AssertRange {
        value: VccValue,
        min: i64,
        max: i64,
        message: String,
    },
    AssertAllowedValues {
        value: VccValue,
        allowed: Vec<i64>,
        message: String,
    },
    AssertBitmask {
        value: VccValue,
        mask: i64,
        message: String,
    },
    AssertConstEqIfConstEq {
        value: VccValue,
        expected: i64,
        when_value: VccValue,
        when_expected: i64,
        message: String,
    },
    AssertCtxFieldLoadGuard {
        field: CtxField,
        guard: ContextFieldLoadGuard,
    },
    AssertKnownConst {
        value: VccValue,
        message: String,
    },
    AssertPtrAccess {
        ptr: VccReg,
        size: VccValue,
        op: &'static str,
    },
    AssertPtrAccessOrZero {
        ptr: VccReg,
        size: VccValue,
        op: &'static str,
    },
    AssertStackSlotBase {
        ptr: VccReg,
        op: String,
    },
    AssertDistinctStackSlots {
        lhs: VccReg,
        rhs: VccReg,
        message: String,
    },
    StackAddr {
        dst: VccReg,
        slot: StackSlotId,
        size: i64,
    },
    BinOp {
        dst: VccReg,
        op: VccBinOp,
        lhs: VccValue,
        rhs: VccValue,
    },
    PtrAdd {
        dst: VccReg,
        base: VccReg,
        offset: VccValue,
    },
    Load {
        dst: VccReg,
        ptr: VccReg,
        offset: i64,
        size: u8,
    },
    Store {
        ptr: VccReg,
        offset: i64,
        src: VccValue,
        size: u8,
    },
    Phi {
        dst: VccReg,
        args: Vec<(VccBlockId, VccReg)>,
    },
    InvalidatePacketPointers,
    RingbufAcquire {
        id: VccReg,
    },
    RingbufRelease {
        ptr: VccValue,
    },
    KfuncAcquire {
        id: VccReg,
        kind: KfuncRefKind,
    },
    KfuncRelease {
        call: String,
        ptr: VccValue,
        kind: KfuncRefKind,
        arg_idx: usize,
    },
    RcuReadLockAcquire,
    RcuReadLockRelease,
    PreemptDisableAcquire,
    PreemptDisableRelease,
    LocalIrqDisableAcquire {
        flags: VccReg,
    },
    LocalIrqDisableRelease {
        flags: VccReg,
    },
    ResSpinLockAcquire {
        lock: VccReg,
    },
    ResSpinLockRelease {
        lock: VccReg,
    },
    BpfSpinLockAcquire {
        lock: VccReg,
    },
    BpfSpinLockRelease {
        lock: VccReg,
    },
    KernelLockRejectIfHeld {
        call: String,
    },
    BpfSpinLockRequireHeld {
        root: VccReg,
        message: String,
    },
    ResSpinLockIrqsaveAcquire {
        lock: VccReg,
        flags: VccReg,
    },
    ResSpinLockIrqsaveRelease {
        lock: VccReg,
        flags: VccReg,
    },
    IterLifecycle {
        iter: VccReg,
        kfunc: String,
        family: KfuncIterFamily,
        op: KfuncIterLifecycleOp,
    },
    DynptrMarkInitialized {
        ptr: VccReg,
        kfunc: String,
        arg_idx: usize,
    },
    DynptrRequireInitialized {
        ptr: VccReg,
        kfunc: String,
        arg_idx: usize,
    },
    DynptrDeinitialize {
        ptr: VccReg,
        kfunc: String,
        arg_idx: usize,
    },
    DynptrMarkMaybeInitialized {
        ptr: VccReg,
        kfunc: String,
        arg_idx: usize,
    },
    HelperDynptrMarkInitialized {
        ptr: VccReg,
        helper: String,
        arg_idx: usize,
    },
    HelperDynptrRequireInitialized {
        ptr: VccReg,
        helper: String,
        arg_idx: usize,
    },
    HelperRingbufDynptrAcquire {
        ptr: VccReg,
        helper: String,
        arg_idx: usize,
    },
    HelperRingbufDynptrRelease {
        ptr: VccReg,
        helper: String,
        arg_idx: usize,
    },
    DynptrCopy {
        src: VccReg,
        dst: VccReg,
        kfunc: String,
        src_arg_idx: usize,
        dst_arg_idx: usize,
        move_semantics: bool,
    },
    UnknownStackObjectInit {
        ptr: VccReg,
        type_name: String,
        type_id: Option<u32>,
        kfunc: String,
        arg_idx: usize,
    },
    UnknownStackObjectRequireInitialized {
        ptr: VccReg,
        type_name: String,
        type_id: Option<u32>,
        kfunc: String,
        arg_idx: usize,
    },
    UnknownStackObjectDestroy {
        ptr: VccReg,
        type_name: String,
        type_id: Option<u32>,
        kfunc: String,
        arg_idx: usize,
    },
    UnknownStackObjectMarkMaybeInitialized {
        ptr: VccReg,
        type_name: String,
        type_id: Option<u32>,
        kfunc: String,
        arg_idx: usize,
    },
    UnknownStackObjectCopy {
        src: VccReg,
        dst: VccReg,
        type_name: String,
        type_id: Option<u32>,
        kfunc: String,
        src_arg_idx: usize,
        dst_arg_idx: usize,
        move_semantics: bool,
    },
    KfuncExpectRefKind {
        ptr: VccValue,
        arg_idx: usize,
        kind: KfuncRefKind,
        kfunc: String,
    },
    HelperExpectRefKind {
        ptr: VccValue,
        arg_idx: usize,
        kind: KfuncRefKind,
        helper_id: u32,
    },
    KptrXchgTransfer {
        dst: VccReg,
        src: VccValue,
        dst_slot_kind: Option<KfuncRefKind>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VccTerminator {
    Jump {
        target: VccBlockId,
    },
    Branch {
        cond: VccValue,
        if_true: VccBlockId,
        if_false: VccBlockId,
    },
    Return {
        value: Option<VccValue>,
    },
}

#[derive(Debug, Clone)]
pub struct VccBlock {
    pub id: VccBlockId,
    pub instructions: Vec<VccInst>,
    pub terminator: VccTerminator,
}

#[derive(Debug, Clone)]
pub struct VccFunction {
    pub entry: VccBlockId,
    pub blocks: Vec<VccBlock>,
    entry_initialized_dynptr_slots: HashSet<StackSlotId>,
    reg_count: u32,
}

impl VccFunction {
    pub fn new() -> Self {
        let entry = VccBlockId(0);
        Self {
            entry,
            blocks: vec![VccBlock {
                id: entry,
                instructions: Vec::new(),
                terminator: VccTerminator::Return { value: None },
            }],
            entry_initialized_dynptr_slots: HashSet::new(),
            reg_count: 0,
        }
    }

    pub fn alloc_reg(&mut self) -> VccReg {
        let reg = VccReg(self.reg_count);
        self.reg_count += 1;
        reg
    }

    pub fn alloc_block(&mut self) -> VccBlockId {
        let id = VccBlockId(self.blocks.len() as u32);
        self.blocks.push(VccBlock {
            id,
            instructions: Vec::new(),
            terminator: VccTerminator::Return { value: None },
        });
        id
    }

    pub fn block_mut(&mut self, id: VccBlockId) -> &mut VccBlock {
        let idx = id.0 as usize;
        &mut self.blocks[idx]
    }

    pub fn block(&self, id: VccBlockId) -> &VccBlock {
        let idx = id.0 as usize;
        &self.blocks[idx]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VccErrorKind {
    UseOfUninitializedReg(VccReg),
    TypeMismatch {
        expected: VccTypeClass,
        actual: VccTypeClass,
    },
    PointerArithmetic,
    PointerBounds,
    UnknownOffset,
    InvalidLoadStore,
    UnsupportedInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VccError {
    pub kind: VccErrorKind,
    pub message: String,
}

impl VccError {
    fn new(kind: VccErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VccError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Default)]
pub struct VccVerifier {
    errors: Vec<VccError>,
    current_summary: Option<crate::compiler::subfn_summaries::SubfunctionSummary>,
}

include!("vcc/verifier.rs");
include!("vcc/state.rs");
pub fn verify_mir(func: &MirFunction, types: &HashMap<VReg, MirType>) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_impl(func, types, &HashMap::new(), None, None, None, None)
}

pub fn verify_mir_for_program(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    program: &ProgramTypeInfo,
) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        &HashMap::new(),
        None,
        Some(program),
        None,
        None,
    )
}

#[cfg(test)]
pub(crate) fn verify_mir_for_probe_context(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    probe_ctx: &ProbeContext,
) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        &HashMap::new(),
        None,
        Some(probe_ctx.program_info()),
        Some(probe_ctx),
        None,
    )
}

#[allow(dead_code)]
pub(crate) fn verify_mir_with_subfunction_summaries(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, crate::compiler::subfn_summaries::SubfunctionSummary>,
) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_impl(func, types, subfn_summaries, None, None, None, None)
}

#[allow(dead_code)]
pub(crate) fn verify_mir_with_subfunction_summaries_for_probe_context(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, crate::compiler::subfn_summaries::SubfunctionSummary>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        func,
        types,
        subfn_summaries,
        None,
        probe_ctx,
        generic_map_value_types,
    )
}

pub(crate) fn verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, crate::compiler::subfn_summaries::SubfunctionSummary>,
    current_summary: Option<crate::compiler::subfn_summaries::SubfunctionSummary>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VccError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        subfn_summaries,
        current_summary,
        probe_ctx.map(|ctx| ctx.program_info()),
        probe_ctx,
        generic_map_value_types,
    )
}

fn verify_mir_with_subfunction_summaries_impl(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, crate::compiler::subfn_summaries::SubfunctionSummary>,
    current_summary: Option<crate::compiler::subfn_summaries::SubfunctionSummary>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VccError>> {
    let effective_program = probe_ctx.map(|ctx| ctx.program_info()).or(program);

    if let Some(program) = effective_program {
        if let Err(errors) = validate_program_capabilities_for_info(func, program) {
            return Err(errors
                .into_iter()
                .map(|err| VccError::new(VccErrorKind::UnsupportedInstruction, err.message))
                .collect());
        }
    }

    if func.param_count > 5 {
        return Err(vec![VccError::new(
            VccErrorKind::UnsupportedInstruction,
            format!(
                "BPF subfunctions support at most 5 arguments, got {}",
                func.param_count
            ),
        )]);
    }
    let empty_map_value_types = HashMap::new();
    let mut early_errors = check_generic_map_layout_constraints(
        func,
        types,
        generic_map_value_types.unwrap_or(&empty_map_value_types),
    );
    early_errors.extend(check_list_operands(func, types));
    if !early_errors.is_empty() {
        return Err(early_errors);
    }
    let list_max = collect_list_max(func);
    let mut verify_func = func.clone();
    let cfg = CFG::build(&verify_func);
    let list_lowering = ListLowering;
    let _ = list_lowering.run(&mut verify_func, &cfg);

    let mut lowerer = VccLowerer::new(
        &verify_func,
        types,
        list_max,
        subfn_summaries,
        current_summary.clone(),
        effective_program,
        probe_ctx,
    );
    let vcc_func = match lowerer.lower() {
        Ok(vcc) => vcc,
        Err(err) => return Err(vec![err]),
    };
    let seed = lowerer.seed_types();
    VccVerifier {
        current_summary,
        ..Default::default()
    }
    .verify_function_with_seed(&vcc_func, seed)
}

include!("vcc/lower.rs");
fn record_field_size(ty: &MirType) -> usize {
    match ty {
        MirType::I64 | MirType::U64 => 8,
        MirType::I32 | MirType::U32 => 8,
        MirType::I16 | MirType::U16 => 8,
        MirType::I8 | MirType::U8 | MirType::Bool => 8,
        ty if ty.byte_array_len() == Some(16) => 16,
        ty if ty.byte_array_len().is_some() => {
            let len = ty
                .byte_array_len()
                .expect("byte-array length must exist after guard");
            (len + 7) & !7
        }
        _ => 8,
    }
}

fn record_field_requires_pointer(ty: &MirType) -> bool {
    matches!(ty, MirType::Array { .. } | MirType::Struct { .. }) || ty.size() > 8
}

fn record_pointer_access_size(field_ty: &MirType, value_ty: Option<&MirType>) -> usize {
    match value_ty {
        Some(MirType::Ptr { pointee, .. })
            if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
        {
            pointee.size().max(1)
        }
        _ => record_field_size(field_ty).max(1),
    }
}

include!("vcc/map_layout.rs");
fn vcc_type_from_mir(ty: &MirType) -> VccValueType {
    match ty {
        MirType::Bool => VccValueType::Bool,
        MirType::Ptr {
            address_space,
            pointee,
        } => {
            let bounds = if matches!(address_space, AddressSpace::Map | AddressSpace::Stack)
                && !matches!(pointee.as_ref(), MirType::Unknown)
            {
                let size = pointee.size();
                if size > 0 {
                    Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: size.saturating_sub(1) as i64,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            VccValueType::Ptr(VccPointerInfo {
                space: match address_space {
                    AddressSpace::Stack => VccAddrSpace::Stack(StackSlotId(u32::MAX)),
                    AddressSpace::Kernel => VccAddrSpace::Kernel,
                    AddressSpace::User => VccAddrSpace::User,
                    AddressSpace::Packet => VccAddrSpace::Packet,
                    AddressSpace::Context => VccAddrSpace::Context,
                    AddressSpace::Map => VccAddrSpace::MapValue,
                },
                nullability: match address_space {
                    AddressSpace::Stack | AddressSpace::Packet | AddressSpace::Context => {
                        VccNullability::NonNull
                    }
                    AddressSpace::Map | AddressSpace::Kernel | AddressSpace::User => {
                        VccNullability::MaybeNull
                    }
                },
                bounds,
                packet_root: None,
                packet_root_field: None,
                packet_ctx_field: None,
                packet_end: false,
                map_root: None,
                context_buffer_root: None,
                context_buffer_end: false,
                ringbuf_ref: None,
                kfunc_ref: None,
            })
        }
        MirType::Subprogram { .. } => VccValueType::Unknown,
        MirType::Unknown => VccValueType::Unknown,
        _ => VccValueType::Scalar { range: None },
    }
}

fn ptr_info_from_mir(ty: &MirType) -> Option<VccPointerInfo> {
    match vcc_type_from_mir(ty) {
        VccValueType::Ptr(info) => Some(info),
        _ => None,
    }
}

fn to_vcc_binop(op: BinOpKind) -> VccBinOp {
    match op {
        BinOpKind::Add => VccBinOp::Add,
        BinOpKind::Sub => VccBinOp::Sub,
        BinOpKind::Mul => VccBinOp::Mul,
        BinOpKind::Div => VccBinOp::Div,
        BinOpKind::Mod => VccBinOp::Mod,
        BinOpKind::And => VccBinOp::And,
        BinOpKind::Or => VccBinOp::Or,
        BinOpKind::Xor => VccBinOp::Xor,
        BinOpKind::Shl => VccBinOp::Shl,
        BinOpKind::Shr | BinOpKind::ArShr => VccBinOp::Shr,
        BinOpKind::Eq => VccBinOp::Eq,
        BinOpKind::Ne => VccBinOp::Ne,
        BinOpKind::Lt => VccBinOp::Lt,
        BinOpKind::Le => VccBinOp::Le,
        BinOpKind::Gt => VccBinOp::Gt,
        BinOpKind::Ge => VccBinOp::Ge,
    }
}

fn stack_bounds(size: i64) -> Option<VccBounds> {
    if size <= 0 {
        return None;
    }
    Some(VccBounds {
        min: 0,
        max: 0,
        limit: size.saturating_sub(1),
    })
}

fn collect_list_max(func: &MirFunction) -> HashMap<StackSlotId, usize> {
    let mut maxes = HashMap::new();
    for block in &func.blocks {
        for inst in block
            .instructions
            .iter()
            .chain(std::iter::once(&block.terminator))
        {
            if let MirInst::ListNew {
                buffer, max_len, ..
            } = inst
            {
                maxes
                    .entry(*buffer)
                    .and_modify(|existing: &mut usize| {
                        *existing = (*existing).min(*max_len);
                    })
                    .or_insert(*max_len);
            }
        }
    }
    maxes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListOperandFact {
    NonPtr(VccTypeClass),
    Ptr(VccAddrSpace),
}

fn check_list_operands(func: &MirFunction, types: &HashMap<VReg, MirType>) -> Vec<VccError> {
    let mut facts: HashMap<VReg, ListOperandFact> = types
        .iter()
        .filter_map(|(reg, ty)| list_operand_fact_from_mir_type(ty).map(|fact| (*reg, fact)))
        .collect();
    let mut errors = Vec::new();

    for block in &func.blocks {
        for inst in block
            .instructions
            .iter()
            .chain(std::iter::once(&block.terminator))
        {
            match inst {
                MirInst::ListLen { list, .. } => {
                    check_list_reg_operand(*list, &facts, func, &mut errors);
                }
                MirInst::ListPush { list, item } => {
                    check_list_reg_operand(*list, &facts, func, &mut errors);
                    if list_scalar_operand_is_pointer(&MirValue::VReg(*item), &facts) {
                        errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: VccTypeClass::Ptr,
                            },
                            "list push item expects scalar",
                        ));
                    }
                }
                MirInst::ListGet { list, idx, .. } => {
                    check_list_reg_operand(*list, &facts, func, &mut errors);
                    if list_scalar_operand_is_pointer(idx, &facts) {
                        errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: VccTypeClass::Ptr,
                            },
                            "list index expects scalar",
                        ));
                    }
                }
                _ => {}
            }

            update_list_operand_facts(inst, types, &mut facts);
        }
    }

    errors
}

fn list_operand_fact_from_mir_type(ty: &MirType) -> Option<ListOperandFact> {
    match vcc_type_from_mir(ty) {
        VccValueType::Ptr(info) => Some(ListOperandFact::Ptr(info.space)),
        VccValueType::Unknown | VccValueType::Uninit | VccValueType::StalePacketPtr => None,
        other => Some(ListOperandFact::NonPtr(other.class())),
    }
}

fn check_list_reg_operand(
    reg: VReg,
    facts: &HashMap<VReg, ListOperandFact>,
    func: &MirFunction,
    errors: &mut Vec<VccError>,
) {
    match facts.get(&reg).copied() {
        Some(ListOperandFact::Ptr(VccAddrSpace::Stack(slot))) => {
            if stack_slot_kind(func, slot).is_some_and(|kind| kind != StackSlotKind::ListBuffer) {
                errors.push(VccError::new(
                    VccErrorKind::PointerBounds,
                    "list expects ListBuffer stack slot",
                ));
            }
        }
        Some(ListOperandFact::Ptr(space)) => {
            errors.push(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "list expects pointer in [Stack], got {}",
                    list_operand_space_name(space)
                ),
            ));
        }
        Some(ListOperandFact::NonPtr(actual)) => {
            errors.push(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual,
                },
                "list expects pointer value",
            ));
        }
        None => {}
    }
}

fn stack_slot_kind(func: &MirFunction, slot: StackSlotId) -> Option<StackSlotKind> {
    func.stack_slots
        .iter()
        .find(|stack_slot| stack_slot.id == slot)
        .map(|stack_slot| stack_slot.kind)
}

fn list_operand_space_name(space: VccAddrSpace) -> &'static str {
    match space {
        VccAddrSpace::Stack(_) => "Stack",
        VccAddrSpace::MapValue => "Map",
        VccAddrSpace::Packet => "Packet",
        VccAddrSpace::Context => "Context",
        VccAddrSpace::RingBuf => "RingBuf",
        VccAddrSpace::Kernel => "Kernel",
        VccAddrSpace::KernelBtf => "KernelBtf",
        VccAddrSpace::User => "User",
        VccAddrSpace::Unknown => "Unknown",
    }
}

fn list_scalar_operand_is_pointer(
    value: &MirValue,
    facts: &HashMap<VReg, ListOperandFact>,
) -> bool {
    match value {
        MirValue::VReg(reg) => matches!(facts.get(reg), Some(ListOperandFact::Ptr(_))),
        MirValue::StackSlot(_) => true,
        MirValue::Const(_) => false,
    }
}

fn update_list_operand_facts(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    facts: &mut HashMap<VReg, ListOperandFact>,
) {
    let Some(dst) = inst.def() else {
        return;
    };

    let fact = types
        .get(&dst)
        .and_then(list_operand_fact_from_mir_type)
        .or_else(|| match inst {
            MirInst::Copy { src, .. } => list_operand_fact_from_value(src, facts),
            MirInst::ListNew { buffer, .. } => {
                Some(ListOperandFact::Ptr(VccAddrSpace::Stack(*buffer)))
            }
            MirInst::MapLookup { .. } | MirInst::MapLookupDynamic { .. } => {
                Some(ListOperandFact::Ptr(VccAddrSpace::MapValue))
            }
            MirInst::LoadGlobal { ty, .. }
            | MirInst::Load { ty, .. }
            | MirInst::LoadSlot { ty, .. } => list_operand_fact_from_mir_type(ty),
            MirInst::CallHelper { helper, .. } => list_operand_fact_from_helper_return(*helper),
            MirInst::CallKfunc { kfunc, .. } => list_operand_fact_from_kfunc_return(kfunc),
            MirInst::Phi { args, .. } => {
                let mut merged = None;
                for (_, reg) in args {
                    let Some(fact) = facts.get(reg).copied() else {
                        return None;
                    };
                    match merged {
                        None => merged = Some(fact),
                        Some(existing) if existing == fact => {}
                        Some(_) => return None,
                    }
                }
                merged
            }
            MirInst::BinOp { .. }
            | MirInst::UnaryOp { .. }
            | MirInst::LoadMapFd { .. }
            | MirInst::StrCmp { .. }
            | MirInst::StopTimer { .. }
            | MirInst::ListLen { .. }
            | MirInst::ListGet { .. } => Some(ListOperandFact::NonPtr(VccTypeClass::Scalar)),
            _ => None,
        });

    if let Some(fact) = fact {
        facts.insert(dst, fact);
    } else {
        facts.remove(&dst);
    }
}

fn list_operand_fact_from_helper_return(helper_id: u32) -> Option<ListOperandFact> {
    let helper = BpfHelper::from_u32(helper_id);
    let sig = HelperSignature::for_id(helper_id)?;
    match sig.ret_kind {
        HelperRetKind::Void | HelperRetKind::Scalar => {
            Some(ListOperandFact::NonPtr(VccTypeClass::Scalar))
        }
        HelperRetKind::PointerNonNull => {
            let space = match helper {
                Some(BpfHelper::GetLocalStorage) => VccAddrSpace::MapValue,
                _ => VccAddrSpace::Kernel,
            };
            Some(ListOperandFact::Ptr(space))
        }
        HelperRetKind::PointerMaybeNull => {
            let space = match helper {
                Some(BpfHelper::RingbufReserve) => VccAddrSpace::RingBuf,
                Some(
                    BpfHelper::KptrXchg
                    | BpfHelper::SkFullsock
                    | BpfHelper::TcpSock
                    | BpfHelper::SkcToTcp6Sock
                    | BpfHelper::SkcToTcpTimewaitSock
                    | BpfHelper::SkcToTcpRequestSock
                    | BpfHelper::SkcToUdp6Sock
                    | BpfHelper::SockFromFile
                    | BpfHelper::TaskPtRegs
                    | BpfHelper::SkcToTcpSock
                    | BpfHelper::PerCpuPtr
                    | BpfHelper::GetListenerSock,
                ) => VccAddrSpace::Kernel,
                Some(helper) if helper_acquire_ref_kind(helper).is_some() => VccAddrSpace::Kernel,
                _ => VccAddrSpace::MapValue,
            };
            Some(ListOperandFact::Ptr(space))
        }
    }
}

fn list_operand_fact_from_kfunc_return(kfunc: &str) -> Option<ListOperandFact> {
    let sig = KfuncSignature::for_name_or_kernel_btf(kfunc)?;
    match sig.ret_kind {
        KfuncRetKind::Scalar | KfuncRetKind::Void => {
            Some(ListOperandFact::NonPtr(VccTypeClass::Scalar))
        }
        KfuncRetKind::PointerMaybeNull => Some(ListOperandFact::Ptr(VccAddrSpace::Kernel)),
    }
}

fn list_operand_fact_from_value(
    value: &MirValue,
    facts: &HashMap<VReg, ListOperandFact>,
) -> Option<ListOperandFact> {
    match value {
        MirValue::VReg(reg) => facts.get(reg).copied(),
        MirValue::StackSlot(slot) => Some(ListOperandFact::Ptr(VccAddrSpace::Stack(*slot))),
        MirValue::Const(_) => Some(ListOperandFact::NonPtr(VccTypeClass::Scalar)),
    }
}

#[cfg(test)]
mod tests;
