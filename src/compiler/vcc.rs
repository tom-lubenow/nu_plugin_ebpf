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

use std::collections::{HashMap, VecDeque};

use crate::compiler::cfg::CFG;
use crate::compiler::instruction::{
    BpfHelper, HelperArgKind, HelperRetKind, HelperSignature, KfuncArgKind, KfuncIterFamily,
    KfuncIterLifecycleOp, KfuncRefKind, KfuncRetKind, KfuncSignature, KfuncUnknownIterLifecycle,
    helper_acquire_ref_kind, helper_pointer_arg_ref_kind, helper_release_ref_kind,
    kfunc_acquire_ref_kind,
    kfunc_pointer_arg_allows_const_zero as kfunc_pointer_arg_allows_const_zero_shared,
    kfunc_pointer_arg_fixed_size as kfunc_pointer_arg_fixed_size_shared,
    kfunc_pointer_arg_min_access_size as kfunc_pointer_arg_min_access_size_shared,
    kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
    kfunc_pointer_arg_requires_stack as kfunc_pointer_arg_requires_stack_shared,
    kfunc_pointer_arg_requires_stack_or_map as kfunc_pointer_arg_requires_stack_or_map_shared,
    kfunc_pointer_arg_requires_stack_slot_base as kfunc_pointer_arg_requires_stack_slot_base_shared,
    kfunc_pointer_arg_requires_user as kfunc_pointer_arg_requires_user_shared,
    kfunc_pointer_arg_size_from_scalar as kfunc_pointer_arg_size_from_scalar_shared,
    kfunc_release_ref_arg_index, kfunc_release_ref_kind,
    kfunc_scalar_arg_requires_known_const as kfunc_scalar_arg_requires_known_const_shared,
    kfunc_scalar_arg_requires_positive as kfunc_scalar_arg_requires_positive_shared,
    kfunc_semantics, kfunc_unknown_iter_lifecycle as kfunc_unknown_iter_lifecycle_shared,
};
use crate::compiler::mir::{
    AddressSpace, BinOpKind, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME,
    MapKind, MirFunction, MirInst, MirType, MirValue, RINGBUF_MAP_NAME, STRING_COUNTER_MAP_NAME,
    StackSlotId, StackSlotKind, StringAppendType, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, UnaryOpKind,
    VReg,
};
use crate::compiler::passes::{ListLowering, MirPass};

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
    Context,
    RingBuf,
    Kernel,
    User,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VccBounds {
    pub min: i64,
    pub max: i64,
    pub limit: i64,
}

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
pub struct VccPointerInfo {
    pub space: VccAddrSpace,
    pub nullability: VccNullability,
    pub bounds: Option<VccBounds>,
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
    Bool,
    Scalar { range: Option<VccRange> },
    Ptr(VccPointerInfo),
}

impl VccValueType {
    fn class(&self) -> VccTypeClass {
        match self {
            VccValueType::Uninit => VccTypeClass::Uninit,
            VccValueType::Unknown => VccTypeClass::Unknown,
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
    },
    AssertScalar {
        value: VccValue,
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
    AssertKnownConst {
        value: VccValue,
        message: String,
    },
    AssertPtrAccess {
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
    ResSpinLockAcquire,
    ResSpinLockRelease,
    ResSpinLockIrqsaveAcquire {
        flags: VccReg,
    },
    ResSpinLockIrqsaveRelease {
        flags: VccReg,
    },
    IterTaskVmaNew {
        iter: VccReg,
    },
    IterTaskVmaNext {
        iter: VccReg,
    },
    IterTaskVmaDestroy {
        iter: VccReg,
    },
    IterTaskNew {
        iter: VccReg,
    },
    IterTaskNext {
        iter: VccReg,
    },
    IterTaskDestroy {
        iter: VccReg,
    },
    IterScxDsqNew {
        iter: VccReg,
    },
    IterScxDsqNext {
        iter: VccReg,
    },
    IterScxDsqDestroy {
        iter: VccReg,
    },
    IterScxDsqMove {
        iter: VccReg,
    },
    IterScxDsqMoveSetSlice {
        iter: VccReg,
    },
    IterScxDsqMoveSetVtime {
        iter: VccReg,
    },
    IterScxDsqMoveVtime {
        iter: VccReg,
    },
    IterNumNew {
        iter: VccReg,
    },
    IterNumNext {
        iter: VccReg,
    },
    IterNumDestroy {
        iter: VccReg,
    },
    IterBitsNew {
        iter: VccReg,
    },
    IterBitsNext {
        iter: VccReg,
    },
    IterBitsDestroy {
        iter: VccReg,
    },
    IterCssNew {
        iter: VccReg,
    },
    IterCssNext {
        iter: VccReg,
    },
    IterCssDestroy {
        iter: VccReg,
    },
    IterCssTaskNew {
        iter: VccReg,
    },
    IterCssTaskNext {
        iter: VccReg,
    },
    IterCssTaskDestroy {
        iter: VccReg,
    },
    IterDmabufNew {
        iter: VccReg,
    },
    IterDmabufNext {
        iter: VccReg,
    },
    IterDmabufDestroy {
        iter: VccReg,
    },
    IterKmemCacheNew {
        iter: VccReg,
    },
    IterKmemCacheNext {
        iter: VccReg,
    },
    IterKmemCacheDestroy {
        iter: VccReg,
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
}

include!("vcc/verifier.rs");
include!("vcc/state.rs");
pub fn verify_mir(func: &MirFunction, types: &HashMap<VReg, MirType>) -> Result<(), Vec<VccError>> {
    if func.param_count > 5 {
        return Err(vec![VccError::new(
            VccErrorKind::UnsupportedInstruction,
            format!(
                "BPF subfunctions support at most 5 arguments, got {}",
                func.param_count
            ),
        )]);
    }
    let early_errors = check_generic_map_layout_constraints(func, types);
    if !early_errors.is_empty() {
        return Err(early_errors);
    }
    let list_max = collect_list_max(func);
    let mut verify_func = func.clone();
    let cfg = CFG::build(&verify_func);
    let list_lowering = ListLowering;
    let _ = list_lowering.run(&mut verify_func, &cfg);

    let mut lowerer = VccLowerer::new(&verify_func, types, list_max);
    let vcc_func = match lowerer.lower() {
        Ok(vcc) => vcc,
        Err(err) => return Err(vec![err]),
    };
    let seed = lowerer.seed_types();
    VccVerifier::default().verify_function_with_seed(&vcc_func, seed)
}

include!("vcc/lower.rs");
fn record_field_size(ty: &MirType) -> usize {
    match ty {
        MirType::I64 | MirType::U64 => 8,
        MirType::I32 | MirType::U32 => 8,
        MirType::I16 | MirType::U16 => 8,
        MirType::I8 | MirType::U8 | MirType::Bool => 8,
        MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) && *len == 16 => 16,
        MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => (len + 7) & !7,
        _ => 8,
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
            let bounds = if matches!(address_space, AddressSpace::Map)
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
                    AddressSpace::Stack => VccAddrSpace::Unknown,
                    AddressSpace::Kernel => VccAddrSpace::Kernel,
                    AddressSpace::User => VccAddrSpace::User,
                    AddressSpace::Map => VccAddrSpace::MapValue,
                },
                nullability: match address_space {
                    AddressSpace::Stack => VccNullability::NonNull,
                    AddressSpace::Map | AddressSpace::Kernel | AddressSpace::User => {
                        VccNullability::MaybeNull
                    }
                },
                bounds,
                ringbuf_ref: None,
                kfunc_ref: None,
            })
        }
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
        BinOpKind::Shr => VccBinOp::Shr,
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

#[cfg(test)]
mod tests;
