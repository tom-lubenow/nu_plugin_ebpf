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
use crate::compiler::instruction::{BpfHelper, HelperArgKind, HelperRetKind, HelperSignature};
use crate::compiler::mir::{
    AddressSpace, BinOpKind, MirFunction, MirInst, MirType, MirValue, STRING_COUNTER_MAP_NAME,
    StackSlotId, StackSlotKind, StringAppendType, UnaryOpKind, VReg,
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

impl VccVerifier {
    const MAX_STATE_UPDATES_PER_BLOCK: usize = 64;

    pub fn verify_function(self, func: &VccFunction) -> Result<(), Vec<VccError>> {
        self.verify_function_with_seed(func, HashMap::new())
    }

    pub fn verify_function_with_seed(
        mut self,
        func: &VccFunction,
        seed: HashMap<VccReg, VccValueType>,
    ) -> Result<(), Vec<VccError>> {
        let mut in_states: HashMap<VccBlockId, VccState> = HashMap::new();
        let mut worklist: VecDeque<VccBlockId> = VecDeque::new();
        let mut update_counts: HashMap<VccBlockId, usize> = HashMap::new();

        in_states.insert(func.entry, VccState::with_seed(seed));
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(mut state) = in_states.get(&block_id).cloned() else {
                continue;
            };
            let block = func.block(block_id);
            for inst in &block.instructions {
                self.verify_inst(inst, &mut state);
            }
            self.verify_terminator(&block.terminator, &mut state);

            match &block.terminator {
                VccTerminator::Jump { target } => {
                    self.propagate_state(
                        *target,
                        &state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                }
                VccTerminator::Branch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    let (true_state, false_state) = self.refine_branch_states(*cond, &state);
                    self.propagate_state(
                        *if_true,
                        &true_state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                    self.propagate_state(
                        *if_false,
                        &false_state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                }
                VccTerminator::Return { .. } => {}
            }
        }

        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    fn refine_branch_states(&self, cond: VccValue, state: &VccState) -> (VccState, VccState) {
        let mut true_state = state.clone();
        let mut false_state = state.clone();
        if let VccValue::Reg(cond_reg) = cond {
            if let Some(refinement) = state.cond_refinement(cond_reg) {
                let true_non_null = refinement.true_means_non_null;
                self.refine_ptr_nullability(&mut true_state, refinement, true_non_null);
                self.refine_ptr_nullability(&mut false_state, refinement, !true_non_null);
            }
        }
        (true_state, false_state)
    }

    fn refine_ptr_nullability(
        &self,
        state: &mut VccState,
        refinement: VccCondRefinement,
        non_null: bool,
    ) {
        let Ok(VccValueType::Ptr(mut ptr)) = state.reg_type(refinement.ptr_reg) else {
            return;
        };
        ptr.nullability = if non_null {
            VccNullability::NonNull
        } else {
            VccNullability::Null
        };
        if !non_null {
            if let Some(ref_id) = refinement.ringbuf_ref {
                state.set_live_ringbuf_ref(ref_id, false);
            }
        }
        state.set_reg(refinement.ptr_reg, VccValueType::Ptr(ptr));
    }

    fn propagate_state(
        &mut self,
        block: VccBlockId,
        state: &VccState,
        in_states: &mut HashMap<VccBlockId, VccState>,
        worklist: &mut VecDeque<VccBlockId>,
        update_counts: &mut HashMap<VccBlockId, usize>,
    ) {
        let existing = in_states.get(&block).cloned();
        let mut next_state = match existing.as_ref() {
            None => state.clone(),
            Some(existing) => existing.merge_with(state),
        };

        let updates = update_counts.get(&block).copied().unwrap_or(0);
        if updates >= Self::MAX_STATE_UPDATES_PER_BLOCK {
            next_state = next_state.widened();
        }

        let changed = match existing {
            None => true,
            Some(existing) => existing != next_state,
        };

        if changed {
            in_states.insert(block, next_state);
            *update_counts.entry(block).or_insert(0) += 1;
            worklist.push_back(block);
        }
    }

    fn verify_inst(&mut self, inst: &VccInst, state: &mut VccState) {
        match inst {
            VccInst::Const { dst, value } => {
                state.set_reg(
                    *dst,
                    VccValueType::Scalar {
                        range: Some(VccRange {
                            min: *value,
                            max: *value,
                        }),
                    },
                );
            }
            VccInst::Copy { dst, src } => match state.value_type(*src) {
                Ok(ty) => state.set_reg(*dst, ty),
                Err(err) => self.errors.push(err),
            },
            VccInst::Assume { dst, ty } => {
                state.set_reg(*dst, *ty);
            }
            VccInst::AssertScalar { value } => match state.value_type(*value) {
                Ok(ty) => {
                    if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: ty.class(),
                            },
                            "expected scalar value",
                        ));
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccInst::StackAddr { dst, slot, size } => {
                let bounds = if *size > 0 {
                    Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: size.saturating_sub(1),
                    })
                } else {
                    None
                };
                state.set_reg(
                    *dst,
                    VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::Stack(*slot),
                        nullability: VccNullability::NonNull,
                        bounds,
                        ringbuf_ref: None,
                    }),
                );
            }
            VccInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_ty = match state.value_type(*lhs) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                let rhs_ty = match state.value_type(*rhs) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };

                match op {
                    VccBinOp::Eq | VccBinOp::Ne => {
                        let ptr_cmp = self.ptr_null_comparison(*lhs, lhs_ty, *rhs, rhs_ty);
                        let lhs_is_ptr = matches!(lhs_ty, VccValueType::Ptr(_));
                        let rhs_is_ptr = matches!(rhs_ty, VccValueType::Ptr(_));
                        if lhs_is_ptr || rhs_is_ptr {
                            match (lhs_ty, rhs_ty) {
                                (VccValueType::Ptr(lp), VccValueType::Ptr(rp)) => {
                                    if lp.space != rp.space
                                        && lp.space != VccAddrSpace::Unknown
                                        && rp.space != VccAddrSpace::Unknown
                                    {
                                        self.errors.push(VccError::new(
                                            VccErrorKind::TypeMismatch {
                                                expected: VccTypeClass::Ptr,
                                                actual: VccTypeClass::Ptr,
                                            },
                                            "pointer comparison requires matching address space",
                                        ));
                                        return;
                                    }
                                }
                                (VccValueType::Ptr(_), other) | (other, VccValueType::Ptr(_)) => {
                                    if !self.is_null_scalar(*lhs, lhs_ty)
                                        && !self.is_null_scalar(*rhs, rhs_ty)
                                        && other.class() != VccTypeClass::Ptr
                                    {
                                        self.errors.push(VccError::new(
                                            VccErrorKind::TypeMismatch {
                                                expected: VccTypeClass::Scalar,
                                                actual: other.class(),
                                            },
                                            "pointer comparison only supports null scalar",
                                        ));
                                        return;
                                    }
                                }
                                _ => {}
                            }
                        } else if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: lhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        } else if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: rhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        state.set_reg(*dst, VccValueType::Bool);
                        if let Some((ptr_reg, ringbuf_ref)) = ptr_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement {
                                    ptr_reg,
                                    ringbuf_ref,
                                    true_means_non_null: matches!(op, VccBinOp::Ne),
                                },
                            );
                        }
                    }
                    VccBinOp::Lt | VccBinOp::Le | VccBinOp::Gt | VccBinOp::Ge => {
                        if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: lhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: rhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        state.set_reg(*dst, VccValueType::Bool);
                    }
                    _ => {
                        if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "binop requires scalar operands (pointer used)",
                            ));
                            return;
                        }
                        if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "binop requires scalar operands (pointer used)",
                            ));
                            return;
                        }
                        let range = state.binop_range(*op, lhs_ty, rhs_ty);
                        state.set_reg(*dst, VccValueType::Scalar { range });
                    }
                }
            }
            VccInst::PtrAdd { dst, base, offset } => {
                let base_ty = state.reg_type(*base);
                let base_ptr = match base_ty {
                    Ok(VccValueType::Ptr(ptr)) => ptr,
                    Ok(other) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            "ptr_add base must be a pointer",
                        ));
                        return;
                    }
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };

                let offset_ty = match state.value_type(*offset) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if offset_ty.class() != VccTypeClass::Scalar
                    && offset_ty.class() != VccTypeClass::Bool
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerArithmetic,
                        "ptr_add offset must be scalar",
                    ));
                    return;
                }

                let offset_range = state.value_range(*offset, offset_ty);
                let bounds = match (base_ptr.space, base_ptr.bounds, offset_range) {
                    (VccAddrSpace::Stack(_), Some(bounds), Some(range)) => {
                        bounds.shifted(range).map(Some).unwrap_or_else(|| {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "stack pointer arithmetic out of bounds",
                            ));
                            None
                        })
                    }
                    (VccAddrSpace::Stack(_), Some(_), None) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnknownOffset,
                            "stack pointer arithmetic requires bounded scalar offset",
                        ));
                        None
                    }
                    _ => base_ptr.bounds,
                };

                state.set_reg(
                    *dst,
                    VccValueType::Ptr(VccPointerInfo {
                        space: base_ptr.space,
                        nullability: base_ptr.nullability,
                        bounds,
                        ringbuf_ref: base_ptr.ringbuf_ref,
                    }),
                );
            }
            VccInst::Load {
                dst,
                ptr,
                offset,
                size,
            } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ptr_ty {
                    VccValueType::Ptr(ptr_info) => {
                        if let Err(err) = self.require_non_null_ptr(ptr_info, "load") {
                            self.errors.push(err);
                            return;
                        }
                        if let (VccAddrSpace::Stack(_), Some(bounds)) =
                            (ptr_info.space, ptr_info.bounds)
                        {
                            let size = *size as i64;
                            if size <= 0 {
                                self.errors.push(VccError::new(
                                    VccErrorKind::InvalidLoadStore,
                                    "load size must be positive",
                                ));
                                return;
                            }
                            if bounds.shifted_with_size(*offset, size).is_none() {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "stack load offset out of bounds",
                                ));
                            }
                        }
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("load requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                }
                state.set_reg(*dst, VccValueType::Scalar { range: None });
            }
            VccInst::Store {
                ptr,
                offset,
                src,
                size,
            } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ptr_ty {
                    VccValueType::Ptr(ptr_info) => {
                        if let Err(err) = self.require_non_null_ptr(ptr_info, "store") {
                            self.errors.push(err);
                            return;
                        }
                        if let (VccAddrSpace::Stack(_), Some(bounds)) =
                            (ptr_info.space, ptr_info.bounds)
                        {
                            let size = *size as i64;
                            if size <= 0 {
                                self.errors.push(VccError::new(
                                    VccErrorKind::InvalidLoadStore,
                                    "store size must be positive",
                                ));
                                return;
                            }
                            if bounds.shifted_with_size(*offset, size).is_none() {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "stack store offset out of bounds",
                                ));
                            }
                        }
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("store requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                }

                if let Err(err) = state.value_type(*src) {
                    self.errors.push(err);
                }
            }
            VccInst::Phi { dst, args } => {
                let mut merged: Option<VccValueType> = None;
                for (_, reg) in args {
                    match state.reg_type(*reg) {
                        Ok(ty) => {
                            merged = Some(match merged {
                                None => ty,
                                Some(existing) => state.merge_types(existing, ty),
                            });
                        }
                        Err(err) => self.errors.push(err),
                    }
                }
                let ty = merged.unwrap_or(VccValueType::Unknown);
                state.set_reg(*dst, ty);
            }
            VccInst::RingbufAcquire { id } => {
                state.set_live_ringbuf_ref(*id, true);
            }
            VccInst::RingbufRelease { ptr } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::RingBuf => {
                        if let Err(err) = self.require_non_null_ptr(info, "ringbuf release") {
                            self.errors.push(err);
                            return;
                        }
                        if let Some(ref_id) = info.ringbuf_ref {
                            if state.is_live_ringbuf_ref(ref_id) {
                                state.invalidate_ringbuf_ref(ref_id);
                            } else {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "ringbuf record already released",
                                ));
                            }
                        } else {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "ringbuf record pointer is not tracked",
                            ));
                        }
                    }
                    VccValueType::Ptr(_) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            "ringbuf release requires ringbuf record pointer",
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            "ringbuf release requires pointer operand",
                        ));
                    }
                }
            }
        }
    }

    fn verify_terminator(&mut self, term: &VccTerminator, state: &mut VccState) {
        match term {
            VccTerminator::Jump { .. } => {}
            VccTerminator::Branch { cond, .. } => match state.value_type(*cond) {
                Ok(ty) => {
                    if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Bool,
                                actual: ty.class(),
                            },
                            "branch condition must be scalar/bool",
                        ));
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccTerminator::Return { value } => {
                if let Some(value) = value {
                    if let Err(err) = state.value_type(*value) {
                        self.errors.push(err);
                    }
                }
                if state.has_live_ringbuf_refs() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
            }
        }
    }

    fn ptr_null_comparison(
        &self,
        lhs: VccValue,
        lhs_ty: VccValueType,
        rhs: VccValue,
        rhs_ty: VccValueType,
    ) -> Option<(VccReg, Option<VccReg>)> {
        match (lhs, lhs_ty, rhs, rhs_ty) {
            (VccValue::Reg(ptr_reg), VccValueType::Ptr(ptr), _, other)
                if self.is_null_scalar(rhs, other) =>
            {
                Some((ptr_reg, ptr.ringbuf_ref))
            }
            (_, other, VccValue::Reg(ptr_reg), VccValueType::Ptr(ptr))
                if self.is_null_scalar(lhs, other) =>
            {
                Some((ptr_reg, ptr.ringbuf_ref))
            }
            _ => None,
        }
    }

    fn require_non_null_ptr(&self, ptr: VccPointerInfo, op: &str) -> Result<(), VccError> {
        match ptr.nullability {
            VccNullability::NonNull => Ok(()),
            VccNullability::Null => Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!("{op} uses null pointer"),
            )),
            VccNullability::MaybeNull => Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!("{op} may dereference null pointer (add a null check)"),
            )),
        }
    }

    fn is_null_scalar(&self, value: VccValue, ty: VccValueType) -> bool {
        (match ty {
            VccValueType::Scalar { range } => matches!(range, Some(VccRange { min: 0, max: 0 })),
            VccValueType::Bool => false,
            VccValueType::Ptr(_) | VccValueType::Unknown | VccValueType::Uninit => false,
        }) || matches!(value, VccValue::Imm(0))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VccState {
    reg_types: HashMap<VccReg, VccValueType>,
    live_ringbuf_refs: HashMap<VccReg, bool>,
    cond_refinements: HashMap<VccReg, VccCondRefinement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VccCondRefinement {
    ptr_reg: VccReg,
    ringbuf_ref: Option<VccReg>,
    true_means_non_null: bool,
}

impl VccState {
    fn with_seed(seed: HashMap<VccReg, VccValueType>) -> Self {
        Self {
            reg_types: seed,
            live_ringbuf_refs: HashMap::new(),
            cond_refinements: HashMap::new(),
        }
    }

    fn set_reg(&mut self, reg: VccReg, ty: VccValueType) {
        self.reg_types.insert(reg, ty);
        self.cond_refinements.remove(&reg);
    }

    fn set_live_ringbuf_ref(&mut self, id: VccReg, live: bool) {
        self.live_ringbuf_refs.insert(id, live);
    }

    fn set_cond_refinement(&mut self, reg: VccReg, refinement: VccCondRefinement) {
        self.cond_refinements.insert(reg, refinement);
    }

    fn cond_refinement(&self, reg: VccReg) -> Option<VccCondRefinement> {
        self.cond_refinements.get(&reg).copied()
    }

    fn is_live_ringbuf_ref(&self, id: VccReg) -> bool {
        self.live_ringbuf_refs.get(&id).copied().unwrap_or(false)
    }

    fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs.values().copied().any(std::convert::identity)
    }

    fn invalidate_ringbuf_ref(&mut self, id: VccReg) {
        self.set_live_ringbuf_ref(id, false);
        for ty in self.reg_types.values_mut() {
            let matches_ref = matches!(
                ty,
                VccValueType::Ptr(VccPointerInfo {
                    ringbuf_ref: Some(ref_id),
                    ..
                }) if *ref_id == id
            );
            if matches_ref {
                *ty = VccValueType::Unknown;
            }
        }
        self.cond_refinements
            .retain(|_, info| info.ringbuf_ref != Some(id));
    }

    fn merge_with(&self, other: &VccState) -> VccState {
        let mut merged = self.reg_types.clone();
        for (reg, rhs) in &other.reg_types {
            match merged.get(reg).copied() {
                Some(lhs) => {
                    merged.insert(*reg, self.merge_types(lhs, *rhs));
                }
                None => {
                    merged.insert(*reg, *rhs);
                }
            }
        }
        let mut live_ringbuf_refs = self.live_ringbuf_refs.clone();
        for (id, live) in &other.live_ringbuf_refs {
            let current = live_ringbuf_refs.get(id).copied().unwrap_or(false);
            live_ringbuf_refs.insert(*id, current || *live);
        }
        let mut cond_refinements = HashMap::new();
        for (reg, left) in &self.cond_refinements {
            if let Some(right) = other.cond_refinements.get(reg) {
                if left == right {
                    cond_refinements.insert(*reg, *left);
                }
            }
        }
        VccState {
            reg_types: merged,
            live_ringbuf_refs,
            cond_refinements,
        }
    }

    fn widened(&self) -> VccState {
        let mut widened = HashMap::new();
        for (reg, ty) in &self.reg_types {
            let widened_ty = match ty {
                VccValueType::Scalar { .. } => VccValueType::Scalar { range: None },
                VccValueType::Ptr(ptr) => VccValueType::Ptr(VccPointerInfo {
                    space: ptr.space,
                    nullability: VccNullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                }),
                VccValueType::Bool => VccValueType::Bool,
                VccValueType::Unknown => VccValueType::Unknown,
                VccValueType::Uninit => VccValueType::Uninit,
            };
            widened.insert(*reg, widened_ty);
        }
        VccState {
            reg_types: widened,
            live_ringbuf_refs: self.live_ringbuf_refs.clone(),
            cond_refinements: HashMap::new(),
        }
    }

    fn reg_type(&self, reg: VccReg) -> Result<VccValueType, VccError> {
        match self.reg_types.get(&reg).copied() {
            Some(VccValueType::Uninit) | None => Err(VccError::new(
                VccErrorKind::UseOfUninitializedReg(reg),
                format!("use of uninitialized reg {:?}", reg),
            )),
            Some(ty) => Ok(ty),
        }
    }

    fn value_type(&self, value: VccValue) -> Result<VccValueType, VccError> {
        match value {
            VccValue::Imm(v) => Ok(VccValueType::Scalar {
                range: Some(VccRange { min: v, max: v }),
            }),
            VccValue::Reg(reg) => self.reg_type(reg),
        }
    }

    fn value_range(&self, value: VccValue, ty: VccValueType) -> Option<VccRange> {
        match value {
            VccValue::Imm(v) => Some(VccRange { min: v, max: v }),
            VccValue::Reg(_) => match ty {
                VccValueType::Scalar { range } => range,
                VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
                _ => None,
            },
        }
    }

    fn binop_range(&self, op: VccBinOp, lhs: VccValueType, rhs: VccValueType) -> Option<VccRange> {
        let lhs_range = match lhs {
            VccValueType::Scalar { range } => range,
            VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
            _ => None,
        }?;
        let rhs_range = match rhs {
            VccValueType::Scalar { range } => range,
            VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
            _ => None,
        }?;

        match op {
            VccBinOp::Add => Some(lhs_range.add(rhs_range)),
            VccBinOp::Sub => Some(lhs_range.sub(rhs_range)),
            VccBinOp::Mul => Some(self.mul_range(lhs_range, rhs_range)),
            _ => None,
        }
    }

    fn mul_range(&self, lhs: VccRange, rhs: VccRange) -> VccRange {
        let candidates = [
            lhs.min.saturating_mul(rhs.min),
            lhs.min.saturating_mul(rhs.max),
            lhs.max.saturating_mul(rhs.min),
            lhs.max.saturating_mul(rhs.max),
        ];
        let mut min = candidates[0];
        let mut max = candidates[0];
        for value in candidates.iter().copied() {
            min = min.min(value);
            max = max.max(value);
        }
        VccRange { min, max }
    }

    fn merge_types(&self, lhs: VccValueType, rhs: VccValueType) -> VccValueType {
        match (lhs, rhs) {
            (VccValueType::Scalar { range: l }, VccValueType::Scalar { range: r }) => {
                VccValueType::Scalar {
                    range: match (l, r) {
                        (Some(lr), Some(rr)) => Some(VccRange {
                            min: lr.min.min(rr.min),
                            max: lr.max.max(rr.max),
                        }),
                        _ => None,
                    },
                }
            }
            (VccValueType::Ptr(lp), VccValueType::Ptr(rp)) if lp.space == rp.space => {
                let bounds = match (lp.bounds, rp.bounds) {
                    (Some(l), Some(r)) if l.limit == r.limit => Some(VccBounds {
                        min: l.min.min(r.min),
                        max: l.max.max(r.max),
                        limit: l.limit,
                    }),
                    _ => None,
                };
                let ringbuf_ref = match (lp.ringbuf_ref, rp.ringbuf_ref) {
                    (Some(a), Some(b)) if a == b => Some(a),
                    _ => None,
                };
                let nullability = Self::join_nullability(lp.nullability, rp.nullability);
                VccValueType::Ptr(VccPointerInfo {
                    space: lp.space,
                    nullability,
                    bounds,
                    ringbuf_ref,
                })
            }
            (left, right) if left == right => left,
            _ => VccValueType::Unknown,
        }
    }

    fn join_nullability(lhs: VccNullability, rhs: VccNullability) -> VccNullability {
        match (lhs, rhs) {
            (VccNullability::NonNull, VccNullability::NonNull) => VccNullability::NonNull,
            (VccNullability::Null, VccNullability::Null) => VccNullability::Null,
            _ => VccNullability::MaybeNull,
        }
    }
}

pub fn verify_mir(func: &MirFunction, types: &HashMap<VReg, MirType>) -> Result<(), Vec<VccError>> {
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

struct VccLowerer<'a> {
    func: &'a MirFunction,
    types: &'a HashMap<VReg, MirType>,
    slot_sizes: HashMap<StackSlotId, usize>,
    slot_kinds: HashMap<StackSlotId, StackSlotKind>,
    list_max: HashMap<StackSlotId, usize>,
    ptr_regs: HashMap<VccReg, VccPointerInfo>,
    next_temp: u32,
}

const STRING_APPEND_COPY_CAP: usize = 64;
const MAX_INT_STRING_LEN: usize = 20;

impl<'a> VccLowerer<'a> {
    fn new(
        func: &'a MirFunction,
        types: &'a HashMap<VReg, MirType>,
        list_max: HashMap<StackSlotId, usize>,
    ) -> Self {
        let mut slot_sizes = HashMap::new();
        let mut slot_kinds = HashMap::new();
        for slot in &func.stack_slots {
            slot_sizes.insert(slot.id, slot.size);
            slot_kinds.insert(slot.id, slot.kind);
        }
        let mut ptr_regs = HashMap::new();
        for (vreg, ty) in types {
            if let VccValueType::Ptr(info) = vcc_type_from_mir(ty) {
                ptr_regs.insert(VccReg(vreg.0), info);
            }
        }
        Self {
            func,
            types,
            slot_sizes,
            slot_kinds,
            list_max,
            ptr_regs,
            next_temp: func.vreg_count.max(func.param_count as u32),
        }
    }

    fn seed_types(&self) -> HashMap<VccReg, VccValueType> {
        let mut seed = HashMap::new();
        for (vreg, ty) in self.types {
            seed.insert(VccReg(vreg.0), vcc_type_from_mir(ty));
        }
        seed
    }

    fn lower(&mut self) -> Result<VccFunction, VccError> {
        let max_block = self.func.blocks.iter().map(|b| b.id.0).max().unwrap_or(0) as usize;
        let mut blocks = Vec::with_capacity(max_block + 1);
        for i in 0..=max_block {
            blocks.push(VccBlock {
                id: VccBlockId(i as u32),
                instructions: Vec::new(),
                terminator: VccTerminator::Return { value: None },
            });
        }

        for block in &self.func.blocks {
            let mut insts = Vec::new();
            for inst in &block.instructions {
                self.lower_inst(inst, &mut insts)?;
            }
            let term = self.lower_terminator(&block.terminator, &mut insts)?;
            let idx = block.id.0 as usize;
            blocks[idx] = VccBlock {
                id: VccBlockId(block.id.0),
                instructions: insts,
                terminator: term,
            };
        }

        Ok(VccFunction {
            entry: VccBlockId(self.func.entry.0),
            blocks,
            reg_count: self.next_temp,
        })
    }

    fn lower_inst(&mut self, inst: &MirInst, out: &mut Vec<VccInst>) -> Result<(), VccError> {
        match inst {
            MirInst::Copy { dst, src } => {
                let dst_reg = VccReg(dst.0);
                match src {
                    MirValue::StackSlot(slot) => {
                        let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                        out.push(VccInst::StackAddr {
                            dst: dst_reg,
                            slot: *slot,
                            size,
                        });
                        self.ptr_regs.insert(
                            dst_reg,
                            VccPointerInfo {
                                space: VccAddrSpace::Stack(*slot),
                                nullability: VccNullability::NonNull,
                                bounds: stack_bounds(size),
                                ringbuf_ref: None,
                            },
                        );
                    }
                    _ => {
                        let vcc_src = self.lower_value(src, out);
                        out.push(VccInst::Copy {
                            dst: dst_reg,
                            src: vcc_src,
                        });
                        if let Some(ptr) = self.value_ptr_info(src) {
                            self.ptr_regs.insert(dst_reg, ptr);
                        }
                    }
                }
            }
            MirInst::Load {
                dst,
                ptr,
                offset,
                ty,
            } => {
                out.push(VccInst::Load {
                    dst: VccReg(dst.0),
                    ptr: VccReg(ptr.0),
                    offset: *offset as i64,
                    size: ty.size() as u8,
                });
                self.maybe_assume_list_len(*dst, *ptr, *offset, out);
                self.maybe_assume_type(*dst, ty, out);
            }
            MirInst::Store {
                ptr,
                offset,
                val,
                ty,
            } => {
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: VccReg(ptr.0),
                    offset: *offset as i64,
                    src: vcc_val,
                    size: ty.size() as u8,
                });
            }
            MirInst::LoadSlot {
                dst,
                slot,
                offset,
                ty,
            } => {
                let base = self.stack_addr_temp(*slot, out);
                out.push(VccInst::Load {
                    dst: VccReg(dst.0),
                    ptr: base,
                    offset: *offset as i64,
                    size: ty.size() as u8,
                });
                self.maybe_assume_list_len_slot(*dst, *slot, *offset, out);
                self.maybe_assume_type(*dst, ty, out);
            }
            MirInst::StoreSlot {
                slot,
                offset,
                val,
                ty,
            } => {
                let base = self.stack_addr_temp(*slot, out);
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: *offset as i64,
                    src: vcc_val,
                    size: ty.size() as u8,
                });
            }
            MirInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_ptr = self.value_ptr_info(lhs);
                let rhs_ptr = self.value_ptr_info(rhs);

                let vcc_op = to_vcc_binop(*op);
                let dst_reg = VccReg(dst.0);

                match op {
                    BinOpKind::Add | BinOpKind::Sub if lhs_ptr.is_some() ^ rhs_ptr.is_some() => {
                        let (base, offset_val, base_ptr) = if lhs_ptr.is_some() {
                            (lhs, rhs, lhs_ptr.unwrap())
                        } else {
                            (rhs, lhs, rhs_ptr.unwrap())
                        };

                        if matches!(op, BinOpKind::Sub) && lhs_ptr.is_none() {
                            return Err(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "numeric - pointer is not supported",
                            ));
                        }

                        let base_reg = self.base_ptr_reg(base, out);
                        let mut offset = self.lower_value(offset_val, out);
                        if matches!(op, BinOpKind::Sub) {
                            match offset {
                                VccValue::Imm(value) => {
                                    offset = VccValue::Imm(-value);
                                }
                                VccValue::Reg(reg) => {
                                    let tmp = self.temp_reg();
                                    out.push(VccInst::BinOp {
                                        dst: tmp,
                                        op: VccBinOp::Sub,
                                        lhs: VccValue::Imm(0),
                                        rhs: VccValue::Reg(reg),
                                    });
                                    offset = VccValue::Reg(tmp);
                                }
                            }
                        }
                        out.push(VccInst::PtrAdd {
                            dst: dst_reg,
                            base: base_reg,
                            offset,
                        });
                        self.ptr_regs.insert(dst_reg, base_ptr);
                    }
                    _ => {
                        let vcc_lhs = self.lower_value(lhs, out);
                        let vcc_rhs = self.lower_value(rhs, out);
                        out.push(VccInst::BinOp {
                            dst: dst_reg,
                            op: vcc_op,
                            lhs: vcc_lhs,
                            rhs: vcc_rhs,
                        });
                    }
                }
            }
            MirInst::UnaryOp { dst, op, src } => {
                let vcc_src = self.lower_value(src, out);
                out.push(VccInst::AssertScalar { value: vcc_src });
                let dst_ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                match op {
                    UnaryOpKind::Not => {
                        out.push(VccInst::Assume {
                            dst: VccReg(dst.0),
                            ty: VccValueType::Bool,
                        });
                    }
                    _ => {
                        out.push(VccInst::Assume {
                            dst: VccReg(dst.0),
                            ty: dst_ty,
                        });
                    }
                }
            }
            MirInst::Phi { dst, args } => {
                let vcc_args = args
                    .iter()
                    .map(|(block, vreg)| (VccBlockId(block.0), VccReg(vreg.0)))
                    .collect();
                out.push(VccInst::Phi {
                    dst: VccReg(dst.0),
                    args: vcc_args,
                });
            }
            MirInst::LoadCtxField { dst, slot, .. } => {
                if let Some(slot) = slot {
                    let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                    out.push(VccInst::StackAddr {
                        dst: VccReg(dst.0),
                        slot: *slot,
                        size,
                    });
                    if size > 0 {
                        out.push(VccInst::Store {
                            ptr: VccReg(dst.0),
                            offset: size.saturating_sub(1),
                            src: VccValue::Imm(0),
                            size: 1,
                        });
                    }
                    self.ptr_regs.insert(
                        VccReg(dst.0),
                        VccPointerInfo {
                            space: VccAddrSpace::Stack(*slot),
                            nullability: VccNullability::NonNull,
                            bounds: stack_bounds(size),
                            ringbuf_ref: None,
                        },
                    );
                } else {
                    let ty = self
                        .types
                        .get(dst)
                        .map(vcc_type_from_mir)
                        .unwrap_or(VccValueType::Unknown);
                    out.push(VccInst::Assume {
                        dst: VccReg(dst.0),
                        ty,
                    });
                    if let VccValueType::Ptr(info) = ty {
                        self.ptr_regs.insert(VccReg(dst.0), info);
                    }
                }
            }
            MirInst::StrCmp { dst, lhs, rhs, len } => {
                if *len > 0 {
                    let lhs_base = self.stack_addr_temp(*lhs, out);
                    let rhs_base = self.stack_addr_temp(*rhs, out);
                    let last = (*len as i64).saturating_sub(1);
                    let lhs_tmp = self.temp_reg();
                    let rhs_tmp = self.temp_reg();
                    out.push(VccInst::Load {
                        dst: lhs_tmp,
                        ptr: lhs_base,
                        offset: last,
                        size: 1,
                    });
                    out.push(VccInst::Load {
                        dst: rhs_tmp,
                        ptr: rhs_base,
                        offset: last,
                        size: 1,
                    });
                }
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty: VccValueType::Bool,
                });
            }
            MirInst::MapLookup { dst, map, key } => {
                self.verify_map_key(&map.name, *key, out)?;
                let mut ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                if let VccValueType::Ptr(mut info) = ty {
                    info.nullability = VccNullability::MaybeNull;
                    ty = VccValueType::Ptr(info);
                }
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
                if let VccValueType::Ptr(info) = ty {
                    self.ptr_regs.insert(VccReg(dst.0), info);
                }
            }
            MirInst::MapUpdate { map, key, val, .. } => {
                self.verify_map_key(&map.name, *key, out)?;
                self.verify_map_value(*val, out)?;
            }
            MirInst::MapDelete { map, key } => {
                self.verify_map_key(&map.name, *key, out)?;
            }
            MirInst::EmitEvent { data, size } => {
                if *size <= 8 {
                    self.assert_scalar_reg(*data, out);
                } else {
                    self.check_ptr_range(*data, *size, out)?;
                }
            }
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    let size = record_field_size(&field.ty);
                    if size <= 8 {
                        self.assert_scalar_reg(field.value, out);
                    } else {
                        self.check_ptr_range(field.value, size, out)?;
                    }
                }
            }
            MirInst::Histogram { value } => {
                self.assert_scalar_reg(*value, out);
            }
            MirInst::StartTimer => {}
            MirInst::StopTimer { dst } => {
                let ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
            }
            MirInst::CallHelper { dst, helper, args } => {
                self.verify_helper_call(*helper, args, out)?;
                let ty = self.helper_return_type(*helper, *dst);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
                if let VccValueType::Ptr(info) = ty {
                    self.ptr_regs.insert(VccReg(dst.0), info);
                }
                if matches!(BpfHelper::from_u32(*helper), Some(BpfHelper::RingbufReserve)) {
                    out.push(VccInst::RingbufAcquire { id: VccReg(dst.0) });
                }
                if matches!(
                    BpfHelper::from_u32(*helper),
                    Some(BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard)
                ) {
                    if let Some(arg0) = args.first() {
                        let release_ptr = self.lower_value(arg0, out);
                        out.push(VccInst::RingbufRelease {
                            ptr: release_ptr,
                        });
                    }
                }
            }
            MirInst::CallSubfn { dst, .. } => {
                let ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
            }
            MirInst::ReadStr {
                dst, ptr, max_len, ..
            } => {
                if *max_len == 0 {
                    return Err(VccError::new(
                        VccErrorKind::PointerBounds,
                        "read_str max_len must be positive",
                    ));
                }
                let ptr_reg = VccReg(ptr.0);
                let tmp = self.temp_reg();
                out.push(VccInst::PtrAdd {
                    dst: tmp,
                    base: ptr_reg,
                    offset: VccValue::Imm(0),
                });

                let base = self.stack_addr_temp(*dst, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: (*max_len as i64).saturating_sub(1),
                    src: VccValue::Imm(0),
                    size: 1,
                });
            }
            MirInst::StringAppend {
                dst_buffer,
                dst_len,
                val,
                val_type,
            } => {
                let len_reg = VccReg(dst_len.0);
                out.push(VccInst::AssertScalar {
                    value: VccValue::Reg(len_reg),
                });

                let dst_base = self.stack_addr_temp(*dst_buffer, out);
                let dst_ptr = self.temp_reg();
                out.push(VccInst::PtrAdd {
                    dst: dst_ptr,
                    base: dst_base,
                    offset: VccValue::Reg(len_reg),
                });

                match val_type {
                    StringAppendType::Literal { bytes } => {
                        let effective_len = bytes
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|idx| idx + 1)
                            .unwrap_or(0);
                        if !bytes.is_empty() {
                            let last = (bytes.len() as i64).saturating_sub(1);
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: last,
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }
                        if effective_len > 0 {
                            out.push(VccInst::BinOp {
                                dst: len_reg,
                                op: VccBinOp::Add,
                                lhs: VccValue::Reg(len_reg),
                                rhs: VccValue::Imm(effective_len as i64),
                            });
                        }
                    }
                    StringAppendType::StringSlot { slot, max_len } => {
                        let copy_len = (*max_len).min(STRING_APPEND_COPY_CAP);
                        if copy_len > 0 {
                            let last = (copy_len as i64).saturating_sub(1);
                            let src_base = self.stack_addr_temp(*slot, out);
                            let tmp = self.temp_reg();
                            out.push(VccInst::Load {
                                dst: tmp,
                                ptr: src_base,
                                offset: last,
                                size: 1,
                            });
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: last,
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }

                        let delta = self.temp_reg();
                        out.push(VccInst::Assume {
                            dst: delta,
                            ty: VccValueType::Scalar {
                                range: Some(VccRange {
                                    min: 0,
                                    max: copy_len as i64,
                                }),
                            },
                        });
                        out.push(VccInst::BinOp {
                            dst: len_reg,
                            op: VccBinOp::Add,
                            lhs: VccValue::Reg(len_reg),
                            rhs: VccValue::Reg(delta),
                        });
                    }
                    StringAppendType::Integer => {
                        let vcc_val = self.lower_value(val, out);
                        out.push(VccInst::AssertScalar { value: vcc_val });

                        let max_digits = MAX_INT_STRING_LEN;
                        if max_digits > 0 {
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: (max_digits as i64).saturating_sub(1),
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }

                        let delta = self.temp_reg();
                        out.push(VccInst::Assume {
                            dst: delta,
                            ty: VccValueType::Scalar {
                                range: Some(VccRange {
                                    min: 1,
                                    max: max_digits as i64,
                                }),
                            },
                        });
                        out.push(VccInst::BinOp {
                            dst: len_reg,
                            op: VccBinOp::Add,
                            lhs: VccValue::Reg(len_reg),
                            rhs: VccValue::Reg(delta),
                        });
                    }
                }
            }
            MirInst::IntToString {
                dst_buffer,
                dst_len,
                val,
            } => {
                out.push(VccInst::AssertScalar {
                    value: VccValue::Reg(VccReg(val.0)),
                });

                let base = self.stack_addr_temp(*dst_buffer, out);
                let max_digits = MAX_INT_STRING_LEN;
                if max_digits > 0 {
                    out.push(VccInst::Store {
                        ptr: base,
                        offset: (max_digits as i64).saturating_sub(1),
                        src: VccValue::Imm(0),
                        size: 1,
                    });
                }

                out.push(VccInst::Assume {
                    dst: VccReg(dst_len.0),
                    ty: VccValueType::Scalar {
                        range: Some(VccRange {
                            min: 1,
                            max: max_digits as i64,
                        }),
                    },
                });
            }
            MirInst::RecordStore {
                buffer,
                field_offset,
                val,
                ty,
            } => {
                let size = ty.size();
                if size == 0 || size > u8::MAX as usize {
                    return Err(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        "record store size out of range",
                    ));
                }
                let base = self.stack_addr_temp(*buffer, out);
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: *field_offset as i64,
                    src: vcc_val,
                    size: size as u8,
                });
            }
            MirInst::ListNew { .. }
            | MirInst::ListPush { .. }
            | MirInst::ListLen { .. }
            | MirInst::ListGet { .. } => {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    "list operations must be lowered before VCC verification",
                ));
            }
            MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopHeader { .. }
            | MirInst::LoopBack { .. }
            | MirInst::Placeholder => {}
        }

        Ok(())
    }

    fn lower_terminator(
        &mut self,
        term: &MirInst,
        out: &mut Vec<VccInst>,
    ) -> Result<VccTerminator, VccError> {
        match term {
            MirInst::Jump { target } => Ok(VccTerminator::Jump {
                target: VccBlockId(target.0),
            }),
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => Ok(VccTerminator::Branch {
                cond: VccValue::Reg(VccReg(cond.0)),
                if_true: VccBlockId(if_true.0),
                if_false: VccBlockId(if_false.0),
            }),
            MirInst::Return { val } => {
                let vcc_val = val.as_ref().map(|v| self.lower_value(v, out));
                Ok(VccTerminator::Return { value: vcc_val })
            }
            MirInst::TailCall { index, .. } => {
                let vcc_val = self.lower_value(index, out);
                out.push(VccInst::AssertScalar { value: vcc_val });
                Ok(VccTerminator::Return { value: None })
            }
            MirInst::LoopHeader {
                counter,
                limit,
                body,
                exit,
            } => {
                let tmp = self.temp_reg();
                out.push(VccInst::BinOp {
                    dst: tmp,
                    op: VccBinOp::Lt,
                    lhs: VccValue::Reg(VccReg(counter.0)),
                    rhs: VccValue::Imm(*limit),
                });
                Ok(VccTerminator::Branch {
                    cond: VccValue::Reg(tmp),
                    if_true: VccBlockId(body.0),
                    if_false: VccBlockId(exit.0),
                })
            }
            MirInst::LoopBack {
                counter,
                step,
                header,
            } => {
                out.push(VccInst::BinOp {
                    dst: VccReg(counter.0),
                    op: VccBinOp::Add,
                    lhs: VccValue::Reg(VccReg(counter.0)),
                    rhs: VccValue::Imm(*step),
                });
                Ok(VccTerminator::Jump {
                    target: VccBlockId(header.0),
                })
            }
            MirInst::Placeholder => Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "placeholder terminator in VCC lowering",
            )),
            _ => Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "non-terminator in terminator position",
            )),
        }
    }

    fn lower_value(&mut self, value: &MirValue, out: &mut Vec<VccInst>) -> VccValue {
        match value {
            MirValue::Const(v) => VccValue::Imm(*v),
            MirValue::VReg(v) => VccValue::Reg(VccReg(v.0)),
            MirValue::StackSlot(slot) => VccValue::Reg(self.stack_addr_temp(*slot, out)),
        }
    }

    fn base_ptr_reg(&mut self, value: &MirValue, out: &mut Vec<VccInst>) -> VccReg {
        match value {
            MirValue::VReg(v) => VccReg(v.0),
            MirValue::StackSlot(slot) => self.stack_addr_temp(*slot, out),
            MirValue::Const(_) => self.temp_reg(),
        }
    }

    fn stack_addr_temp(&mut self, slot: StackSlotId, out: &mut Vec<VccInst>) -> VccReg {
        let reg = self.temp_reg();
        let size = self.slot_sizes.get(&slot).copied().unwrap_or(0) as i64;
        out.push(VccInst::StackAddr {
            dst: reg,
            slot,
            size,
        });
        self.ptr_regs.insert(
            reg,
            VccPointerInfo {
                space: VccAddrSpace::Stack(slot),
                nullability: VccNullability::NonNull,
                bounds: stack_bounds(size),
                ringbuf_ref: None,
            },
        );
        reg
    }

    fn temp_reg(&mut self) -> VccReg {
        let reg = VccReg(self.next_temp);
        self.next_temp += 1;
        reg
    }

    fn value_ptr_info(&self, value: &MirValue) -> Option<VccPointerInfo> {
        match value {
            MirValue::StackSlot(slot) => {
                let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                Some(VccPointerInfo {
                    space: VccAddrSpace::Stack(*slot),
                    nullability: VccNullability::NonNull,
                    bounds: stack_bounds(size),
                    ringbuf_ref: None,
                })
            }
            MirValue::VReg(v) => self
                .ptr_regs
                .get(&VccReg(v.0))
                .copied()
                .or_else(|| self.types.get(v).and_then(ptr_info_from_mir)),
            MirValue::Const(_) => None,
        }
    }

    fn maybe_assume_type(&mut self, dst: VReg, ty: &MirType, out: &mut Vec<VccInst>) {
        let vcc_ty = vcc_type_from_mir(ty);
        if matches!(vcc_ty, VccValueType::Ptr(_) | VccValueType::Bool) {
            out.push(VccInst::Assume {
                dst: VccReg(dst.0),
                ty: vcc_ty,
            });
            if let VccValueType::Ptr(info) = vcc_ty {
                self.ptr_regs.insert(VccReg(dst.0), info);
            }
        }
    }

    fn helper_return_type(&self, helper_id: u32, dst: VReg) -> VccValueType {
        let inferred = self.types.get(&dst).map(vcc_type_from_mir);
        let helper = BpfHelper::from_u32(helper_id);
        let Some(sig) = HelperSignature::for_id(helper_id) else {
            return inferred.unwrap_or(VccValueType::Unknown);
        };

        match sig.ret_kind {
            HelperRetKind::Scalar => inferred.unwrap_or(VccValueType::Scalar { range: None }),
            HelperRetKind::PointerMaybeNull => {
                if matches!(helper, Some(BpfHelper::RingbufReserve)) {
                    return VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::RingBuf,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: Some(VccReg(dst.0)),
                    });
                }
                match inferred {
                    Some(VccValueType::Ptr(mut info)) => {
                        info.nullability = VccNullability::MaybeNull;
                        VccValueType::Ptr(info)
                    }
                    _ => VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::MapValue,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                    }),
                }
            }
        }
    }

    fn maybe_assume_list_len(&mut self, dst: VReg, ptr: VReg, offset: i32, out: &mut Vec<VccInst>) {
        if offset != 0 {
            return;
        }
        let slot = match self.ptr_regs.get(&VccReg(ptr.0)) {
            Some(info) => match info.space {
                VccAddrSpace::Stack(slot) => Some(slot),
                _ => None,
            },
            None => None,
        };
        if let Some(slot) = slot {
            self.maybe_assume_list_len_slot(dst, slot, offset, out);
        }
    }

    fn maybe_assume_list_len_slot(
        &self,
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        out: &mut Vec<VccInst>,
    ) {
        if offset != 0 {
            return;
        }
        let kind = self.slot_kinds.get(&slot).copied();
        if kind != Some(StackSlotKind::ListBuffer) {
            return;
        }
        let size = self.slot_sizes.get(&slot).copied().unwrap_or(0);
        let slot_cap = size / 8;
        if slot_cap == 0 {
            return;
        }
        let max_len = self
            .list_max
            .get(&slot)
            .copied()
            .unwrap_or(slot_cap.saturating_sub(1));
        let max_len = max_len.min(slot_cap.saturating_sub(1));
        let max = max_len.saturating_sub(1);
        out.push(VccInst::Assume {
            dst: VccReg(dst.0),
            ty: VccValueType::Scalar {
                range: Some(VccRange {
                    min: 0,
                    max: max as i64,
                }),
            },
        });
    }

    fn assert_scalar_reg(&self, reg: VReg, out: &mut Vec<VccInst>) {
        out.push(VccInst::AssertScalar {
            value: VccValue::Reg(VccReg(reg.0)),
        });
    }

    fn check_ptr_range(
        &mut self,
        reg: VReg,
        size: usize,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if size == 0 {
            return Ok(());
        }
        let ty = self
            .types
            .get(&reg)
            .map(vcc_type_from_mir)
            .unwrap_or(VccValueType::Unknown);
        if ty.class() != VccTypeClass::Ptr && !self.ptr_regs.contains_key(&VccReg(reg.0)) {
            return Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: ty.class(),
                },
                "expected pointer value",
            ));
        }

        let check_size = if size >= 8 { 8 } else { 1 };
        let offset = if size >= 8 {
            (size - 8) as i64
        } else {
            (size - 1) as i64
        };
        let tmp = self.temp_reg();
        out.push(VccInst::Load {
            dst: tmp,
            ptr: VccReg(reg.0),
            offset,
            size: check_size as u8,
        });
        Ok(())
    }

    fn verify_helper_call(
        &mut self,
        helper_id: u32,
        args: &[MirValue],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if let Some(sig) = HelperSignature::for_id(helper_id) {
            if args.len() < sig.min_args || args.len() > sig.max_args {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "helper {} expects {}..={} args, got {}",
                        helper_id,
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    ),
                ));
            }

            for (idx, arg) in args.iter().enumerate() {
                self.verify_helper_arg_value(helper_id, idx, arg, sig.arg_kind(idx), out)?;
            }
            self.verify_helper_semantics(helper_id, args, out)?;
        } else if args.len() > 5 {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "BPF helpers support at most 5 arguments",
            ));
        }

        Ok(())
    }

    fn verify_helper_arg_value(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        expected: HelperArgKind,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        match expected {
            HelperArgKind::Scalar => match arg {
                MirValue::Const(_) => Ok(()),
                MirValue::VReg(vreg) => {
                    self.assert_scalar_reg(*vreg, out);
                    Ok(())
                }
                MirValue::StackSlot(_) => Err(VccError::new(
                    VccErrorKind::TypeMismatch {
                        expected: VccTypeClass::Scalar,
                        actual: VccTypeClass::Ptr,
                    },
                    format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
                )),
            },
            HelperArgKind::Pointer => match arg {
                MirValue::Const(_) => Err(VccError::new(
                    VccErrorKind::TypeMismatch {
                        expected: VccTypeClass::Ptr,
                        actual: VccTypeClass::Scalar,
                    },
                    format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
                )),
                MirValue::VReg(vreg) => self.check_ptr_range(*vreg, 1, out),
                MirValue::StackSlot(_) => Ok(()),
            },
        }
    }

    fn helper_space_allowed(
        &self,
        space: VccAddrSpace,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> bool {
        match space {
            VccAddrSpace::Stack(_) => allow_stack,
            VccAddrSpace::MapValue | VccAddrSpace::RingBuf => allow_map,
            VccAddrSpace::Context | VccAddrSpace::Kernel => allow_kernel,
            VccAddrSpace::User => allow_user,
            VccAddrSpace::Unknown => true,
        }
    }

    fn helper_space_name(&self, space: VccAddrSpace) -> &'static str {
        match space {
            VccAddrSpace::Stack(_) => "Stack",
            VccAddrSpace::MapValue => "Map",
            VccAddrSpace::RingBuf => "RingBuf",
            VccAddrSpace::Context => "Context",
            VccAddrSpace::Kernel => "Kernel",
            VccAddrSpace::User => "User",
            VccAddrSpace::Unknown => "Unknown",
        }
    }

    fn helper_allowed_spaces_label(
        &self,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> String {
        let mut labels = Vec::new();
        if allow_stack {
            labels.push("Stack");
        }
        if allow_map {
            labels.push("Map");
        }
        if allow_kernel {
            labels.push("Kernel");
        }
        if allow_user {
            labels.push("User");
        }
        format!("[{}]", labels.join(", "))
    }

    fn check_ptr_range_reg(
        &mut self,
        ptr: VccReg,
        size: usize,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if size == 0 {
            return Ok(());
        }
        if !self.ptr_regs.contains_key(&ptr) {
            return Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Unknown,
                },
                "expected pointer value",
            ));
        }

        let check_size = if size >= 8 { 8 } else { 1 };
        let offset = if size >= 8 {
            (size - 8) as i64
        } else {
            (size - 1) as i64
        };
        let tmp = self.temp_reg();
        out.push(VccInst::Load {
            dst: tmp,
            ptr,
            offset,
            size: check_size as u8,
        });
        Ok(())
    }

    fn check_helper_ptr_arg_value(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        op: &str,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
        access_size: Option<usize>,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let ptr = self.value_ptr_info(arg).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
            )
        })?;

        if !self.helper_space_allowed(ptr.space, allow_stack, allow_map, allow_kernel, allow_user) {
            let allowed =
                self.helper_allowed_spaces_label(allow_stack, allow_map, allow_kernel, allow_user);
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "{op} expects pointer in {allowed}, got {}",
                    self.helper_space_name(ptr.space)
                ),
            ));
        }

        if let Some(size) = access_size {
            match arg {
                MirValue::VReg(vreg) => self.check_ptr_range(*vreg, size, out)?,
                MirValue::StackSlot(slot) => {
                    let ptr = self.stack_addr_temp(*slot, out);
                    self.check_ptr_range_reg(ptr, size, out)?;
                }
                MirValue::Const(_) => {
                    return Err(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Ptr,
                            actual: VccTypeClass::Scalar,
                        },
                        format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
                    ));
                }
            }
        }

        Ok(())
    }

    fn check_helper_ringbuf_record_arg(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        op: &str,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let ptr = self.value_ptr_info(arg).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!("helper {} arg{} expects ringbuf record pointer", helper_id, arg_idx),
            )
        })?;

        if ptr.space != VccAddrSpace::RingBuf {
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "{op} expects ringbuf record pointer, got {}",
                    self.helper_space_name(ptr.space)
                ),
            ));
        }

        match arg {
            MirValue::VReg(vreg) => self.check_ptr_range(*vreg, 1, out),
            MirValue::StackSlot(slot) => {
                let ptr = self.stack_addr_temp(*slot, out);
                self.check_ptr_range_reg(ptr, 1, out)
            }
            MirValue::Const(_) => Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!("helper {} arg{} expects ringbuf record pointer", helper_id, arg_idx),
            )),
        }
    }

    fn helper_positive_size_upper_bound(
        &self,
        helper_id: u32,
        arg_idx: usize,
        value: &MirValue,
    ) -> Result<Option<usize>, VccError> {
        match value {
            MirValue::Const(v) => {
                if *v <= 0 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("helper {} arg{} must be > 0", helper_id, arg_idx),
                    ));
                }
                let size = usize::try_from(*v).map_err(|_| {
                    VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("helper {} arg{} is out of range", helper_id, arg_idx),
                    )
                })?;
                Ok(Some(size))
            }
            MirValue::VReg(_) => Ok(None),
            MirValue::StackSlot(_) => Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Scalar,
                    actual: VccTypeClass::Ptr,
                },
                format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
            )),
        }
    }

    fn verify_helper_semantics(
        &mut self,
        helper_id: u32,
        args: &[MirValue],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let Some(helper) = BpfHelper::from_u32(helper_id) else {
            return Ok(());
        };

        match helper {
            BpfHelper::MapLookupElem => {
                if let Some(map) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        map,
                        "helper map_lookup map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(key) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        key,
                        "helper map_lookup key",
                        true,
                        true,
                        false,
                        false,
                        Some(1),
                        out,
                    )?;
                }
            }
            BpfHelper::MapUpdateElem => {
                if let Some(map) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        map,
                        "helper map_update map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(key) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        key,
                        "helper map_update key",
                        true,
                        true,
                        false,
                        false,
                        Some(1),
                        out,
                    )?;
                }
                if let Some(value) = args.get(2) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        2,
                        value,
                        "helper map_update value",
                        true,
                        true,
                        false,
                        false,
                        Some(1),
                        out,
                    )?;
                }
            }
            BpfHelper::MapDeleteElem => {
                if let Some(map) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        map,
                        "helper map_delete map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(key) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        key,
                        "helper map_delete key",
                        true,
                        true,
                        false,
                        false,
                        Some(1),
                        out,
                    )?;
                }
            }
            BpfHelper::GetCurrentComm => {
                let size = args
                    .get(1)
                    .map(|arg| self.helper_positive_size_upper_bound(helper_id, 1, arg))
                    .transpose()?
                    .flatten();
                if let Some(dst) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        dst,
                        "helper get_current_comm dst",
                        true,
                        true,
                        false,
                        false,
                        size,
                        out,
                    )?;
                }
            }
            BpfHelper::ProbeRead | BpfHelper::ProbeReadKernelStr | BpfHelper::ProbeReadUserStr => {
                let size = args
                    .get(1)
                    .map(|arg| self.helper_positive_size_upper_bound(helper_id, 1, arg))
                    .transpose()?
                    .flatten();
                if let Some(dst) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        dst,
                        "helper probe_read dst",
                        true,
                        true,
                        false,
                        false,
                        size,
                        out,
                    )?;
                }
                if let Some(src) = args.get(2) {
                    let (allow_stack, allow_map, allow_kernel, allow_user) =
                        if matches!(helper, BpfHelper::ProbeReadUserStr) {
                            (false, false, false, true)
                        } else {
                            (true, true, true, false)
                        };
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        2,
                        src,
                        "helper probe_read src",
                        allow_stack,
                        allow_map,
                        allow_kernel,
                        allow_user,
                        size,
                        out,
                    )?;
                }
            }
            BpfHelper::RingbufReserve => {
                if let Some(map) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        map,
                        "helper ringbuf_reserve map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(size_arg) = args.get(1) {
                    let _ = self.helper_positive_size_upper_bound(helper_id, 1, size_arg)?;
                }
            }
            BpfHelper::RingbufOutput => {
                if let Some(map) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        map,
                        "helper ringbuf_output map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                let size = args
                    .get(2)
                    .map(|arg| self.helper_positive_size_upper_bound(helper_id, 2, arg))
                    .transpose()?
                    .flatten();
                if let Some(data) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        data,
                        "helper ringbuf_output data",
                        true,
                        true,
                        false,
                        false,
                        size,
                        out,
                    )?;
                }
            }
            BpfHelper::TailCall => {
                if let Some(ctx) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        ctx,
                        "helper tail_call ctx",
                        false,
                        false,
                        true,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(map) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        map,
                        "helper tail_call map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
            }
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => {
                if let Some(record) = args.first() {
                    self.check_helper_ringbuf_record_arg(
                        helper_id,
                        0,
                        record,
                        "helper ringbuf submit/discard record",
                        out,
                    )?;
                }
            }
            BpfHelper::PerfEventOutput => {
                if let Some(ctx) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        ctx,
                        "helper perf_event_output ctx",
                        false,
                        false,
                        true,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(map) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        map,
                        "helper perf_event_output map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
                let size = args
                    .get(4)
                    .map(|arg| self.helper_positive_size_upper_bound(helper_id, 4, arg))
                    .transpose()?
                    .flatten();
                if let Some(data) = args.get(3) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        3,
                        data,
                        "helper perf_event_output data",
                        true,
                        true,
                        false,
                        false,
                        size,
                        out,
                    )?;
                }
            }
            BpfHelper::GetStackId => {
                if let Some(ctx) = args.first() {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        0,
                        ctx,
                        "helper get_stackid ctx",
                        false,
                        false,
                        true,
                        false,
                        None,
                        out,
                    )?;
                }
                if let Some(map) = args.get(1) {
                    self.check_helper_ptr_arg_value(
                        helper_id,
                        1,
                        map,
                        "helper get_stackid map",
                        true,
                        true,
                        false,
                        false,
                        None,
                        out,
                    )?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn verify_map_key(
        &mut self,
        map_name: &str,
        key: VReg,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if map_name == STRING_COUNTER_MAP_NAME {
            self.check_ptr_range(key, 16, out)
        } else {
            self.verify_map_operand(key, out)
        }
    }

    fn verify_map_value(&mut self, value: VReg, out: &mut Vec<VccInst>) -> Result<(), VccError> {
        self.verify_map_operand(value, out)
    }

    fn verify_map_operand(&mut self, reg: VReg, out: &mut Vec<VccInst>) -> Result<(), VccError> {
        let is_ptr = self
            .types
            .get(&reg)
            .map(vcc_type_from_mir)
            .map(|ty| ty.class() == VccTypeClass::Ptr)
            .unwrap_or(false)
            || self.ptr_regs.contains_key(&VccReg(reg.0));

        if is_ptr {
            let size = match self.types.get(&reg) {
                Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
                _ => 1,
            };
            self.check_ptr_range(reg, size, out)
        } else {
            self.assert_scalar_reg(reg, out);
            Ok(())
        }
    }
}

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

fn vcc_type_from_mir(ty: &MirType) -> VccValueType {
    match ty {
        MirType::Bool => VccValueType::Bool,
        MirType::Ptr { address_space, .. } => VccValueType::Ptr(VccPointerInfo {
            space: match address_space {
                AddressSpace::Stack => VccAddrSpace::Unknown,
                AddressSpace::Kernel => VccAddrSpace::Kernel,
                AddressSpace::User => VccAddrSpace::User,
                AddressSpace::Map => VccAddrSpace::MapValue,
            },
            nullability: VccNullability::NonNull,
            bounds: None,
            ringbuf_ref: None,
        }),
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
mod tests {
    use super::*;
    use crate::compiler::mir::{
        AddressSpace, BlockId, MapKind, MapRef, MirFunction, MirInst, MirType, MirValue,
        StackSlotKind, StringAppendType,
    };
    use std::collections::HashMap;

    fn verify_ok(func: &VccFunction) {
        VccVerifier::default()
            .verify_function(func)
            .expect("expected verifier success");
    }

    fn verify_err(func: &VccFunction, kind: VccErrorKind) {
        let err = VccVerifier::default()
            .verify_function(func)
            .expect_err("expected verifier error");
        assert!(
            err.iter().any(|e| e.kind == kind),
            "expected error {:?}, got {:?}",
            kind,
            err
        );
    }

    fn map_lookup_types(func: &MirFunction, vreg: VReg) -> HashMap<VReg, MirType> {
        let mut types = HashMap::new();
        for i in 0..func.vreg_count {
            types.insert(VReg(i), MirType::I64);
        }
        types.insert(
            vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types
    }

    #[test]
    fn test_reject_pointer_binop() {
        let mut func = VccFunction::new();
        let entry = func.entry;
        let p0 = func.alloc_reg();
        let p1 = func.alloc_reg();
        let out = func.alloc_reg();

        func.block_mut(entry).instructions.push(VccInst::StackAddr {
            dst: p0,
            slot: StackSlotId(0),
            size: 16,
        });
        func.block_mut(entry).instructions.push(VccInst::StackAddr {
            dst: p1,
            slot: StackSlotId(1),
            size: 16,
        });
        func.block_mut(entry).instructions.push(VccInst::BinOp {
            dst: out,
            op: VccBinOp::Add,
            lhs: VccValue::Reg(p0),
            rhs: VccValue::Reg(p1),
        });

        verify_err(&func, VccErrorKind::PointerArithmetic);
    }

    #[test]
    fn test_ptr_add_in_bounds() {
        let mut func = VccFunction::new();
        let entry = func.entry;
        let base = func.alloc_reg();
        let out = func.alloc_reg();

        func.block_mut(entry).instructions.push(VccInst::StackAddr {
            dst: base,
            slot: StackSlotId(0),
            size: 16,
        });
        func.block_mut(entry).instructions.push(VccInst::PtrAdd {
            dst: out,
            base,
            offset: VccValue::Imm(8),
        });

        verify_ok(&func);
    }

    #[test]
    fn test_ptr_add_out_of_bounds() {
        let mut func = VccFunction::new();
        let entry = func.entry;
        let base = func.alloc_reg();
        let out = func.alloc_reg();

        func.block_mut(entry).instructions.push(VccInst::StackAddr {
            dst: base,
            slot: StackSlotId(0),
            size: 8,
        });
        func.block_mut(entry).instructions.push(VccInst::PtrAdd {
            dst: out,
            base,
            offset: VccValue::Imm(16),
        });

        verify_err(&func, VccErrorKind::PointerBounds);
    }

    #[test]
    fn test_ptr_add_unknown_offset_on_stack() {
        let mut func = VccFunction::new();
        let entry = func.entry;
        let base = func.alloc_reg();
        let tmp = func.alloc_reg();
        let out = func.alloc_reg();

        func.block_mut(entry).instructions.push(VccInst::StackAddr {
            dst: base,
            slot: StackSlotId(0),
            size: 16,
        });
        func.block_mut(entry).instructions.push(VccInst::Assume {
            dst: tmp,
            ty: VccValueType::Scalar { range: None },
        });
        func.block_mut(entry).instructions.push(VccInst::PtrAdd {
            dst: out,
            base,
            offset: VccValue::Reg(tmp),
        });

        verify_err(&func, VccErrorKind::UnknownOffset);
    }

    #[test]
    fn test_unreachable_block_is_ignored() {
        let mut func = VccFunction::new();
        let entry = func.entry;
        let unreachable = func.alloc_block();
        let p0 = func.alloc_reg();
        let p1 = func.alloc_reg();
        let out = func.alloc_reg();

        func.block_mut(entry).terminator = VccTerminator::Return { value: None };
        func.block_mut(unreachable)
            .instructions
            .push(VccInst::StackAddr {
                dst: p0,
                slot: StackSlotId(0),
                size: 16,
            });
        func.block_mut(unreachable)
            .instructions
            .push(VccInst::StackAddr {
                dst: p1,
                slot: StackSlotId(1),
                size: 16,
            });
        func.block_mut(unreachable).instructions.push(VccInst::BinOp {
            dst: out,
            op: VccBinOp::Add,
            lhs: VccValue::Reg(p0),
            rhs: VccValue::Reg(p1),
        });

        verify_ok(&func);
    }

    fn new_mir_function() -> (MirFunction, BlockId) {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        (func, entry)
    }

    #[test]
    fn test_verify_mir_string_append_literal_bounds() {
        let (mut func, entry) = new_mir_function();
        let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        let len = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len,
            src: MirValue::Const(0),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: buffer,
                dst_len: len,
                val: MirValue::Const(0),
                val_type: StringAppendType::Literal {
                    bytes: vec![b'a', b'b', b'c'],
                },
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        assert!(verify_mir(&func, &HashMap::new()).is_ok());
    }

    #[test]
    fn test_verify_mir_string_append_literal_oob() {
        let (mut func, entry) = new_mir_function();
        let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        let len = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len,
            src: MirValue::Const(0),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: buffer,
                dst_len: len,
                val: MirValue::Const(0),
                val_type: StringAppendType::Literal {
                    bytes: vec![0u8; 9],
                },
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_string_append_slot_oob() {
        let (mut func, entry) = new_mir_function();
        let dst_buffer = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
        let src_buffer = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let len = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len,
            src: MirValue::Const(0),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer,
                dst_len: len,
                val: MirValue::Const(0),
                val_type: StringAppendType::StringSlot {
                    slot: src_buffer,
                    max_len: 8,
                },
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_int_to_string_buffer_oob() {
        let (mut func, entry) = new_mir_function();
        let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        let len = func.alloc_vreg();
        let val = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: val,
            src: MirValue::Const(42),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::IntToString {
                dst_buffer: buffer,
                dst_len: len,
                val,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_emit_event_requires_ptr() {
        let (mut func, entry) = new_mir_function();
        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let data = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: data,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::EmitEvent { data, size: 16 });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        assert!(verify_mir(&func, &HashMap::new()).is_ok());

        let (mut func, entry) = new_mir_function();
        let data = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: data,
            src: MirValue::Const(0),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::EmitEvent { data, size: 16 });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected pointer error");
        assert!(
            err.iter()
                .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })),
            "expected type mismatch error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_strcmp_bounds() {
        let (mut func, entry) = new_mir_function();
        let lhs = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let rhs = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::StrCmp {
            dst,
            lhs,
            rhs,
            len: 8,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_map_lookup_requires_null_check_before_load() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let load_dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "test".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        let err = verify_mir(&func, &types).expect_err("expected null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_map_lookup_null_check_then_load_ok() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let load_block = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let load_dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "test".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(dst),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: load_block,
            if_false: done,
        };

        func.block_mut(load_block).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(load_block).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        verify_mir(&func, &types).expect("expected null-checked map lookup load to pass");
    }

    #[test]
    fn test_verify_mir_helper_map_lookup_requires_null_check_before_load() {
        let (mut func, entry) = new_mir_function();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_map_lookup_null_check_then_load_ok() {
        let (mut func, entry) = new_mir_function();
        let load_block = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: load_block,
            if_false: done,
        };

        func.block_mut(load_block).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(load_block).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        verify_mir(&func, &types).expect("expected helper null-checked load to pass");
    }

    #[test]
    fn test_verify_mir_helper_map_lookup_rejects_user_map_pointer() {
        let (mut func, entry) = new_mir_function();
        let map = func.alloc_vreg();
        func.param_count = 1;
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::StackSlot(key_slot)],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            map,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper map pointer-space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(
                |e| e.message
                    .contains("helper map_lookup map expects pointer in [Stack, Map]")
            ),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_reserve_submit_ok() {
        let (mut func, entry) = new_mir_function();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_reserve_submit_ok_with_eq_null_branch() {
        let (mut func, entry) = new_mir_function();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: done,
            if_false: submit,
        };

        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_reserve_without_release_rejected() {
        let (mut func, entry) = new_mir_function();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new())
            .expect_err("expected leak error for unreleased ringbuf record");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter()
                .any(|e| e.message.contains("unreleased ringbuf record reference")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_submit_requires_null_check() {
        let (mut func, entry) = new_mir_function();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected missing null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_submit_rejects_double_release() {
        let (mut func, entry) = new_mir_function();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret0 = func.alloc_vreg();
        let submit_ret1 = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret0,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret1,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret0, MirType::I64);
        types.insert(submit_ret1, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected double-release error");
        assert!(
            err.iter().any(|e| {
                e.message.contains("ringbuf record already released")
                    || e.message.contains("ringbuf release requires pointer operand")
            }),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_submit_invalidates_record_pointer() {
        let (mut func, entry) = new_mir_function();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();
        let load_dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
        func.block_mut(submit).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: record,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        types.insert(load_dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected use-after-release error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("load requires pointer operand")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_submit_rejects_map_lookup_pointer() {
        let (mut func, entry) = new_mir_function();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit).instructions.push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(ptr), MirValue::Const(0)],
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(|e| e
                .message
                .contains("expects ringbuf record pointer, got Map")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_ringbuf_submit_rejects_stack_pointer() {
        let (mut func, entry) = new_mir_function();
        let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::StackSlot(slot), MirValue::Const(0)],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(|e| e
                .message
                .contains("expects ringbuf record pointer, got Stack")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_perf_event_output_rejects_user_ctx_pointer() {
        let (mut func, entry) = new_mir_function();
        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_get_stackid_rejects_user_ctx_pointer() {
        let (mut func, entry) = new_mir_function();
        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 27, // bpf_get_stackid(ctx, map, flags)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper get_stackid ctx expects pointer in [Kernel]")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_tail_call_rejects_user_ctx_pointer() {
        let (mut func, entry) = new_mir_function();
        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper tail_call ctx expects pointer in [Kernel]")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_get_current_comm_positive_size_required() {
        let (mut func, entry) = new_mir_function();
        let dst = func.alloc_vreg();
        let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(0)],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper size error");
        assert!(
            err.iter()
                .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
            "expected helper size error, got {:?}",
            err
        );
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper 16 arg1 must be > 0")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_get_current_comm_bounds() {
        let (mut func, entry) = new_mir_function();
        let dst = func.alloc_vreg();
        let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(16)],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_probe_read_user_str_rejects_stack_src() {
        let (mut func, entry) = new_mir_function();
        let dst = func.alloc_vreg();
        let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 114, // bpf_probe_read_user_str(dst, size, unsafe_ptr)
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(8),
                MirValue::StackSlot(src_slot),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper source space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper probe_read src expects pointer in [User]")),
            "unexpected error messages: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_mir_helper_map_update_rejects_user_key() {
        let (mut func, entry) = new_mir_function();
        let key = func.alloc_vreg();
        func.param_count = 1;
        let dst = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let val_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry).instructions.push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(val_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            key,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper key space error");
        assert!(
            err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
            "expected pointer bounds error, got {:?}",
            err
        );
        assert!(
            err.iter().any(
                |e| e.message
                    .contains("helper map_update key expects pointer in [Stack, Map]")
            ),
            "unexpected error messages: {:?}",
            err
        );
    }
}
