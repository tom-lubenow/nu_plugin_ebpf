//! Flow-sensitive verifier-type analysis over MIR.
//!
//! This pass models a subset of the kernel verifier's type system, focusing on
//! pointer kinds and nullability. It is intended to reject uses that are known
//! to fail the verifier (e.g. dereferencing a map lookup result without a null check).

use std::collections::{HashMap, VecDeque};

use super::mir::{AddressSpace, BinOpKind, BlockId, MirFunction, MirInst, MirType, MirValue, VReg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nullability {
    NonNull,
    MaybeNull,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifierType {
    Uninit,
    Unknown,
    Scalar,
    Bool,
    Ptr { space: AddressSpace, nullability: Nullability },
}

#[derive(Debug, Clone, Copy)]
struct Guard {
    ptr: VReg,
    true_is_non_null: bool,
}

#[derive(Debug, Clone)]
struct VerifierState {
    regs: Vec<VerifierType>,
    guards: HashMap<VReg, Guard>,
}

impl VerifierState {
    fn new(total_vregs: usize) -> Self {
        Self {
            regs: vec![VerifierType::Uninit; total_vregs],
            guards: HashMap::new(),
        }
    }

    fn with_cleared_guards(&self) -> Self {
        Self {
            regs: self.regs.clone(),
            guards: HashMap::new(),
        }
    }

    fn get(&self, vreg: VReg) -> VerifierType {
        self.regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(VerifierType::Unknown)
    }

    fn set(&mut self, vreg: VReg, ty: VerifierType) {
        if let Some(slot) = self.regs.get_mut(vreg.0 as usize) {
            *slot = ty;
        }
        self.guards.remove(&vreg);
    }

    fn join(&self, other: &VerifierState) -> VerifierState {
        let mut regs = Vec::with_capacity(self.regs.len());
        for i in 0..self.regs.len() {
            let a = self.regs[i];
            let b = other.regs[i];
            regs.push(join_type(a, b));
        }
        VerifierState {
            regs,
            guards: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifierTypeError {
    pub message: String,
}

impl VerifierTypeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerifierTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifierTypeError {}

pub fn verify_mir(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
) -> Result<(), Vec<VerifierTypeError>> {
    let total_vregs = func
        .vreg_count
        .max(func.param_count as u32) as usize;
    let mut in_states: HashMap<BlockId, VerifierState> = HashMap::new();
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut errors = Vec::new();

    let mut entry_state = VerifierState::new(total_vregs);
    for i in 0..func.param_count {
        let vreg = VReg(i as u32);
        let ty = types
            .get(&vreg)
            .map(|ty| verifier_type_from_mir(ty))
            .unwrap_or(VerifierType::Unknown);
        entry_state.set(vreg, ty);
    }

    in_states.insert(func.entry, entry_state);
    worklist.push_back(func.entry);

    while let Some(block_id) = worklist.pop_front() {
        let state_in = match in_states.get(&block_id) {
            Some(state) => state.clone(),
            None => continue,
        };
        let mut state = state_in.with_cleared_guards();
        let block = func.block(block_id);

        for inst in &block.instructions {
            apply_inst(inst, types, &mut state, &mut errors);
        }

        match &block.terminator {
            MirInst::Jump { target } => {
                propagate_state(*target, &state, &mut in_states, &mut worklist);
            }
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                let guard = state.guards.get(cond).copied();
                let true_state = refine_on_branch(&state, guard, true);
                let false_state = refine_on_branch(&state, guard, false);
                propagate_state(*if_true, &true_state, &mut in_states, &mut worklist);
                propagate_state(*if_false, &false_state, &mut in_states, &mut worklist);
            }
            MirInst::Return { .. } | MirInst::TailCall { .. } => {}
            _ => {}
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn propagate_state(
    block: BlockId,
    state: &VerifierState,
    in_states: &mut HashMap<BlockId, VerifierState>,
    worklist: &mut VecDeque<BlockId>,
) {
    let updated = match in_states.get(&block) {
        None => {
            in_states.insert(block, state.clone());
            true
        }
        Some(existing) => {
            let merged = existing.join(state);
            if merged.regs != existing.regs {
                in_states.insert(block, merged);
                true
            } else {
                false
            }
        }
    };

    if updated {
        worklist.push_back(block);
    }
}

fn refine_on_branch(state: &VerifierState, guard: Option<Guard>, take_true: bool) -> VerifierState {
    let mut next = state.with_cleared_guards();
    if let Some(guard) = guard {
        let wants_non_null = if take_true {
            guard.true_is_non_null
        } else {
            !guard.true_is_non_null
        };
        let current = next.get(guard.ptr);
        if let VerifierType::Ptr { space, .. } = current {
            let nullability = if wants_non_null {
                Nullability::NonNull
            } else {
                Nullability::Null
            };
            next.set(
                guard.ptr,
                VerifierType::Ptr {
                    space,
                    nullability,
                },
            );
        }
    }
    next
}

fn apply_inst(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            let ty = value_type(src, state);
            state.set(*dst, ty);
        }
        MirInst::Load { dst, ptr, .. } => {
            require_non_null_ptr(*ptr, "load", state, errors);
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::Store { ptr, .. } => {
            require_non_null_ptr(*ptr, "store", state, errors);
        }
        MirInst::LoadSlot { dst, .. } => {
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::StoreSlot { .. } => {}
        MirInst::BinOp { dst, op, lhs, rhs } => {
            if matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
                state.set(*dst, VerifierType::Bool);
                if let Some(guard) = guard_from_compare(*op, lhs, rhs, state) {
                    state.guards.insert(*dst, guard);
                }
            } else if matches!(op, BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge) {
                state.set(*dst, VerifierType::Bool);
            } else {
                let ty = pointer_arith_result(lhs, rhs, state)
                    .unwrap_or(VerifierType::Scalar);
                state.set(*dst, ty);
            }
        }
        MirInst::UnaryOp { op, .. } => {
            let ty = match op {
                super::mir::UnaryOpKind::Not => VerifierType::Bool,
                _ => VerifierType::Scalar,
            };
            if let Some(dst) = inst.def() {
                state.set(dst, ty);
            }
        }
        MirInst::CallHelper { dst, .. }
        | MirInst::CallSubfn { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::ListLen { dst, .. }
        | MirInst::ListGet { dst, .. }
        | MirInst::Phi { dst, .. } => {
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::MapLookup { dst, .. } => {
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Map,
                    nullability: Nullability::MaybeNull,
                },
            );
        }
        MirInst::ListNew { dst, .. } => {
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability: Nullability::NonNull,
                },
            );
        }
        MirInst::LoadCtxField { dst, .. } => {
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::EmitEvent { data, size } => {
            if *size > 8 {
                require_non_null_ptr(*data, "emit", state, errors);
            }
        }
        MirInst::EmitRecord { fields } => {
            for field in fields {
                if let Some(MirType::Array { .. }) = types.get(&field.value) {
                    require_non_null_ptr(field.value, "emit record", state, errors);
                }
            }
        }
        MirInst::MapUpdate { .. }
        | MirInst::MapDelete { .. }
        | MirInst::ReadStr { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { .. } => {}
        MirInst::StringAppend { .. } | MirInst::IntToString { .. } | MirInst::RecordStore { .. } => {}
    }
}

fn pointer_arith_result(
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> Option<VerifierType> {
    let lhs_ty = value_type(lhs, state);
    let rhs_ty = value_type(rhs, state);
    match (lhs_ty, rhs_ty) {
        (VerifierType::Ptr { space, nullability }, VerifierType::Scalar)
        | (VerifierType::Ptr { space, nullability }, VerifierType::Bool) => Some(
            VerifierType::Ptr {
                space,
                nullability,
            },
        ),
        (VerifierType::Scalar, VerifierType::Ptr { space, nullability })
        | (VerifierType::Bool, VerifierType::Ptr { space, nullability }) => Some(
            VerifierType::Ptr {
                space,
                nullability,
            },
        ),
        _ => None,
    }
}

fn guard_from_compare(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> Option<Guard> {
    let (ptr, other) = match (lhs, rhs) {
        (MirValue::VReg(v), other) => (Some(*v), other),
        (other, MirValue::VReg(v)) => (Some(*v), other),
        _ => (None, rhs),
    };

    let ptr = ptr?;
    let ptr_ty = state.get(ptr);
    if !matches!(ptr_ty, VerifierType::Ptr { .. }) {
        return None;
    }

    match other {
        MirValue::Const(c) if *c == 0 => {
            let true_is_non_null = matches!(op, BinOpKind::Ne);
            Some(Guard {
                ptr,
                true_is_non_null,
            })
        }
        _ => None,
    }
}

fn require_non_null_ptr(
    ptr: VReg,
    op: &str,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match state.get(ptr) {
        VerifierType::Ptr {
            nullability: Nullability::NonNull,
            ..
        } => {}
        VerifierType::Ptr {
            nullability: Nullability::Null,
            ..
        } => errors.push(VerifierTypeError::new(format!(
            "{op} uses null pointer v{}",
            ptr.0
        ))),
        VerifierType::Ptr {
            nullability: Nullability::MaybeNull,
            ..
        } => errors.push(VerifierTypeError::new(format!(
            "{op} may dereference null pointer v{} (add a null check)",
            ptr.0
        ))),
        VerifierType::Uninit => errors.push(VerifierTypeError::new(format!(
            "{op} uses uninitialized pointer v{}",
            ptr.0
        ))),
        other => errors.push(VerifierTypeError::new(format!(
            "{op} requires pointer type, got {:?}",
            other
        ))),
    }
}

fn value_type(value: &MirValue, state: &VerifierState) -> VerifierType {
    match value {
        MirValue::Const(_) => VerifierType::Scalar,
        MirValue::VReg(v) => state.get(*v),
        MirValue::StackSlot(_) => VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability: Nullability::NonNull,
        },
    }
}

fn verifier_type_from_mir(ty: &MirType) -> VerifierType {
    match ty {
        MirType::Bool => VerifierType::Bool,
        MirType::Ptr { address_space, .. } => VerifierType::Ptr {
            space: *address_space,
            nullability: match address_space {
                AddressSpace::Stack => Nullability::NonNull,
                AddressSpace::Map => Nullability::MaybeNull,
                AddressSpace::Kernel | AddressSpace::User => Nullability::MaybeNull,
            },
        },
        MirType::Unknown => VerifierType::Unknown,
        _ => VerifierType::Scalar,
    }
}

fn join_type(a: VerifierType, b: VerifierType) -> VerifierType {
    use VerifierType::*;
    match (a, b) {
        (Uninit, other) | (other, Uninit) => other,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Scalar, Scalar) => Scalar,
        (Bool, Bool) => Bool,
        (Ptr { space: sa, nullability: na }, Ptr { space: sb, nullability: nb }) => {
            if sa != sb {
                return Unknown;
            }
            let nullability = join_nullability(na, nb);
            Ptr {
                space: sa,
                nullability,
            }
        }
        (Scalar, Bool) | (Bool, Scalar) => Scalar,
        _ => Unknown,
    }
}

fn join_nullability(a: Nullability, b: Nullability) -> Nullability {
    match (a, b) {
        (Nullability::Null, Nullability::Null) => Nullability::Null,
        (Nullability::NonNull, Nullability::NonNull) => Nullability::NonNull,
        _ => Nullability::MaybeNull,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MapKind, MapRef, MirType, StackSlotKind};

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
    fn test_map_lookup_requires_null_check() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();

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
        let load_dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        let err = verify_mir(&func, &types).expect_err("expected null-check error");
        assert!(err
            .iter()
            .any(|e| e.message.contains("may dereference null")));
    }

    #[test]
    fn test_map_lookup_null_check_ok() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let cond = func.alloc_vreg();

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
            if_true: ok,
            if_false: bad,
        };

        let ok_load = func.alloc_vreg();
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst: ok_load,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        verify_mir(&func, &types).expect("expected verifier pass");
    }

    #[test]
    fn test_stack_pointer_non_null() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);
        verify_mir(&func, &types).expect("stack pointer should be non-null");
    }
}
