//! Hindley-Milner Type Inference for MIR
//!
//! Uses constraint-based type inference to determine types for all virtual
//! registers in a MIR function. Types are internal to the compiler - users
//! write idiomatic Nushell and the compiler infers types from context.
//!
//! ## Algorithm
//!
//! 1. Assign fresh type variables to each virtual register
//! 2. Generate type constraints from how values are used
//! 3. Solve constraints via unification
//! 4. Apply the resulting substitution to get concrete types
//!
//! ## References
//!
//! - Hindley, J. R. (1969). The principal type-scheme of an object
//! - Milner, R. (1978). A theory of type polymorphism in programming
//! - Damas & Milner (1982). Principal type-schemes for functional programs

use std::collections::{HashMap, HashSet};

use super::elf::{EbpfProgramType, ProbeContext};
use super::hindley_milner::{
    Constraint, HMType, Substitution, TypeScheme, TypeVar, TypeVarGenerator, UnifyError, unify,
};
use super::instruction::{
    BpfHelper, HelperArgKind, HelperRetKind, HelperSignature, KfuncArgKind, KfuncRetKind,
    KfuncSignature, helper_acquire_ref_kind,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
};
use super::mir::{
    AddressSpace, BasicBlock, BinOpKind, CtxField, MapKind, MirFunction, MirInst, MirType,
    MirValue, STRING_COUNTER_MAP_NAME, StackSlotId, StackSlotKind, StringAppendType, SubfunctionId,
    UnaryOpKind, VReg,
};

mod helper_semantics;
mod ranges;

pub type SubfnSchemeMap = HashMap<SubfunctionId, TypeScheme>;

/// Type inference error
#[derive(Debug, Clone)]
pub struct TypeError {
    pub message: String,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueRange {
    Unset,
    Unknown,
    Known { min: i64, max: i64 },
}

impl ValueRange {
    fn known(min: i64, max: i64) -> Self {
        ValueRange::Known { min, max }
    }

    fn merge(self, other: ValueRange) -> ValueRange {
        match (self, other) {
            (ValueRange::Unset, other) => other,
            (ValueRange::Unknown, _) | (_, ValueRange::Unknown) => ValueRange::Unknown,
            (
                ValueRange::Known { min, max },
                ValueRange::Known {
                    min: omin,
                    max: omax,
                },
            ) => ValueRange::Known {
                min: min.min(omin),
                max: max.max(omax),
            },
            (known, ValueRange::Unset) => known,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackBounds {
    slot: StackSlotId,
    min: i64,
    max: i64,
    limit: i64,
}

impl TypeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {})", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for TypeError {}

impl From<UnifyError> for TypeError {
    fn from(e: UnifyError) -> Self {
        TypeError::new(format!(
            "Type mismatch: expected {}, got {}",
            e.expected, e.actual
        ))
        .with_hint(e.message)
    }
}

/// Hindley-Milner type inference pass for MIR
pub struct TypeInference<'a> {
    /// Type variable generator
    tvar_gen: TypeVarGenerator,
    /// Type variable assigned to each vreg
    vreg_vars: HashMap<VReg, TypeVar>,
    /// Accumulated constraints
    constraints: Vec<Constraint>,
    /// Probe context for determining context field types
    probe_ctx: Option<ProbeContext>,
    /// Current substitution (updated during inference)
    substitution: Substitution,
    /// Subfunction type schemes (if any)
    subfn_schemes: Option<&'a SubfnSchemeMap>,
    /// Type variables for context args (kprobes can be ptr or int)
    ctx_arg_vars: HashMap<usize, TypeVar>,
    /// Type variables for tracepoint fields (field name -> type)
    ctx_tp_vars: HashMap<String, TypeVar>,
    /// Return type variable for the current function
    return_var: Option<TypeVar>,
    /// Expected return type (if constrained externally)
    expected_return: Option<HMType>,
    /// Optional type hints for MIR registers
    type_hints: Option<&'a HashMap<VReg, MirType>>,
}

impl<'a> TypeInference<'a> {
    /// Create a new type inference pass
    pub fn new(probe_ctx: Option<ProbeContext>) -> Self {
        Self::new_with_env(probe_ctx, None, None, None)
    }

    /// Create a new type inference pass with subfunction schemes and optional return type
    pub fn new_with_env(
        probe_ctx: Option<ProbeContext>,
        subfn_schemes: Option<&'a SubfnSchemeMap>,
        expected_return: Option<HMType>,
        type_hints: Option<&'a HashMap<VReg, MirType>>,
    ) -> Self {
        Self {
            tvar_gen: TypeVarGenerator::new(),
            vreg_vars: HashMap::new(),
            constraints: Vec::new(),
            probe_ctx,
            substitution: Substitution::new(),
            subfn_schemes,
            ctx_arg_vars: HashMap::new(),
            ctx_tp_vars: HashMap::new(),
            return_var: None,
            expected_return,
            type_hints,
        }
    }

    /// Run type inference on a MIR function
    ///
    /// Returns the type map on success, or a list of type errors.
    pub fn infer(&mut self, func: &MirFunction) -> Result<HashMap<VReg, MirType>, Vec<TypeError>> {
        let total_vregs = func.vreg_count.max(func.param_count as u32);

        // Phase 1: Assign fresh type variables to all vregs
        for i in 0..total_vregs {
            let vreg = VReg(i);
            let tvar = self.tvar_gen.fresh();
            self.vreg_vars.insert(vreg, tvar);
        }
        self.return_var = Some(self.tvar_gen.fresh());
        if let (Some(ret_var), Some(expected)) = (self.return_var, self.expected_return.clone()) {
            self.constrain(HMType::Var(ret_var), expected, "return_type");
        }

        // Phase 2: Generate constraints from each instruction
        let mut errors = Vec::new();

        if let Some(hints) = self.type_hints {
            for (vreg, mir_ty) in hints {
                if matches!(mir_ty, MirType::Unknown) {
                    continue;
                }
                if let Some(tvar) = self.vreg_vars.get(vreg) {
                    let expected = HMType::Var(*tvar);
                    let actual = HMType::from_mir_type(mir_ty);
                    self.constrain(expected, actual, "type_hint");
                }
            }
        }
        for block in &func.blocks {
            self.generate_block_constraints(block, &mut errors);
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Phase 3: Solve constraints via unification
        for constraint in &self.constraints {
            let t1 = self.substitution.apply(&constraint.expected);
            let t2 = self.substitution.apply(&constraint.actual);

            match unify(&t1, &t2) {
                Ok(s) => {
                    self.substitution = s.compose(&self.substitution);
                }
                Err(e) => {
                    errors.push(
                        TypeError::new(format!("{}: {}", constraint.context, e.message))
                            .with_hint(format!("expected {}, got {}", e.expected, e.actual)),
                    );
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Phase 4: Apply substitution to get final types
        let mut result = HashMap::new();
        for (vreg, tvar) in &self.vreg_vars {
            let hm_type = self.substitution.apply(&HMType::Var(*tvar));
            let mir_type = self.hm_to_mir(&hm_type);
            result.insert(*vreg, mir_type);
        }

        // Phase 5: Validate operations with resolved types
        self.validate_types(func, &result, &mut errors);

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(result)
    }

    /// Generate constraints for a basic block
    fn generate_block_constraints(&mut self, block: &BasicBlock, errors: &mut Vec<TypeError>) {
        for inst in &block.instructions {
            if let Err(e) = self.generate_inst_constraints(inst) {
                errors.push(e);
            }
        }

        if let Err(e) = self.generate_inst_constraints(&block.terminator) {
            errors.push(e);
        }
    }

    /// Generate constraints for a single instruction
    fn generate_inst_constraints(&mut self, inst: &MirInst) -> Result<(), TypeError> {
        match inst {
            MirInst::Copy { dst, src } => {
                // dst has same type as src
                let dst_ty = self.vreg_type(*dst);
                let src_ty = self.value_type(src);
                self.constrain(dst_ty, src_ty, "copy");
            }

            MirInst::Load { dst, ty, .. } => {
                // dst has the specified type
                let dst_ty = self.vreg_type(*dst);
                let expected = HMType::from_mir_type(ty);
                self.constrain(dst_ty, expected, "load");
            }

            MirInst::LoadSlot { dst, ty, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let expected = HMType::from_mir_type(ty);
                self.constrain(dst_ty, expected, "load_slot");
            }

            MirInst::BinOp { dst, op, lhs, rhs } => {
                let dst_ty = self.vreg_type(*dst);
                let lhs_ty = self.value_type(lhs);
                let rhs_ty = self.value_type(rhs);

                // Generate constraints based on operator
                let result_ty = self.binop_result_type(*op, &lhs_ty, &rhs_ty)?;
                self.constrain(dst_ty, result_ty, format!("binop {:?}", op));
            }

            MirInst::UnaryOp { dst, op, src } => {
                let dst_ty = self.vreg_type(*dst);
                let src_ty = self.value_type(src);

                let result_ty = self.unaryop_result_type(*op, &src_ty)?;
                self.constrain(dst_ty, result_ty, format!("unaryop {:?}", op));
            }

            MirInst::CallHelper { dst, helper, .. } => {
                let dst_ty = self.vreg_type(*dst);
                if let Some(sig) = HelperSignature::for_id(*helper) {
                    match sig.ret_kind {
                        HelperRetKind::Scalar => {
                            self.constrain(dst_ty, HMType::I64, "helper_call");
                        }
                        HelperRetKind::PointerMaybeNull => {
                            let pointee = HMType::Var(self.tvar_gen.fresh());
                            let address_space = match BpfHelper::from_u32(*helper) {
                                Some(BpfHelper::KptrXchg) => AddressSpace::Kernel,
                                Some(helper) if helper_acquire_ref_kind(helper).is_some() => {
                                    AddressSpace::Kernel
                                }
                                _ => AddressSpace::Map,
                            };
                            let ptr_ty = HMType::Ptr {
                                pointee: Box::new(pointee),
                                address_space,
                            };
                            self.constrain(dst_ty, ptr_ty, "helper_call_ptr_ret");
                        }
                    }
                } else {
                    // Unknown helpers default to scalar return.
                    self.constrain(dst_ty, HMType::I64, "helper_call");
                }
            }

            MirInst::CallKfunc { dst, kfunc, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let sig = KfuncSignature::for_name(kfunc).ok_or_else(|| {
                    TypeError::new(format!(
                        "unknown kfunc '{}' (typed signature required)",
                        kfunc
                    ))
                })?;
                match sig.ret_kind {
                    KfuncRetKind::Scalar | KfuncRetKind::Void => {
                        self.constrain(dst_ty, HMType::I64, "kfunc_call");
                    }
                    KfuncRetKind::PointerMaybeNull => {
                        let pointee = HMType::Var(self.tvar_gen.fresh());
                        let ptr_ty = HMType::Ptr {
                            pointee: Box::new(pointee),
                            address_space: AddressSpace::Kernel,
                        };
                        self.constrain(dst_ty, ptr_ty, "kfunc_call_ptr_ret");
                    }
                }
            }

            MirInst::CallSubfn { dst, subfn, args } => {
                let dst_ty = self.vreg_type(*dst);
                let scheme = self
                    .subfn_schemes
                    .and_then(|env| env.get(subfn))
                    .ok_or_else(|| TypeError::new(format!("Unknown subfunction ID {:?}", subfn)))?;
                let inst = scheme.instantiate(&mut self.tvar_gen);
                match inst {
                    HMType::Fn {
                        args: expected_args,
                        ret,
                    } => {
                        if expected_args.len() != args.len() {
                            return Err(TypeError::new(format!(
                                "Subfunction {:?} expects {} args, got {}",
                                subfn,
                                expected_args.len(),
                                args.len()
                            )));
                        }
                        for (arg_vreg, expected) in args.iter().zip(expected_args.iter()) {
                            let arg_ty = self.vreg_type(*arg_vreg);
                            self.constrain(arg_ty, expected.clone(), "subfn_arg");
                        }
                        self.constrain(dst_ty, *ret, "subfn_ret");
                    }
                    _ => {
                        return Err(TypeError::new(format!(
                            "Subfunction scheme is not a function type: {}",
                            inst
                        )));
                    }
                }
            }

            MirInst::MapLookup { dst, .. } => {
                // Map lookup returns pointer to value
                let dst_ty = self.vreg_type(*dst);
                let pointee = HMType::Var(self.tvar_gen.fresh());
                let ptr_ty = HMType::Ptr {
                    pointee: Box::new(pointee),
                    address_space: AddressSpace::Map,
                };
                self.constrain(dst_ty, ptr_ty, "map_lookup");
            }

            MirInst::LoadCtxField { dst, field, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let field_ty = self.ctx_field_type(field);
                self.constrain(dst_ty, field_ty, format!("ctx.{:?}", field));
            }

            MirInst::StrCmp { dst, .. } => {
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::Bool, "strcmp");
            }

            MirInst::StopTimer { dst } => {
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::U64, "stop_timer");
            }

            MirInst::LoopHeader { counter, .. } => {
                let counter_ty = self.vreg_type(*counter);
                self.constrain(counter_ty, HMType::I64, "loop_counter");
            }

            MirInst::ListNew { dst, .. } => {
                // List pointer is essentially a pointer to stack (list buffer)
                let dst_ty = self.vreg_type(*dst);
                let list_ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::I64),
                    address_space: AddressSpace::Stack,
                };
                self.constrain(dst_ty, list_ptr_ty, "list_new");
            }

            MirInst::ListLen { dst, list } => {
                // Length is u64
                let dst_ty = self.vreg_type(*dst);
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::I64),
                    address_space: AddressSpace::Stack,
                };
                self.constrain(dst_ty, HMType::U64, "list_len");
                self.constrain(list_ty, list_ptr_ty, "list_len_src");
            }

            MirInst::ListGet { dst, list, .. } => {
                // Element is i64 (all values stored as 64-bit)
                let dst_ty = self.vreg_type(*dst);
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::I64),
                    address_space: AddressSpace::Stack,
                };
                self.constrain(dst_ty, HMType::I64, "list_get");
                self.constrain(list_ty, list_ptr_ty, "list_get_src");
            }

            MirInst::Phi { dst, args } => {
                // Phi destination has same type as all its arguments
                let dst_ty = self.vreg_type(*dst);
                for (_, arg_vreg) in args {
                    let arg_ty = self.vreg_type(*arg_vreg);
                    self.constrain(dst_ty.clone(), arg_ty, "phi");
                }
            }

            MirInst::ReadStr {
                ptr, user_space, ..
            } => {
                let ptr_ty = self.vreg_type(*ptr);
                let expected = HMType::Ptr {
                    pointee: Box::new(HMType::U8),
                    address_space: if *user_space {
                        AddressSpace::User
                    } else {
                        AddressSpace::Kernel
                    },
                };
                self.constrain(ptr_ty, expected, "read_str_ptr");
            }

            MirInst::StringAppend {
                dst_len,
                val,
                val_type,
                ..
            } => {
                let len_ty = self.vreg_type(*dst_len);
                self.constrain(len_ty, HMType::U64, "string_len");
                if matches!(val_type, StringAppendType::Integer) {
                    let val_ty = self.value_type(val);
                    self.constrain(val_ty, HMType::I64, "string_append_int");
                }
            }

            MirInst::IntToString { dst_len, val, .. } => {
                let len_ty = self.vreg_type(*dst_len);
                self.constrain(len_ty, HMType::U64, "int_to_string_len");
                let val_ty = self.vreg_type(*val);
                self.constrain(val_ty, HMType::I64, "int_to_string_val");
            }

            MirInst::ListPush { list, item } => {
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::I64),
                    address_space: AddressSpace::Stack,
                };
                let item_ty = self.vreg_type(*item);
                self.constrain(list_ty, list_ptr_ty, "list_push_list");
                self.constrain(item_ty, HMType::I64, "list_push_item");
            }

            MirInst::Return { val } => {
                if let (Some(ret_var), Some(value)) = (self.return_var, val.as_ref()) {
                    let value_ty = self.value_type(value);
                    self.constrain(HMType::Var(ret_var), value_ty, "return");
                }
            }

            // Instructions that don't define a vreg - no constraints needed
            MirInst::Store { .. }
            | MirInst::StoreSlot { .. }
            | MirInst::MapUpdate { .. }
            | MirInst::MapDelete { .. }
            | MirInst::Histogram { .. }
            | MirInst::StartTimer
            | MirInst::EmitEvent { .. }
            | MirInst::EmitRecord { .. }
            | MirInst::RecordStore { .. }
            | MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopBack { .. }
            | MirInst::Placeholder => {}
        }

        Ok(())
    }

    /// Get the type variable for a vreg as an HMType
    fn vreg_type(&self, vreg: VReg) -> HMType {
        if let Some(&tvar) = self.vreg_vars.get(&vreg) {
            HMType::Var(tvar)
        } else {
            HMType::Unknown
        }
    }

    /// Get the type of a MirValue
    fn value_type(&mut self, value: &MirValue) -> HMType {
        match value {
            MirValue::VReg(vreg) => self.vreg_type(*vreg),
            MirValue::Const(_) => HMType::I64,
            MirValue::StackSlot(_) => HMType::Ptr {
                pointee: Box::new(HMType::U8),
                address_space: AddressSpace::Stack,
            },
        }
    }

    fn constrain(&mut self, expected: HMType, actual: HMType, context: impl Into<String>) {
        self.constraints
            .push(Constraint::new(expected, actual, context));
    }

    fn validate_types(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        errors: &mut Vec<TypeError>,
    ) {
        let list_caps = self.compute_list_caps(func);
        let value_ranges = self.compute_value_ranges(func, types, &list_caps);
        let stack_bounds = self.compute_stack_bounds(func, types, &value_ranges);
        let slot_sizes: HashMap<StackSlotId, i64> = func
            .stack_slots
            .iter()
            .map(|slot| (slot.id, slot.size as i64))
            .collect();

        for block in &func.blocks {
            for inst in &block.instructions {
                self.validate_inst(
                    inst,
                    types,
                    &value_ranges,
                    &stack_bounds,
                    &slot_sizes,
                    errors,
                );
            }
            self.validate_inst(
                &block.terminator,
                types,
                &value_ranges,
                &stack_bounds,
                &slot_sizes,
                errors,
            );
        }
    }

    fn validate_inst(
        &self,
        inst: &MirInst,
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
        stack_bounds: &HashMap<VReg, StackBounds>,
        slot_sizes: &HashMap<StackSlotId, i64>,
        errors: &mut Vec<TypeError>,
    ) {
        match inst {
            MirInst::BinOp { op, lhs, rhs, .. } => {
                let lhs_ty = self.mir_type_for_value(lhs, types);
                let rhs_ty = self.mir_type_for_value(rhs, types);
                let lhs_ptr = Self::mir_ptr_space(&lhs_ty);
                let rhs_ptr = Self::mir_ptr_space(&rhs_ty);

                match op {
                    BinOpKind::Eq | BinOpKind::Ne => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            match (lhs_ptr, rhs_ptr) {
                                (Some(lhs_space), Some(rhs_space)) => {
                                    if lhs_space != rhs_space {
                                        errors.push(TypeError::new(format!(
                                            "pointer comparison requires same address space (lhs={:?}, rhs={:?})",
                                            lhs_space, rhs_space
                                        )));
                                    }
                                }
                                (Some(_), None) => {
                                    if !Self::is_const_zero(rhs) {
                                        errors.push(TypeError::new(
                                            "pointer comparison only supports null (0) constants"
                                                .to_string(),
                                        ));
                                    }
                                }
                                (None, Some(_)) => {
                                    if !Self::is_const_zero(lhs) {
                                        errors.push(TypeError::new(
                                            "pointer comparison only supports null (0) constants"
                                                .to_string(),
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "comparison expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            errors.push(TypeError::new(
                                "ordering comparisons on pointers are not supported".to_string(),
                            ));
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "comparison expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                    BinOpKind::Add | BinOpKind::Sub => {
                        let is_add = matches!(op, BinOpKind::Add);
                        match (lhs_ptr, rhs_ptr) {
                            (Some(_), Some(_)) => {
                                errors.push(TypeError::new(
                                    "pointer + pointer arithmetic is not supported".to_string(),
                                ));
                            }
                            (Some(space), None) => {
                                if !Self::mir_is_numeric(&rhs_ty) {
                                    errors.push(TypeError::new(format!(
                                        "pointer arithmetic expects numeric offset, got {:?}",
                                        rhs_ty
                                    )));
                                } else if let Err(msg) = self.pointer_arith_check(
                                    space,
                                    self.stack_bounds_for_value(lhs, stack_bounds),
                                    rhs,
                                    is_add,
                                    value_ranges,
                                ) {
                                    errors.push(TypeError::new(msg));
                                }
                            }
                            (None, Some(space)) => {
                                if !is_add {
                                    errors.push(TypeError::new(
                                        "numeric - pointer is not supported".to_string(),
                                    ));
                                } else if !Self::mir_is_numeric(&lhs_ty) {
                                    errors.push(TypeError::new(format!(
                                        "pointer arithmetic expects numeric offset, got {:?}",
                                        lhs_ty
                                    )));
                                } else if let Err(msg) = self.pointer_arith_check(
                                    space,
                                    self.stack_bounds_for_value(rhs, stack_bounds),
                                    lhs,
                                    true,
                                    value_ranges,
                                ) {
                                    errors.push(TypeError::new(msg));
                                }
                            }
                            (None, None) => {
                                if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty)
                                {
                                    errors.push(TypeError::new(format!(
                                        "arithmetic expects numeric types, got {:?} and {:?}",
                                        lhs_ty, rhs_ty
                                    )));
                                }
                            }
                        }
                    }
                    BinOpKind::Mul
                    | BinOpKind::Div
                    | BinOpKind::Mod
                    | BinOpKind::And
                    | BinOpKind::Or
                    | BinOpKind::Xor
                    | BinOpKind::Shl
                    | BinOpKind::Shr => {
                        if lhs_ptr.is_some() || rhs_ptr.is_some() {
                            errors.push(TypeError::new(
                                "bitwise/arithmetic ops on pointers are not supported".to_string(),
                            ));
                        } else if !Self::mir_is_numeric(&lhs_ty) || !Self::mir_is_numeric(&rhs_ty) {
                            errors.push(TypeError::new(format!(
                                "operation expects numeric types, got {:?} and {:?}",
                                lhs_ty, rhs_ty
                            )));
                        }
                    }
                }
            }

            MirInst::UnaryOp { op, src, .. } => {
                let src_ty = self.mir_type_for_value(src, types);
                if Self::mir_ptr_space(&src_ty).is_some() {
                    errors.push(TypeError::new(format!(
                        "unary {:?} is not supported for pointers",
                        op
                    )));
                } else if !Self::mir_is_numeric(&src_ty) {
                    errors.push(TypeError::new(format!(
                        "unary {:?} expects numeric type, got {:?}",
                        op, src_ty
                    )));
                }
            }

            MirInst::ReadStr {
                ptr, user_space, ..
            } => {
                let ptr_ty = self.mir_type_for_vreg(*ptr, types);
                match ptr_ty {
                    MirType::Ptr { address_space, .. } => {
                        let expected = if *user_space {
                            AddressSpace::User
                        } else {
                            AddressSpace::Kernel
                        };
                        if address_space != expected {
                            errors.push(TypeError::new(format!(
                                "read_str expects {:?} pointer, got {:?}",
                                expected, address_space
                            )));
                        }
                    }
                    _ => {
                        errors.push(TypeError::new(format!(
                            "read_str expects pointer, got {:?}",
                            ptr_ty
                        )));
                    }
                }
            }

            MirInst::EmitEvent { data, size } => {
                if *size > 8 {
                    let data_ty = self.mir_type_for_vreg(*data, types);
                    match data_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "emit event of size {} expects stack/map pointer, got {:?}",
                            size, data_ty
                        ))),
                    }
                }
            }

            MirInst::EmitRecord { fields } => {
                for field in fields {
                    let size = Self::record_field_size(&field.ty);
                    let value_ty = self.mir_type_for_vreg(field.value, types);
                    if size > 8 {
                        match value_ty {
                            MirType::Ptr { address_space, .. }
                                if matches!(
                                    address_space,
                                    AddressSpace::Stack | AddressSpace::Map
                                ) => {}
                            _ => errors.push(TypeError::new(format!(
                                "record field '{}' expects pointer value, got {:?}",
                                field.name, value_ty
                            ))),
                        }
                    } else if !Self::mir_is_numeric(&value_ty) {
                        errors.push(TypeError::new(format!(
                            "record field '{}' expects numeric value, got {:?}",
                            field.name, value_ty
                        )));
                    }
                }
            }

            MirInst::RecordStore { val, ty, .. } => {
                let size = ty.size();
                let value_ty = self.mir_type_for_value(val, types);
                if size > 8 {
                    match value_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "record store expects pointer for {:?}, got {:?}",
                            ty, value_ty
                        ))),
                    }
                } else if !Self::mir_is_numeric(&value_ty) {
                    errors.push(TypeError::new(format!(
                        "record store expects numeric value for {:?}, got {:?}",
                        ty, value_ty
                    )));
                }
            }

            MirInst::MapUpdate { map, key, val, .. } => {
                let key_ty = self.mir_type_for_vreg(*key, types);
                if map.name == STRING_COUNTER_MAP_NAME {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' expects string pointer key, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                } else {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ if Self::mir_is_numeric(&key_ty) => {}
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' key expects numeric or stack/map pointer, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                }

                let val_ty = self.mir_type_for_vreg(*val, types);
                match val_ty {
                    MirType::Ptr { address_space, .. }
                        if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {}
                    _ if Self::mir_is_numeric(&val_ty) => {}
                    _ => errors.push(TypeError::new(format!(
                        "map '{}' value expects numeric or stack/map pointer, got {:?}",
                        map.name, val_ty
                    ))),
                }
            }

            MirInst::MapDelete { map, key } => {
                let key_ty = self.mir_type_for_vreg(*key, types);
                if map.name == STRING_COUNTER_MAP_NAME {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' expects string pointer key, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                } else {
                    match key_ty {
                        MirType::Ptr { address_space, .. }
                            if matches!(address_space, AddressSpace::Stack | AddressSpace::Map) => {
                        }
                        _ if Self::mir_is_numeric(&key_ty) => {}
                        _ => errors.push(TypeError::new(format!(
                            "map '{}' key expects numeric or stack/map pointer, got {:?}",
                            map.name, key_ty
                        ))),
                    }
                }
            }

            MirInst::Histogram { value } => {
                let value_ty = self.mir_type_for_vreg(*value, types);
                if !Self::mir_is_numeric(&value_ty) {
                    errors.push(TypeError::new(format!(
                        "histogram expects numeric value, got {:?}",
                        value_ty
                    )));
                }
            }

            MirInst::ListPush { list, item } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
                let item_ty = self.mir_type_for_vreg(*item, types);
                if !Self::mir_is_numeric(&item_ty) {
                    errors.push(TypeError::new(format!(
                        "list push expects numeric item, got {:?}",
                        item_ty
                    )));
                }
            }

            MirInst::ListLen { list, .. } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
            }

            MirInst::ListGet { list, idx, .. } => {
                let list_ty = self.mir_type_for_vreg(*list, types);
                if !matches!(
                    list_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    errors.push(TypeError::new(format!(
                        "list expects stack pointer, got {:?}",
                        list_ty
                    )));
                }
                let idx_ty = self.mir_type_for_value(idx, types);
                if !Self::mir_is_numeric(&idx_ty) {
                    errors.push(TypeError::new(format!(
                        "list index expects numeric type, got {:?}",
                        idx_ty
                    )));
                }
            }

            MirInst::StringAppend {
                dst_len,
                val,
                val_type,
                ..
            } => {
                let len_ty = self.mir_type_for_vreg(*dst_len, types);
                if !Self::mir_is_numeric(&len_ty) {
                    errors.push(TypeError::new(format!(
                        "string append length expects numeric type, got {:?}",
                        len_ty
                    )));
                }
                if matches!(val_type, StringAppendType::Integer) {
                    let val_ty = self.mir_type_for_value(val, types);
                    if !Self::mir_is_numeric(&val_ty) {
                        errors.push(TypeError::new(format!(
                            "string append integer expects numeric type, got {:?}",
                            val_ty
                        )));
                    }
                }
            }

            MirInst::IntToString { dst_len, val, .. } => {
                let len_ty = self.mir_type_for_vreg(*dst_len, types);
                if !Self::mir_is_numeric(&len_ty) {
                    errors.push(TypeError::new(format!(
                        "int to string length expects numeric type, got {:?}",
                        len_ty
                    )));
                }
                let val_ty = self.mir_type_for_vreg(*val, types);
                if !Self::mir_is_numeric(&val_ty) {
                    errors.push(TypeError::new(format!(
                        "int to string expects numeric value, got {:?}",
                        val_ty
                    )));
                }
            }

            MirInst::Branch { cond, .. } => {
                let cond_ty = self.mir_type_for_vreg(*cond, types);
                if !Self::mir_is_numeric(&cond_ty) && Self::mir_ptr_space(&cond_ty).is_none() {
                    errors.push(TypeError::new(format!(
                        "branch condition expects numeric or pointer, got {:?}",
                        cond_ty
                    )));
                }
            }

            MirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    errors.push(TypeError::new(format!(
                        "tail call requires ProgArray map kind, got {:?} for '{}'",
                        prog_map.kind, prog_map.name
                    )));
                }
                let idx_ty = self.mir_type_for_value(index, types);
                if !Self::mir_is_numeric(&idx_ty) {
                    errors.push(TypeError::new(format!(
                        "tail call index expects numeric type, got {:?}",
                        idx_ty
                    )));
                }
            }

            MirInst::CallHelper { helper, args, .. } => {
                if let Some(sig) = HelperSignature::for_id(*helper) {
                    if args.len() < sig.min_args || args.len() > sig.max_args {
                        errors.push(TypeError::new(format!(
                            "helper {} expects {}..={} arguments, got {}",
                            helper,
                            sig.min_args,
                            sig.max_args,
                            args.len()
                        )));
                    }
                    for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                        let arg_ty = self.mir_type_for_value(arg, types);
                        match sig.arg_kind(idx) {
                            HelperArgKind::Scalar => {
                                if !Self::mir_is_numeric(&arg_ty) {
                                    errors.push(TypeError::new(format!(
                                        "helper {} arg{} expects scalar, got {:?}",
                                        helper, idx, arg_ty
                                    )));
                                }
                            }
                            HelperArgKind::Pointer => {
                                let is_const_zero = matches!(arg, MirValue::Const(0));
                                if !matches!(arg_ty, MirType::Ptr { .. })
                                    && !(is_const_zero
                                        && Self::helper_pointer_arg_allows_const_zero(*helper, idx))
                                {
                                    errors.push(TypeError::new(format!(
                                        "helper {} arg{} expects pointer, got {:?}",
                                        helper, idx, arg_ty
                                    )));
                                }
                            }
                        }
                    }
                    self.validate_helper_semantics(
                        *helper,
                        args,
                        types,
                        value_ranges,
                        stack_bounds,
                        slot_sizes,
                        errors,
                    );
                } else if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF helpers support at most 5 arguments".to_string(),
                    ));
                }
            }

            MirInst::CallKfunc { kfunc, args, .. } => {
                let Some(sig) = KfuncSignature::for_name(kfunc) else {
                    errors.push(TypeError::new(format!(
                        "unknown kfunc '{}' (typed signature required)",
                        kfunc
                    )));
                    return;
                };
                if args.len() < sig.min_args || args.len() > sig.max_args {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' expects {}..={} arguments, got {}",
                        kfunc,
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    )));
                }
                if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF kfunc calls support at most 5 arguments".to_string(),
                    ));
                }
                for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                    let arg_ty = self.mir_type_for_vreg(*arg, types);
                    match sig.arg_kind(idx) {
                        KfuncArgKind::Scalar => {
                            if !Self::mir_is_numeric(&arg_ty) {
                                errors.push(TypeError::new(format!(
                                    "kfunc '{}' arg{} expects scalar, got {:?}",
                                    kfunc, idx, arg_ty
                                )));
                            }
                        }
                        KfuncArgKind::Pointer => match arg_ty {
                            MirType::Ptr { address_space, .. } => {
                                if Self::kfunc_pointer_arg_requires_kernel(kfunc, idx)
                                    && address_space != AddressSpace::Kernel
                                {
                                    errors.push(TypeError::new(format!(
                                        "kfunc '{}' arg{} expects kernel pointer, got {:?}",
                                        kfunc, idx, address_space
                                    )));
                                }
                            }
                            _ => {
                                errors.push(TypeError::new(format!(
                                    "kfunc '{}' arg{} expects pointer, got {:?}",
                                    kfunc, idx, arg_ty
                                )));
                            }
                        },
                    }
                }
            }

            MirInst::CallSubfn { args, .. } => {
                if args.len() > 5 {
                    errors.push(TypeError::new(
                        "BPF subfunctions support at most 5 arguments".to_string(),
                    ));
                }
            }

            _ => {}
        }
    }

    fn pointer_arith_check(
        &self,
        space: AddressSpace,
        base_bounds: Option<&StackBounds>,
        offset: &MirValue,
        is_add: bool,
        value_ranges: &HashMap<VReg, ValueRange>,
    ) -> Result<(), String> {
        match space {
            AddressSpace::Stack => {
                if Self::const_value(offset).is_some() {
                    return Ok(());
                }
                let Some(bounds) = base_bounds else {
                    return Err("stack pointer arithmetic requires constant offsets".to_string());
                };
                match self.value_range_for(offset, value_ranges) {
                    ValueRange::Known { min, max } => {
                        if min < 0 {
                            return Err("stack pointer arithmetic requires non-negative offsets"
                                .to_string());
                        }
                        let (new_min, new_max) = if is_add {
                            (bounds.min + min, bounds.max + max)
                        } else {
                            (bounds.min - max, bounds.max - min)
                        };
                        if new_min < 0 || new_max > bounds.limit {
                            return Err(format!(
                                "stack pointer arithmetic offset range [{}..{}] exceeds bounds [0..{}]",
                                new_min, new_max, bounds.limit
                            ));
                        }
                        Ok(())
                    }
                    ValueRange::Unknown | ValueRange::Unset => Err(
                        "stack pointer arithmetic requires constant or bounded offsets".to_string(),
                    ),
                }
            }
            AddressSpace::Map => Ok(()),
            _ => Err(format!(
                "pointer arithmetic not supported for {:?} pointers",
                space
            )),
        }
    }

    fn ctx_field_type(&mut self, field: &CtxField) -> HMType {
        match field {
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Cpu => {
                HMType::U32
            }

            CtxField::Timestamp => HMType::U64,

            CtxField::Arg(idx) => {
                if self.is_userspace_probe() {
                    HMType::Ptr {
                        pointee: Box::new(HMType::U8),
                        address_space: AddressSpace::User,
                    }
                } else {
                    let tvar = *self
                        .ctx_arg_vars
                        .entry(*idx as usize)
                        .or_insert_with(|| self.tvar_gen.fresh());
                    HMType::Var(tvar)
                }
            }

            CtxField::RetVal => HMType::I64,
            CtxField::KStack | CtxField::UStack => HMType::I64,

            CtxField::Comm => HMType::Ptr {
                pointee: Box::new(HMType::Array {
                    elem: Box::new(HMType::U8),
                    len: 16,
                }),
                address_space: AddressSpace::Stack,
            },

            CtxField::TracepointField(name) => {
                let tvar = *self
                    .ctx_tp_vars
                    .entry(name.clone())
                    .or_insert_with(|| self.tvar_gen.fresh());
                HMType::Var(tvar)
            }
        }
    }

    /// Check if the current probe is a userspace probe
    fn is_userspace_probe(&self) -> bool {
        self.probe_ctx
            .as_ref()
            .map(|ctx| {
                matches!(
                    ctx.probe_type,
                    EbpfProgramType::Uprobe | EbpfProgramType::Uretprobe
                )
            })
            .unwrap_or(false)
    }

    /// Determine result type of a binary operation
    fn binop_result_type(
        &mut self,
        op: BinOpKind,
        lhs: &HMType,
        rhs: &HMType,
    ) -> Result<HMType, TypeError> {
        // Comparison operators return bool
        if matches!(
            op,
            BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge
        ) {
            // Add constraint that operands are comparable
            // For now, we allow comparing any types and check at unification
            return Ok(HMType::Bool);
        }

        // Arithmetic operations
        match op {
            BinOpKind::Add | BinOpKind::Sub => {
                // Pointer arithmetic: ptr + int -> ptr
                if let HMType::Ptr { .. } = lhs {
                    return Ok(lhs.clone());
                }
                // Regular arithmetic - result is larger type
                Ok(self.promote_numeric(lhs, rhs))
            }

            BinOpKind::Mul | BinOpKind::Div | BinOpKind::Mod => Ok(self.promote_numeric(lhs, rhs)),

            BinOpKind::And | BinOpKind::Or | BinOpKind::Xor => Ok(self.promote_numeric(lhs, rhs)),

            BinOpKind::Shl | BinOpKind::Shr => {
                // Shift result type is lhs type
                Ok(lhs.clone())
            }

            _ => Ok(HMType::I64),
        }
    }

    /// Determine result type of a unary operation
    fn unaryop_result_type(&self, op: UnaryOpKind, src: &HMType) -> Result<HMType, TypeError> {
        match op {
            UnaryOpKind::Not => Ok(HMType::Bool),
            UnaryOpKind::BitNot | UnaryOpKind::Neg => Ok(src.clone()),
        }
    }

    /// Promote two numeric types to a common type
    fn promote_numeric(&self, lhs: &HMType, rhs: &HMType) -> HMType {
        // If either is a type variable, return I64 as default
        if matches!(lhs, HMType::Var(_)) || matches!(rhs, HMType::Var(_)) {
            return HMType::I64;
        }

        // If either is unknown, return I64
        if matches!(lhs, HMType::Unknown) || matches!(rhs, HMType::Unknown) {
            return HMType::I64;
        }

        // Get sizes
        let lhs_size = self.type_size(lhs);
        let rhs_size = self.type_size(rhs);

        // Prefer signed if either is signed
        let is_signed = self.is_signed(lhs) || self.is_signed(rhs);
        let size = lhs_size.max(rhs_size);

        if is_signed {
            match size {
                1 => HMType::I8,
                2 => HMType::I16,
                4 => HMType::I32,
                _ => HMType::I64,
            }
        } else {
            match size {
                1 => HMType::U8,
                2 => HMType::U16,
                4 => HMType::U32,
                _ => HMType::U64,
            }
        }
    }

    fn type_size(&self, ty: &HMType) -> usize {
        match ty {
            HMType::I8 | HMType::U8 | HMType::Bool => 1,
            HMType::I16 | HMType::U16 => 2,
            HMType::I32 | HMType::U32 => 4,
            HMType::I64 | HMType::U64 => 8,
            _ => 8,
        }
    }

    fn is_signed(&self, ty: &HMType) -> bool {
        matches!(ty, HMType::I8 | HMType::I16 | HMType::I32 | HMType::I64)
    }

    fn hm_type_for_vreg(&self, vreg: VReg) -> HMType {
        self.substitution.apply(&self.vreg_type(vreg))
    }

    fn hm_return_type(&self) -> HMType {
        match self.return_var {
            Some(var) => self.substitution.apply(&HMType::Var(var)),
            None => HMType::Unknown,
        }
    }

    fn scheme_for_function(&self, func: &MirFunction, env: Option<&SubfnSchemeMap>) -> TypeScheme {
        let args: Vec<HMType> = (0..func.param_count)
            .map(|i| self.hm_type_for_vreg(VReg(i as u32)))
            .collect();
        let ret = self.hm_return_type();
        let ty = HMType::Fn {
            args,
            ret: Box::new(ret),
        };
        let env_vars = env.map(env_free_vars).unwrap_or_default();
        let ty_vars = ty.free_vars();
        let quantified = ty_vars.difference(&env_vars).copied().collect();
        TypeScheme { quantified, ty }
    }

    /// Convert HMType to MirType
    fn hm_to_mir(&self, ty: &HMType) -> MirType {
        // Apply current substitution first
        let resolved = self.substitution.apply(ty);

        match resolved {
            HMType::Var(_) => MirType::I64, // Unresolved var defaults to I64
            HMType::I8 => MirType::I8,
            HMType::I16 => MirType::I16,
            HMType::I32 => MirType::I32,
            HMType::I64 => MirType::I64,
            HMType::U8 => MirType::U8,
            HMType::U16 => MirType::U16,
            HMType::U32 => MirType::U32,
            HMType::U64 => MirType::U64,
            HMType::Bool => MirType::Bool,
            HMType::Ptr {
                pointee,
                address_space,
            } => MirType::Ptr {
                pointee: Box::new(self.hm_to_mir(&pointee)),
                address_space,
            },
            HMType::Array { elem, len } => MirType::Array {
                elem: Box::new(self.hm_to_mir(&elem)),
                len,
            },
            HMType::Struct { name, fields } => {
                let mut mir_fields = Vec::new();
                let mut offset = 0;
                for (field_name, field_ty) in fields {
                    let mir_ty = self.hm_to_mir(&field_ty);
                    let size = mir_ty.size();
                    mir_fields.push(super::mir::StructField {
                        name: field_name,
                        ty: mir_ty,
                        offset,
                    });
                    offset += size;
                }
                MirType::Struct {
                    name,
                    fields: mir_fields,
                }
            }
            HMType::MapRef { key_ty, val_ty } => MirType::MapRef {
                key_ty: Box::new(self.hm_to_mir(&key_ty)),
                val_ty: Box::new(self.hm_to_mir(&val_ty)),
            },
            HMType::Fn { .. } => MirType::I64, // Functions not in MirType
            HMType::Unknown => MirType::Unknown,
        }
    }

    /// Get the type for a vreg (after inference)
    pub fn get_type(&self, vreg: VReg) -> Option<MirType> {
        let tvar = self.vreg_vars.get(&vreg)?;
        let hm_type = self.substitution.apply(&HMType::Var(*tvar));
        Some(self.hm_to_mir(&hm_type))
    }

    /// Get all inferred types
    pub fn types(&self) -> HashMap<VReg, MirType> {
        let mut result = HashMap::new();
        for (vreg, tvar) in &self.vreg_vars {
            let hm_type = self.substitution.apply(&HMType::Var(*tvar));
            result.insert(*vreg, self.hm_to_mir(&hm_type));
        }
        result
    }
}

fn env_free_vars(env: &SubfnSchemeMap) -> HashSet<TypeVar> {
    let mut vars = HashSet::new();
    for scheme in env.values() {
        vars.extend(scheme.free_vars());
    }
    vars
}

fn collect_subfn_calls(func: &MirFunction) -> Vec<SubfunctionId> {
    let mut calls = Vec::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            if let MirInst::CallSubfn { subfn, .. } = inst {
                calls.push(*subfn);
            }
        }
        if let MirInst::CallSubfn { subfn, .. } = &block.terminator {
            calls.push(*subfn);
        }
    }
    calls
}

fn topo_sort_subfunctions(graph: &[Vec<usize>]) -> Result<Vec<usize>, TypeError> {
    fn dfs(
        node: usize,
        graph: &[Vec<usize>],
        state: &mut [u8],
        stack: &mut Vec<usize>,
        order: &mut Vec<usize>,
    ) -> Result<(), TypeError> {
        match state[node] {
            1 => {
                let mut cycle = stack.clone();
                cycle.push(node);
                let cycle_ids: Vec<String> = cycle
                    .into_iter()
                    .map(|idx| format!("subfn{}", idx))
                    .collect();
                return Err(TypeError::new(format!(
                    "recursive subfunction call detected: {} (polymorphic recursion requires explicit type annotations and is not currently supported)",
                    cycle_ids.join(" -> ")
                )));
            }
            2 => return Ok(()),
            _ => {}
        }

        state[node] = 1;
        stack.push(node);
        for &next in &graph[node] {
            dfs(next, graph, state, stack, order)?;
        }
        stack.pop();
        state[node] = 2;
        order.push(node);
        Ok(())
    }

    let mut state = vec![0u8; graph.len()];
    let mut order = Vec::new();
    let mut stack = Vec::new();

    for node in 0..graph.len() {
        if state[node] == 0 {
            dfs(node, graph, &mut state, &mut stack, &mut order)?;
        }
    }

    order.reverse();
    Ok(order)
}

pub fn infer_subfunction_schemes(
    subfunctions: &[MirFunction],
    probe_ctx: Option<ProbeContext>,
) -> Result<SubfnSchemeMap, Vec<TypeError>> {
    let mut errors = Vec::new();
    let mut graph = vec![Vec::new(); subfunctions.len()];

    for (idx, func) in subfunctions.iter().enumerate() {
        if func.param_count > 5 {
            errors.push(TypeError::new(format!(
                "BPF subfunctions support at most 5 arguments, got {} for subfn{}",
                func.param_count, idx
            )));
        }
        for subfn in collect_subfn_calls(func) {
            let target = subfn.0 as usize;
            if target >= subfunctions.len() {
                errors.push(TypeError::new(format!(
                    "Unknown subfunction ID {:?}",
                    subfn
                )));
            } else {
                graph[idx].push(target);
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let order = match topo_sort_subfunctions(&graph) {
        Ok(order) => order,
        Err(err) => return Err(vec![err]),
    };

    let mut schemes: SubfnSchemeMap = HashMap::new();

    for idx in order {
        let subfn_id = SubfunctionId(idx as u32);
        let func = &subfunctions[idx];
        let mut ti = TypeInference::new_with_env(probe_ctx.clone(), Some(&schemes), None, None);
        match ti.infer(func) {
            Ok(_) => {
                let scheme = ti.scheme_for_function(func, Some(&schemes));
                schemes.insert(subfn_id, scheme);
            }
            Err(errs) => return Err(errs),
        }
    }

    Ok(schemes)
}

#[cfg(test)]
mod tests;
