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
mod subfunctions;
mod typing;
mod validate;

pub type SubfnSchemeMap = HashMap<SubfunctionId, TypeScheme>;
pub use subfunctions::infer_subfunction_schemes;

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
}

#[cfg(test)]
mod tests;
