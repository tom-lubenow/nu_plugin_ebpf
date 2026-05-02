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

use super::ctx_field_schema::{synthetic_bpf_sock_type, synthetic_bpf_tcp_sock_type};
use super::elf::{ProbeContext, ProgramCapability, ProgramTypeInfo};
use super::hindley_milner::{
    Constraint, HMType, Substitution, TypeScheme, TypeVar, TypeVarGenerator, UnifyError, unify,
};
use super::instruction::{
    BpfHelper, HelperArgKind, HelperRetKind, HelperSignature, KfuncArgKind, KfuncRetKind,
    KfuncSignature, KfuncUnknownDynptrCopy, KfuncUnknownStackObjectCopy, helper_acquire_ref_kind,
    kfunc_pointer_arg_allows_const_zero as kfunc_pointer_arg_allows_const_zero_shared,
    kfunc_pointer_arg_fixed_size as kfunc_pointer_arg_fixed_size_shared,
    kfunc_pointer_arg_min_access_size as kfunc_pointer_arg_min_access_size_shared,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
    kfunc_pointer_arg_requires_stack as kfunc_pointer_arg_requires_stack_shared,
    kfunc_pointer_arg_requires_stack_or_map as kfunc_pointer_arg_requires_stack_or_map_shared,
    kfunc_pointer_arg_requires_stack_slot_base as kfunc_pointer_arg_requires_stack_slot_base_shared,
    kfunc_pointer_arg_requires_user as kfunc_pointer_arg_requires_user_shared,
    kfunc_pointer_arg_size_from_scalar as kfunc_pointer_arg_size_from_scalar_shared,
    kfunc_scalar_arg_requires_known_const as kfunc_scalar_arg_requires_known_const_shared,
    kfunc_scalar_arg_requires_positive as kfunc_scalar_arg_requires_positive_shared,
    kfunc_semantics, kfunc_unknown_dynptr_copy as kfunc_unknown_dynptr_copy_shared,
    kfunc_unknown_stack_object_copy as kfunc_unknown_stack_object_copy_shared,
};
use super::mir::{
    AddressSpace, BYTES_COUNTER_MAP_NAME, BasicBlock, BinOpKind, COUNTER_MAP_NAME, CtxField,
    HISTOGRAM_MAP_NAME, MapKind, MapOpKind, MirFunction, MirInst, MirType, MirValue,
    STRING_COUNTER_MAP_NAME, StackSlotId, StackSlotKind, StringAppendType, SubfunctionId,
    TIMESTAMP_MAP_NAME, UnaryOpKind, VReg,
};

mod constraints;
mod helper_semantics;
mod ranges;
mod subfunctions;
mod typing;
mod validate;

pub type SubfnSchemeMap = HashMap<SubfunctionId, TypeScheme>;
pub use subfunctions::{infer_subfunction_schemes, infer_subfunction_schemes_with_hints};

pub(crate) fn validate_program_capabilities(
    func: &MirFunction,
    probe_ctx: Option<&ProbeContext>,
) -> Result<(), Vec<TypeError>> {
    let Some(ctx) = probe_ctx else {
        return Ok(());
    };
    validate_program_capabilities_for_info(func, ctx.program_info())
}

pub(crate) fn validate_program_capabilities_for_info(
    func: &MirFunction,
    program: &ProgramTypeInfo,
) -> Result<(), Vec<TypeError>> {
    let mut errors = Vec::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            TypeInference::validate_program_capability_for_info(inst, program, &mut errors);
        }
        TypeInference::validate_program_capability_for_info(
            &block.terminator,
            program,
            &mut errors,
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

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
    /// Optional stack-slot pointee type hints
    stack_slot_hints: Option<&'a HashMap<StackSlotId, MirType>>,
}

impl<'a> TypeInference<'a> {
    pub(super) fn precise_helper_return_mir_type(helper: BpfHelper) -> Option<MirType> {
        match helper {
            BpfHelper::SkLookupTcp
            | BpfHelper::SkLookupUdp
            | BpfHelper::SkcLookupTcp
            | BpfHelper::GetListenerSock
            | BpfHelper::SkFullsock => Some(MirType::Ptr {
                pointee: Box::new(synthetic_bpf_sock_type()),
                address_space: AddressSpace::Kernel,
            }),
            BpfHelper::TcpSock => Some(MirType::Ptr {
                pointee: Box::new(synthetic_bpf_tcp_sock_type()),
                address_space: AddressSpace::Kernel,
            }),
            BpfHelper::SkcToTcp6Sock => Some(MirType::named_kernel_struct_ptr("tcp6_sock")),
            BpfHelper::SkcToTcpSock => Some(MirType::named_kernel_struct_ptr("tcp_sock")),
            BpfHelper::SkcToTcpTimewaitSock => {
                Some(MirType::named_kernel_struct_ptr("tcp_timewait_sock"))
            }
            BpfHelper::SkcToTcpRequestSock => {
                Some(MirType::named_kernel_struct_ptr("tcp_request_sock"))
            }
            BpfHelper::SkcToUdp6Sock => Some(MirType::named_kernel_struct_ptr("udp6_sock")),
            BpfHelper::SkcToMptcpSock => Some(MirType::named_kernel_struct_ptr("mptcp_sock")),
            BpfHelper::SkcToUnixSock => Some(MirType::named_kernel_struct_ptr("unix_sock")),
            BpfHelper::SockFromFile => Some(MirType::named_kernel_struct_ptr("socket")),
            BpfHelper::GetCurrentTask | BpfHelper::GetCurrentTaskBtf => {
                Some(MirType::named_kernel_struct_ptr("task_struct"))
            }
            BpfHelper::TaskPtRegs => Some(MirType::named_kernel_struct_ptr("pt_regs")),
            BpfHelper::PerCpuPtr | BpfHelper::ThisCpuPtr => Some(MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            }),
            _ => None,
        }
    }

    pub(super) fn precise_kfunc_return_mir_type(kfunc: &str) -> Option<MirType> {
        match kfunc {
            "bpf_task_acquire" | "bpf_task_from_pid" | "bpf_task_from_vpid" => {
                Some(MirType::named_kernel_struct_ptr("task_struct"))
            }
            "bpf_task_get_cgroup1"
            | "bpf_cgroup_acquire"
            | "bpf_cgroup_ancestor"
            | "bpf_cgroup_from_id" => Some(MirType::named_kernel_struct_ptr("cgroup")),
            "bpf_get_task_exe_file" => Some(MirType::named_kernel_struct_ptr("file")),
            _ => None,
        }
    }

    /// Create a new type inference pass
    pub fn new(probe_ctx: Option<ProbeContext>) -> Self {
        Self::new_with_env(probe_ctx, None, None, None, None)
    }

    /// Create a new type inference pass with subfunction schemes and optional return type
    pub fn new_with_env(
        probe_ctx: Option<ProbeContext>,
        subfn_schemes: Option<&'a SubfnSchemeMap>,
        expected_return: Option<HMType>,
        type_hints: Option<&'a HashMap<VReg, MirType>>,
        stack_slot_hints: Option<&'a HashMap<StackSlotId, MirType>>,
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
            stack_slot_hints,
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
        if let Some(hints) = self.type_hints {
            for (vreg, hint) in hints {
                let Some(inferred) = result.get_mut(vreg) else {
                    continue;
                };
                if Self::can_restore_layout_hint(hint, inferred) {
                    *inferred = hint.clone();
                }
            }
        }

        // Phase 5: Validate operations with resolved types
        self.validate_types(func, &result, &mut errors);

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(result)
    }

    fn can_restore_layout_hint(hint: &MirType, inferred: &MirType) -> bool {
        if matches!(hint, MirType::Unknown) {
            return false;
        }
        if matches!(inferred, MirType::Unknown) {
            return true;
        }
        HMType::from_mir_type(hint) == HMType::from_mir_type(inferred)
    }
}

#[cfg(test)]
mod tests;
