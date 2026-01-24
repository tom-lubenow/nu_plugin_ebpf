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

use std::collections::HashMap;

use super::elf::{EbpfProgramType, ProbeContext};
use super::hindley_milner::{
    Constraint, HMType, Substitution, TypeVar, TypeVarGenerator, UnifyError, unify,
};
use super::mir::{
    AddressSpace, BasicBlock, BinOpKind, CtxField, MirFunction, MirInst, MirType, MirValue,
    UnaryOpKind, VReg,
};

/// Type inference error
#[derive(Debug, Clone)]
pub struct TypeError {
    pub message: String,
    pub hint: Option<String>,
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
pub struct TypeInference {
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
}

impl TypeInference {
    /// Create a new type inference pass
    pub fn new(probe_ctx: Option<ProbeContext>) -> Self {
        Self {
            tvar_gen: TypeVarGenerator::new(),
            vreg_vars: HashMap::new(),
            constraints: Vec::new(),
            probe_ctx,
            substitution: Substitution::new(),
        }
    }

    /// Run type inference on a MIR function
    ///
    /// Returns the type map on success, or a list of type errors.
    pub fn infer(&mut self, func: &MirFunction) -> Result<HashMap<VReg, MirType>, Vec<TypeError>> {
        // Phase 1: Assign fresh type variables to all vregs
        for i in 0..func.vreg_count {
            let vreg = VReg(i);
            let tvar = self.tvar_gen.fresh();
            self.vreg_vars.insert(vreg, tvar);
        }

        // Phase 2: Generate constraints from each instruction
        let mut errors = Vec::new();
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

            MirInst::CallHelper { dst, .. } => {
                // Most BPF helpers return i64
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::I64, "helper_call");
            }

            MirInst::CallSubfn { dst, .. } => {
                // Subfunction return type - default to i64 for now
                // TODO: infer from subfunction signature
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::I64, "subfn_call");
            }

            MirInst::MapLookup { dst, .. } => {
                // Map lookup returns pointer to value
                let dst_ty = self.vreg_type(*dst);
                let ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::I64),
                    address_space: AddressSpace::Map,
                };
                self.constrain(dst_ty, ptr_ty, "map_lookup");
            }

            MirInst::LoadCtxField { dst, field } => {
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

            // Instructions that don't define a vreg - no constraints needed
            MirInst::Store { .. }
            | MirInst::StoreSlot { .. }
            | MirInst::MapUpdate { .. }
            | MirInst::MapDelete { .. }
            | MirInst::Histogram { .. }
            | MirInst::StartTimer
            | MirInst::EmitEvent { .. }
            | MirInst::EmitRecord { .. }
            | MirInst::ReadStr { .. }
            | MirInst::RecordStore { .. }
            | MirInst::ListPush { .. }
            | MirInst::StringAppend { .. }
            | MirInst::IntToString { .. }
            | MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopBack { .. } => {}
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

    /// Add a constraint
    fn constrain(&mut self, expected: HMType, actual: HMType, context: impl Into<String>) {
        self.constraints
            .push(Constraint::new(expected, actual, context));
    }

    /// Get the type of a context field based on probe type
    fn ctx_field_type(&self, field: &CtxField) -> HMType {
        match field {
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Cpu => {
                HMType::U32
            }

            CtxField::Timestamp => HMType::U64,

            CtxField::Arg(_) => {
                if self.is_userspace_probe() {
                    HMType::Ptr {
                        pointee: Box::new(HMType::U8),
                        address_space: AddressSpace::User,
                    }
                } else {
                    HMType::I64
                }
            }

            CtxField::RetVal => HMType::I64,
            CtxField::KStack | CtxField::UStack => HMType::I64,

            CtxField::Comm => HMType::Array {
                elem: Box::new(HMType::U8),
                len: 16,
            },

            CtxField::TracepointField(_) => HMType::I64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{BlockId, MirFunction};

    fn make_test_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;
        func
    }

    #[test]
    fn test_infer_constant() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_ctx_pid() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Pid,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::U32));
    }

    #[test]
    fn test_infer_ctx_comm() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Comm,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(
            types.get(&v0),
            Some(&MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16
            })
        );
    }

    #[test]
    fn test_infer_binop_add() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(10),
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(20),
        });
        block.instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v2), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_comparison() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Pid,
        });
        block.instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1234),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v1), Some(&MirType::Bool));
    }

    #[test]
    fn test_infer_uprobe_arg_is_user_ptr() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Arg(0),
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "test");
        let mut ti = TypeInference::new(Some(ctx));
        let types = ti.infer(&func).unwrap();

        match types.get(&v0) {
            Some(MirType::Ptr { address_space, .. }) => {
                assert_eq!(*address_space, AddressSpace::User);
            }
            other => panic!("Expected user pointer, got {:?}", other),
        }
    }

    #[test]
    fn test_infer_kprobe_arg_is_int() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Arg(0),
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "test");
        let mut ti = TypeInference::new(Some(ctx));
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_map_lookup_returns_ptr() {
        use crate::compiler::mir::{MapKind, MapRef};

        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(123),
        });
        block.instructions.push(MirInst::MapLookup {
            dst: v1,
            map: MapRef {
                name: "test_map".to_string(),
                kind: MapKind::Hash,
            },
            key: v0,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        match types.get(&v1) {
            Some(MirType::Ptr { address_space, .. }) => {
                assert_eq!(*address_space, AddressSpace::Map);
            }
            other => panic!("Expected map pointer, got {:?}", other),
        }
    }

    #[test]
    fn test_copy_propagates_type() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Timestamp,
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        // Both should be U64 (timestamp type)
        assert_eq!(types.get(&v0), Some(&MirType::U64));
        assert_eq!(types.get(&v1), Some(&MirType::U64));
    }

    #[test]
    fn test_type_propagation_through_chain() {
        // Test that types propagate through a chain of copies
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Pid, // U32
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        block.instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::VReg(v1),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        // All should be U32
        assert_eq!(types.get(&v0), Some(&MirType::U32));
        assert_eq!(types.get(&v1), Some(&MirType::U32));
        assert_eq!(types.get(&v2), Some(&MirType::U32));
    }

    #[test]
    fn test_unification_through_binop() {
        // Test that types unify correctly through binary operations
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Uid, // U32
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        // Compare v1 (which got type from v0) with constant
        block.instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(v1),
            rhs: MirValue::Const(0),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::U32));
        assert_eq!(types.get(&v1), Some(&MirType::U32));
        assert_eq!(types.get(&v2), Some(&MirType::Bool));
    }
}
