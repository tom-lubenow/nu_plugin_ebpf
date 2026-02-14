use super::*;

impl<'a> TypeInference<'a> {
    pub(super) fn ctx_field_type(&mut self, field: &CtxField) -> HMType {
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
    pub(super) fn is_userspace_probe(&self) -> bool {
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
    pub(super) fn binop_result_type(
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
    pub(super) fn unaryop_result_type(
        &self,
        op: UnaryOpKind,
        src: &HMType,
    ) -> Result<HMType, TypeError> {
        match op {
            UnaryOpKind::Not => Ok(HMType::Bool),
            UnaryOpKind::BitNot | UnaryOpKind::Neg => Ok(src.clone()),
        }
    }

    /// Promote two numeric types to a common type
    pub(super) fn promote_numeric(&self, lhs: &HMType, rhs: &HMType) -> HMType {
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

    pub(super) fn type_size(&self, ty: &HMType) -> usize {
        match ty {
            HMType::I8 | HMType::U8 | HMType::Bool => 1,
            HMType::I16 | HMType::U16 => 2,
            HMType::I32 | HMType::U32 => 4,
            HMType::I64 | HMType::U64 => 8,
            _ => 8,
        }
    }

    pub(super) fn is_signed(&self, ty: &HMType) -> bool {
        matches!(ty, HMType::I8 | HMType::I16 | HMType::I32 | HMType::I64)
    }

    pub(super) fn hm_type_for_vreg(&self, vreg: VReg) -> HMType {
        self.substitution.apply(&self.vreg_type(vreg))
    }

    pub(super) fn hm_return_type(&self) -> HMType {
        match self.return_var {
            Some(var) => self.substitution.apply(&HMType::Var(var)),
            None => HMType::Unknown,
        }
    }

    pub(super) fn scheme_for_function(
        &self,
        func: &MirFunction,
        env: Option<&SubfnSchemeMap>,
    ) -> TypeScheme {
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
    pub(super) fn hm_to_mir(&self, ty: &HMType) -> MirType {
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
                    mir_fields.push(crate::compiler::mir::StructField {
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
