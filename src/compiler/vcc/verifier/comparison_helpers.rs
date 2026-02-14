use super::*;

impl VccVerifier {
    pub(super) fn ptr_null_comparison(
        &self,
        lhs: VccValue,
        lhs_ty: VccValueType,
        rhs: VccValue,
        rhs_ty: VccValueType,
    ) -> Option<(VccReg, Option<VccReg>, Option<VccReg>)> {
        match (lhs, lhs_ty, rhs, rhs_ty) {
            (VccValue::Reg(ptr_reg), VccValueType::Ptr(ptr), _, other)
                if self.is_null_scalar(rhs, other) =>
            {
                Some((ptr_reg, ptr.ringbuf_ref, ptr.kfunc_ref))
            }
            (_, other, VccValue::Reg(ptr_reg), VccValueType::Ptr(ptr))
                if self.is_null_scalar(lhs, other) =>
            {
                Some((ptr_reg, ptr.ringbuf_ref, ptr.kfunc_ref))
            }
            _ => None,
        }
    }

    pub(super) fn ptr_cond_comparison(
        &self,
        op: VccBinOp,
        lhs: VccValue,
        lhs_ty: VccValueType,
        rhs: VccValue,
        rhs_ty: VccValueType,
        state: &VccState,
    ) -> Option<(VccReg, Option<VccReg>, Option<VccReg>, bool)> {
        let map_cond =
            |cond: VccValue, cond_ty: VccValueType, other: VccValue, other_ty: VccValueType| {
                let VccValue::Reg(cond_reg) = cond else {
                    return None;
                };
                if !self.is_null_scalar(other, other_ty) {
                    return None;
                }
                if cond_ty.class() != VccTypeClass::Scalar && cond_ty.class() != VccTypeClass::Bool
                {
                    return None;
                }
                let VccCondRefinement::PtrNull {
                    ptr_reg,
                    ringbuf_ref,
                    kfunc_ref,
                    true_means_non_null,
                } = state.cond_refinement(cond_reg)?
                else {
                    return None;
                };
                let true_means_non_null = match op {
                    VccBinOp::Ne => true_means_non_null,
                    VccBinOp::Eq => !true_means_non_null,
                    _ => return None,
                };
                Some((ptr_reg, ringbuf_ref, kfunc_ref, true_means_non_null))
            };

        map_cond(lhs, lhs_ty, rhs, rhs_ty).or_else(|| map_cond(rhs, rhs_ty, lhs, lhs_ty))
    }

    pub(super) fn scalar_const_comparison(
        &self,
        lhs: VccValue,
        lhs_ty: VccValueType,
        rhs: VccValue,
        rhs_ty: VccValueType,
        op: VccBinOp,
    ) -> Option<(VccReg, VccBinOp, i64)> {
        if !matches!(
            op,
            VccBinOp::Eq | VccBinOp::Ne | VccBinOp::Lt | VccBinOp::Le | VccBinOp::Gt | VccBinOp::Ge
        ) {
            return None;
        }
        match (lhs, lhs_ty, rhs, rhs_ty) {
            (VccValue::Reg(reg), left_ty, _, right_ty)
                if Self::is_scalar_like(left_ty)
                    && Self::const_scalar_value(rhs, right_ty).is_some() =>
            {
                let value = Self::const_scalar_value(rhs, right_ty)?;
                Some((reg, op, value))
            }
            (_, left_ty, VccValue::Reg(reg), right_ty)
                if Self::is_scalar_like(right_ty)
                    && Self::const_scalar_value(lhs, left_ty).is_some() =>
            {
                let value = Self::const_scalar_value(lhs, left_ty)?;
                Some((reg, Self::reverse_compare(op)?, value))
            }
            _ => None,
        }
    }

    pub(super) fn scalar_reg_comparison(
        &self,
        lhs: VccValue,
        lhs_ty: VccValueType,
        rhs: VccValue,
        rhs_ty: VccValueType,
        op: VccBinOp,
    ) -> Option<(VccReg, VccReg, VccBinOp)> {
        if !matches!(
            op,
            VccBinOp::Eq | VccBinOp::Ne | VccBinOp::Lt | VccBinOp::Le | VccBinOp::Gt | VccBinOp::Ge
        ) {
            return None;
        }
        match (lhs, lhs_ty, rhs, rhs_ty) {
            (VccValue::Reg(lhs), left_ty, VccValue::Reg(rhs), right_ty)
                if Self::is_scalar_like(left_ty) && Self::is_scalar_like(right_ty) =>
            {
                Some((lhs, rhs, op))
            }
            _ => None,
        }
    }

    pub(super) fn is_scalar_like(ty: VccValueType) -> bool {
        matches!(ty.class(), VccTypeClass::Scalar | VccTypeClass::Bool)
    }

    pub(super) fn const_scalar_value(value: VccValue, ty: VccValueType) -> Option<i64> {
        match value {
            VccValue::Imm(v) => Some(v),
            VccValue::Reg(_) => match ty {
                VccValueType::Scalar {
                    range: Some(VccRange { min, max }),
                } if min == max => Some(min),
                _ => None,
            },
        }
    }

    pub(super) fn reverse_compare(op: VccBinOp) -> Option<VccBinOp> {
        match op {
            VccBinOp::Eq => Some(VccBinOp::Eq),
            VccBinOp::Ne => Some(VccBinOp::Ne),
            VccBinOp::Lt => Some(VccBinOp::Gt),
            VccBinOp::Le => Some(VccBinOp::Ge),
            VccBinOp::Gt => Some(VccBinOp::Lt),
            VccBinOp::Ge => Some(VccBinOp::Le),
            _ => None,
        }
    }

    pub(super) fn require_non_null_ptr(&self, ptr: VccPointerInfo, op: &str) -> Result<(), VccError> {
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

    pub(super) fn is_mem_space_allowed(space: VccAddrSpace) -> bool {
        matches!(space, VccAddrSpace::Stack(_) | VccAddrSpace::MapValue)
    }

    pub(super) fn space_name(space: VccAddrSpace) -> &'static str {
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

    pub(super) fn is_null_scalar(&self, value: VccValue, ty: VccValueType) -> bool {
        (match ty {
            VccValueType::Scalar { range } => matches!(range, Some(VccRange { min: 0, max: 0 })),
            VccValueType::Bool => false,
            VccValueType::Ptr(_) | VccValueType::Unknown | VccValueType::Uninit => false,
        }) || matches!(value, VccValue::Imm(0))
    }
}
