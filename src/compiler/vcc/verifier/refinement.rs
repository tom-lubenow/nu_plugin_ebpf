use super::*;

impl VccVerifier {
    pub(super) fn refine_branch_states(&self, cond: VccValue, state: &VccState) -> (VccState, VccState) {
        let mut true_state = state.clone();
        let mut false_state = state.clone();
        if let Some(truthy) = self.known_truthy(cond, state) {
            if truthy {
                false_state.mark_unreachable();
            } else {
                true_state.mark_unreachable();
            }
        }
        if let VccValue::Reg(cond_reg) = cond {
            if let Some(refinement) = state.cond_refinement(cond_reg) {
                match refinement {
                    VccCondRefinement::PtrNull {
                        true_means_non_null,
                        ..
                    } => {
                        self.refine_ptr_nullability(
                            &mut true_state,
                            refinement,
                            true_means_non_null,
                        );
                        self.refine_ptr_nullability(
                            &mut false_state,
                            refinement,
                            !true_means_non_null,
                        );
                    }
                    VccCondRefinement::ScalarCmpConst { reg, op, value } => {
                        self.refine_scalar_compare_const(&mut true_state, reg, op, value, true);
                        self.refine_scalar_compare_const(&mut false_state, reg, op, value, false);
                    }
                    VccCondRefinement::ScalarCmpRegs { lhs, rhs, op } => {
                        self.refine_scalar_compare_regs(&mut true_state, lhs, rhs, op, true);
                        self.refine_scalar_compare_regs(&mut false_state, lhs, rhs, op, false);
                    }
                }
            }
        }
        (true_state, false_state)
    }

    pub(super) fn refine_ptr_nullability(
        &self,
        state: &mut VccState,
        refinement: VccCondRefinement,
        non_null: bool,
    ) {
        if !state.is_reachable() {
            return;
        }
        let VccCondRefinement::PtrNull {
            ptr_reg,
            ringbuf_ref,
            kfunc_ref,
            ..
        } = refinement
        else {
            return;
        };
        let Ok(VccValueType::Ptr(mut ptr)) = state.reg_type(ptr_reg) else {
            return;
        };
        if (non_null && ptr.nullability == VccNullability::Null)
            || (!non_null && ptr.nullability == VccNullability::NonNull)
        {
            state.mark_unreachable();
            return;
        }
        ptr.nullability = if non_null {
            VccNullability::NonNull
        } else {
            VccNullability::Null
        };
        if !non_null {
            if let Some(ref_id) = ringbuf_ref {
                state.set_live_ringbuf_ref(ref_id, false);
            }
            if let Some(ref_id) = kfunc_ref {
                state.set_live_kfunc_ref(ref_id, false, None);
            }
        }
        state.set_reg(ptr_reg, VccValueType::Ptr(ptr));
    }

    pub(super) fn refine_scalar_compare_const(
        &self,
        state: &mut VccState,
        reg: VccReg,
        op: VccBinOp,
        value: i64,
        take_true: bool,
    ) {
        if !state.is_reachable() {
            return;
        }
        let effective_op = if take_true {
            Some(op)
        } else {
            Self::invert_compare(op)
        };
        let Some(effective_op) = effective_op else {
            return;
        };
        let Ok(ty) = state.reg_type(reg) else {
            return;
        };
        let VccValueType::Scalar { range } = ty else {
            return;
        };
        let prior_excluded = state.not_equal_consts(reg).to_vec();
        if !Self::range_can_satisfy_const_compare(range, &prior_excluded, effective_op, value) {
            state.mark_unreachable();
            return;
        }
        let Some(refined) = Self::refine_scalar_range(range, effective_op, value) else {
            state.mark_unreachable();
            return;
        };
        state.set_reg(reg, VccValueType::Scalar { range: refined });
        for excluded in prior_excluded {
            state.set_not_equal_const(reg, excluded);
        }
        match effective_op {
            VccBinOp::Eq => state.clear_not_equal_consts(reg),
            VccBinOp::Ne => {
                state.set_not_equal_const(reg, value);
                state.retain_not_equal_in_range(reg, refined);
            }
            _ => state.retain_not_equal_in_range(reg, refined),
        }
    }

    pub(super) fn invert_compare(op: VccBinOp) -> Option<VccBinOp> {
        match op {
            VccBinOp::Eq => Some(VccBinOp::Ne),
            VccBinOp::Ne => Some(VccBinOp::Eq),
            VccBinOp::Lt => Some(VccBinOp::Ge),
            VccBinOp::Le => Some(VccBinOp::Gt),
            VccBinOp::Gt => Some(VccBinOp::Le),
            VccBinOp::Ge => Some(VccBinOp::Lt),
            _ => None,
        }
    }

    pub(super) fn refine_scalar_range(
        range: Option<VccRange>,
        op: VccBinOp,
        value: i64,
    ) -> Option<Option<VccRange>> {
        let current = range.unwrap_or(VccRange {
            min: i64::MIN,
            max: i64::MAX,
        });
        let maybe_refined = match op {
            VccBinOp::Eq => {
                if value < current.min || value > current.max {
                    None
                } else {
                    Some(VccRange {
                        min: value,
                        max: value,
                    })
                }
            }
            VccBinOp::Ne => {
                if current.min == current.max && current.min == value {
                    None
                } else {
                    Some(current)
                }
            }
            VccBinOp::Lt => {
                let max = current.max.min(value.saturating_sub(1));
                if current.min > max {
                    None
                } else {
                    Some(VccRange {
                        min: current.min,
                        max,
                    })
                }
            }
            VccBinOp::Le => {
                let max = current.max.min(value);
                if current.min > max {
                    None
                } else {
                    Some(VccRange {
                        min: current.min,
                        max,
                    })
                }
            }
            VccBinOp::Gt => {
                let min = current.min.max(value.saturating_add(1));
                if min > current.max {
                    None
                } else {
                    Some(VccRange {
                        min,
                        max: current.max,
                    })
                }
            }
            VccBinOp::Ge => {
                let min = current.min.max(value);
                if min > current.max {
                    None
                } else {
                    Some(VccRange {
                        min,
                        max: current.max,
                    })
                }
            }
            _ => Some(current),
        }?;
        if range.is_none() && maybe_refined.min == i64::MIN && maybe_refined.max == i64::MAX {
            Some(None)
        } else {
            Some(Some(maybe_refined))
        }
    }

    pub(super) fn known_truthy(&self, cond: VccValue, state: &VccState) -> Option<bool> {
        let ty = state.value_type(cond).ok()?;
        let range = state.value_range(cond, ty)?;
        if range.min == 0 && range.max == 0 {
            Some(false)
        } else if range.min > 0 || range.max < 0 {
            Some(true)
        } else {
            None
        }
    }

    pub(super) fn range_can_satisfy_const_compare(
        range: Option<VccRange>,
        excluded: &[i64],
        op: VccBinOp,
        value: i64,
    ) -> bool {
        match op {
            VccBinOp::Eq => {
                if excluded.contains(&value) {
                    return false;
                }
                match range {
                    Some(range) => value >= range.min && value <= range.max,
                    None => true,
                }
            }
            VccBinOp::Ne => match range {
                Some(VccRange { min, max }) => !(min == max && min == value),
                None => true,
            },
            VccBinOp::Lt => match range {
                Some(VccRange { min, .. }) => min < value,
                None => true,
            },
            VccBinOp::Le => match range {
                Some(VccRange { min, .. }) => min <= value,
                None => true,
            },
            VccBinOp::Gt => match range {
                Some(VccRange { max, .. }) => max > value,
                None => true,
            },
            VccBinOp::Ge => match range {
                Some(VccRange { max, .. }) => max >= value,
                None => true,
            },
            _ => true,
        }
    }

    pub(super) fn refine_scalar_compare_regs(
        &self,
        state: &mut VccState,
        lhs: VccReg,
        rhs: VccReg,
        op: VccBinOp,
        take_true: bool,
    ) {
        if !state.is_reachable() {
            return;
        }
        let effective_op = if take_true {
            Some(op)
        } else {
            Self::invert_compare(op)
        };
        let Some(effective_op) = effective_op else {
            return;
        };
        let Ok(lhs_ty) = state.reg_type(lhs) else {
            return;
        };
        let Ok(rhs_ty) = state.reg_type(rhs) else {
            return;
        };
        let VccValueType::Scalar { range: lhs_range } = lhs_ty else {
            return;
        };
        let VccValueType::Scalar { range: rhs_range } = rhs_ty else {
            return;
        };
        if !Self::ranges_can_satisfy_compare(lhs_range, rhs_range, effective_op) {
            state.mark_unreachable();
            return;
        }
        let (new_lhs, new_rhs) = Self::refine_compare_ranges(lhs_range, rhs_range, effective_op);

        let lhs_excluded = state.not_equal_consts(lhs).to_vec();
        let rhs_excluded = state.not_equal_consts(rhs).to_vec();
        state.set_reg(lhs, VccValueType::Scalar { range: new_lhs });
        for value in lhs_excluded {
            state.set_not_equal_const(lhs, value);
        }
        state.retain_not_equal_in_range(lhs, new_lhs);

        if rhs != lhs {
            state.set_reg(rhs, VccValueType::Scalar { range: new_rhs });
            for value in rhs_excluded {
                state.set_not_equal_const(rhs, value);
            }
            state.retain_not_equal_in_range(rhs, new_rhs);
        }
    }

    pub(super) fn ranges_can_satisfy_compare(
        lhs: Option<VccRange>,
        rhs: Option<VccRange>,
        op: VccBinOp,
    ) -> bool {
        let Some((lhs_min, lhs_max)) = Self::range_bounds(lhs) else {
            return true;
        };
        let Some((rhs_min, rhs_max)) = Self::range_bounds(rhs) else {
            return true;
        };
        match op {
            VccBinOp::Eq => lhs_min <= rhs_max && rhs_min <= lhs_max,
            VccBinOp::Ne => !(lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min),
            VccBinOp::Lt => lhs_min < rhs_max,
            VccBinOp::Le => lhs_min <= rhs_max,
            VccBinOp::Gt => lhs_max > rhs_min,
            VccBinOp::Ge => lhs_max >= rhs_min,
            _ => true,
        }
    }

    pub(super) fn refine_compare_ranges(
        lhs: Option<VccRange>,
        rhs: Option<VccRange>,
        op: VccBinOp,
    ) -> (Option<VccRange>, Option<VccRange>) {
        let lhs_bounds = Self::range_bounds(lhs);
        let rhs_bounds = Self::range_bounds(rhs);
        match op {
            VccBinOp::Eq => {
                let lhs = match rhs_bounds {
                    Some((min, max)) => Self::intersect_range(lhs, Some(min), Some(max)),
                    None => lhs,
                };
                let rhs = match lhs_bounds {
                    Some((min, max)) => Self::intersect_range(rhs, Some(min), Some(max)),
                    None => rhs,
                };
                (lhs, rhs)
            }
            VccBinOp::Ne => {
                let lhs = if let Some((min, max)) = rhs_bounds {
                    if min == max {
                        Self::refine_scalar_range(lhs, VccBinOp::Ne, min).unwrap_or(lhs)
                    } else {
                        lhs
                    }
                } else {
                    lhs
                };
                let rhs = if let Some((min, max)) = lhs_bounds {
                    if min == max {
                        Self::refine_scalar_range(rhs, VccBinOp::Ne, min).unwrap_or(rhs)
                    } else {
                        rhs
                    }
                } else {
                    rhs
                };
                (lhs, rhs)
            }
            VccBinOp::Lt => {
                let lhs = match rhs_bounds {
                    Some((_, rhs_max)) => {
                        Self::intersect_range(lhs, None, Some(rhs_max.saturating_sub(1)))
                    }
                    None => lhs,
                };
                let rhs = match lhs_bounds {
                    Some((lhs_min, _)) => {
                        Self::intersect_range(rhs, Some(lhs_min.saturating_add(1)), None)
                    }
                    None => rhs,
                };
                (lhs, rhs)
            }
            VccBinOp::Le => {
                let lhs = match rhs_bounds {
                    Some((_, rhs_max)) => Self::intersect_range(lhs, None, Some(rhs_max)),
                    None => lhs,
                };
                let rhs = match lhs_bounds {
                    Some((lhs_min, _)) => Self::intersect_range(rhs, Some(lhs_min), None),
                    None => rhs,
                };
                (lhs, rhs)
            }
            VccBinOp::Gt => {
                let lhs = match rhs_bounds {
                    Some((rhs_min, _)) => {
                        Self::intersect_range(lhs, Some(rhs_min.saturating_add(1)), None)
                    }
                    None => lhs,
                };
                let rhs = match lhs_bounds {
                    Some((_, lhs_max)) => {
                        Self::intersect_range(rhs, None, Some(lhs_max.saturating_sub(1)))
                    }
                    None => rhs,
                };
                (lhs, rhs)
            }
            VccBinOp::Ge => {
                let lhs = match rhs_bounds {
                    Some((rhs_min, _)) => Self::intersect_range(lhs, Some(rhs_min), None),
                    None => lhs,
                };
                let rhs = match lhs_bounds {
                    Some((_, lhs_max)) => Self::intersect_range(rhs, None, Some(lhs_max)),
                    None => rhs,
                };
                (lhs, rhs)
            }
            _ => (lhs, rhs),
        }
    }

    pub(super) fn range_bounds(range: Option<VccRange>) -> Option<(i64, i64)> {
        range.map(|range| (range.min, range.max))
    }

    pub(super) fn intersect_range(
        current: Option<VccRange>,
        min: Option<i64>,
        max: Option<i64>,
    ) -> Option<VccRange> {
        if min.is_none() && max.is_none() {
            return current;
        }
        match current {
            Some(current) => {
                let min = min
                    .map(|value| current.min.max(value))
                    .unwrap_or(current.min);
                let max = max
                    .map(|value| current.max.min(value))
                    .unwrap_or(current.max);
                if min <= max {
                    Some(VccRange { min, max })
                } else {
                    Some(current)
                }
            }
            None => {
                let min = min.unwrap_or(i64::MIN);
                let max = max.unwrap_or(i64::MAX);
                if min <= max {
                    Some(VccRange { min, max })
                } else {
                    None
                }
            }
        }
    }

}
