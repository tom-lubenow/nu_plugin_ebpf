#[path = "verifier/comparison_helpers.rs"]
mod comparison_helpers;

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
            if !state.is_reachable() {
                continue;
            }
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

    fn refine_ptr_nullability(
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

    fn refine_scalar_compare_const(
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

    fn invert_compare(op: VccBinOp) -> Option<VccBinOp> {
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

    fn refine_scalar_range(
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

    fn known_truthy(&self, cond: VccValue, state: &VccState) -> Option<bool> {
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

    fn range_can_satisfy_const_compare(
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

    fn refine_scalar_compare_regs(
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

    fn ranges_can_satisfy_compare(
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

    fn refine_compare_ranges(
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

    fn range_bounds(range: Option<VccRange>) -> Option<(i64, i64)> {
        range.map(|range| (range.min, range.max))
    }

    fn intersect_range(
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

    fn propagate_state(
        &mut self,
        block: VccBlockId,
        state: &VccState,
        in_states: &mut HashMap<VccBlockId, VccState>,
        worklist: &mut VecDeque<VccBlockId>,
        update_counts: &mut HashMap<VccBlockId, usize>,
    ) {
        if !state.is_reachable() {
            return;
        }
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
        if !state.is_reachable() {
            return;
        }
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
                if *value != 0 {
                    state.set_not_equal_const(*dst, 0);
                }
            }
            VccInst::Copy { dst, src } => match state.value_type(*src) {
                Ok(ty) => {
                    let (copied_refinement, src_not_equal) = match src {
                        VccValue::Reg(src_reg) => (
                            state.cond_refinement(*src_reg),
                            state.not_equal_consts(*src_reg).to_vec(),
                        ),
                        VccValue::Imm(v) if *v != 0 => (None, vec![0]),
                        _ => (None, Vec::new()),
                    };
                    state.set_reg(*dst, ty);
                    if let Some(refinement) = copied_refinement {
                        state.set_cond_refinement(*dst, refinement);
                    }
                    for value in src_not_equal {
                        state.set_not_equal_const(*dst, value);
                    }
                }
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
            VccInst::AssertPositive { value, message } => {
                let ty = match state.value_type(*value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: ty.class(),
                        },
                        "expected scalar value",
                    ));
                    return;
                }
                if let Some(range) = state.value_range(*value, ty) {
                    if range.max <= 0 || range.min <= 0 {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            message.clone(),
                        ));
                    }
                }
            }
            VccInst::AssertPtrAccess { ptr, size, op } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                let ptr_info = match ptr_ty {
                    VccValueType::Ptr(info) => {
                        if let Err(err) = self.require_non_null_ptr(info, op) {
                            self.errors.push(err);
                            return;
                        }
                        info
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("{op} requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                };
                let size_ty = match state.value_type(*size) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if size_ty.class() != VccTypeClass::Scalar && size_ty.class() != VccTypeClass::Bool
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: size_ty.class(),
                        },
                        format!("{op} size must be scalar"),
                    ));
                    return;
                }
                if let Some(size_range) = state.value_range(*size, size_ty) {
                    if size_range.max <= 0 || size_range.min <= 0 {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            format!("{op} size must be > 0"),
                        ));
                        return;
                    }
                    if let (VccAddrSpace::Stack(_), Some(bounds)) =
                        (ptr_info.space, ptr_info.bounds)
                    {
                        if bounds.shifted_with_size(0, size_range.max).is_none() {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!("{op} out of bounds"),
                            ));
                        }
                    }
                }
            }
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
                        kfunc_ref: None,
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
                        let ptr_cond_cmp =
                            self.ptr_cond_comparison(*op, *lhs, lhs_ty, *rhs, rhs_ty, state);
                        let scalar_cmp =
                            self.scalar_const_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let scalar_reg_cmp =
                            self.scalar_reg_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
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
                        if let Some((ptr_reg, ringbuf_ref, kfunc_ref)) = ptr_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PtrNull {
                                    ptr_reg,
                                    ringbuf_ref,
                                    kfunc_ref,
                                    true_means_non_null: matches!(op, VccBinOp::Ne),
                                },
                            );
                        } else if let Some((ptr_reg, ringbuf_ref, kfunc_ref, true_means_non_null)) =
                            ptr_cond_cmp
                        {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PtrNull {
                                    ptr_reg,
                                    ringbuf_ref,
                                    kfunc_ref,
                                    true_means_non_null,
                                },
                            );
                        } else if let Some((reg, cmp_op, value)) = scalar_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpConst {
                                    reg,
                                    op: cmp_op,
                                    value,
                                },
                            );
                        } else if let Some((lhs, rhs, cmp_op)) = scalar_reg_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpRegs {
                                    lhs,
                                    rhs,
                                    op: cmp_op,
                                },
                            );
                        }
                    }
                    VccBinOp::Lt | VccBinOp::Le | VccBinOp::Gt | VccBinOp::Ge => {
                        let scalar_cmp =
                            self.scalar_const_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let scalar_reg_cmp =
                            self.scalar_reg_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
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
                        if let Some((reg, cmp_op, value)) = scalar_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpConst {
                                    reg,
                                    op: cmp_op,
                                    value,
                                },
                            );
                        } else if let Some((lhs, rhs, cmp_op)) = scalar_reg_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpRegs {
                                    lhs,
                                    rhs,
                                    op: cmp_op,
                                },
                            );
                        }
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
                        let range = state.binop_range(*op, *lhs, lhs_ty, *rhs, rhs_ty);
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
                let bounds = match (base_ptr.bounds, offset_range) {
                    (Some(bounds), Some(range)) => {
                        bounds.shifted(range).map(Some).unwrap_or_else(|| {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "pointer arithmetic out of bounds",
                            ));
                            None
                        })
                    }
                    (Some(_), None) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnknownOffset,
                            "pointer arithmetic requires bounded scalar offset",
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
                        kfunc_ref: base_ptr.kfunc_ref,
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
                        if !Self::is_mem_space_allowed(ptr_info.space) {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "load requires pointer in [Stack, Map], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if let Some(bounds) = ptr_info.bounds {
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
                                    "load offset out of bounds",
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
                        if !Self::is_mem_space_allowed(ptr_info.space) {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "store requires pointer in [Stack, Map], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if let Some(bounds) = ptr_info.bounds {
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
                                    "store offset out of bounds",
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
                let mut merged_refinement: Option<Option<VccCondRefinement>> = None;
                for (_, reg) in args {
                    let next = state.cond_refinement(*reg);
                    merged_refinement = Some(match merged_refinement {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged_refinement, Some(None)) {
                        break;
                    }
                }
                if let Some(Some(refinement)) = merged_refinement {
                    state.set_cond_refinement(*dst, refinement);
                }
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
            VccInst::KfuncAcquire { id, kind } => {
                state.set_live_kfunc_ref(*id, true, Some(*kind));
            }
            VccInst::KfuncRelease { ptr, kind } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::Kernel => {
                        if let Err(err) = self.require_non_null_ptr(info, "kfunc release") {
                            self.errors.push(err);
                            return;
                        }
                        if let Some(ref_id) = info.kfunc_ref {
                            if !state.is_live_kfunc_ref(ref_id) {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "kfunc reference already released",
                                ));
                                return;
                            }
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind == Some(*kind) {
                                state.invalidate_kfunc_ref(ref_id);
                            } else {
                                let expected = kind.label();
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc release expects {} reference, got {} reference",
                                        expected, actual
                                    ),
                                ));
                            }
                        } else {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "kfunc release pointer is not tracked",
                            ));
                        }
                    }
                    VccValueType::Ptr(_) => {
                        let expected = kind.label();
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "kfunc release requires kernel {} reference pointer",
                                expected
                            ),
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            "kfunc release requires pointer operand",
                        ));
                    }
                }
            }
            VccInst::KfuncExpectRefKind {
                ptr,
                arg_idx,
                kind,
                kfunc,
            } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::Kernel => {
                        if let Some(ref_id) = info.kfunc_ref {
                            let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                            if let Err(err) = self.require_non_null_ptr(info, &op) {
                                self.errors.push(err);
                            }
                            if !state.is_live_kfunc_ref(ref_id) {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc '{}' arg{} reference already released",
                                        kfunc, arg_idx
                                    ),
                                ));
                                return;
                            }
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind != Some(*kind) {
                                let expected = kind.label();
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc '{}' arg{} expects {} reference, got {} reference",
                                        kfunc, arg_idx, expected, actual
                                    ),
                                ));
                            }
                        }
                    }
                    VccValueType::Ptr(info) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "kfunc '{}' arg{} expects pointer in [Kernel], got {}",
                                kfunc,
                                arg_idx,
                                Self::space_name(info.space)
                            ),
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            format!("kfunc '{}' arg{} expects pointer value", kfunc, arg_idx),
                        ));
                    }
                }
            }
            VccInst::KptrXchgTransfer { dst, src } => {
                let ty = match state.value_type(*src) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if let VccValueType::Ptr(info) = ty
                    && let Some(ref_id) = info.kfunc_ref
                {
                    if !state.is_live_kfunc_ref(ref_id) {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            "helper 194 arg1 reference already released",
                        ));
                        return;
                    }
                    let kind = state.kfunc_ref_kind(ref_id);
                    state.invalidate_kfunc_ref(ref_id);
                    state.set_live_kfunc_ref(*dst, true, kind);

                    if let Ok(VccValueType::Ptr(mut dst_info)) = state.reg_type(*dst) {
                        dst_info.kfunc_ref = Some(*dst);
                        state.set_reg(*dst, VccValueType::Ptr(dst_info));
                    }
                }
            }
        }
    }

    fn verify_terminator(&mut self, term: &VccTerminator, state: &mut VccState) {
        if !state.is_reachable() {
            return;
        }
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
                if state.has_live_kfunc_refs() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased kfunc reference at function exit",
                    ));
                }
            }
        }
    }
}
