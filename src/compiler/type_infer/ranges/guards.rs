use super::*;

impl<'a> TypeInference<'a> {
    pub(super) fn guard_from_compare(
        &self,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
    ) -> Option<RangeGuard> {
        match (lhs, rhs) {
            (MirValue::VReg(vreg), MirValue::Const(value)) => {
                self.guard_from_compare_reg_const(op, *vreg, *value)
            }
            (MirValue::Const(value), MirValue::VReg(vreg)) => self
                .swap_compare(op)
                .and_then(|swapped| self.guard_from_compare_reg_const(swapped, *vreg, *value)),
            _ => None,
        }
    }

    fn guard_from_compare_reg_const(
        &self,
        op: BinOpKind,
        reg: VReg,
        value: i64,
    ) -> Option<RangeGuard> {
        match op {
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => Some(RangeGuard::CompareConst { reg, op, value }),
            _ => None,
        }
    }

    fn swap_compare(&self, op: BinOpKind) -> Option<BinOpKind> {
        Some(match op {
            BinOpKind::Eq => BinOpKind::Eq,
            BinOpKind::Ne => BinOpKind::Ne,
            BinOpKind::Lt => BinOpKind::Gt,
            BinOpKind::Le => BinOpKind::Ge,
            BinOpKind::Gt => BinOpKind::Lt,
            BinOpKind::Ge => BinOpKind::Le,
            _ => return None,
        })
    }

    fn negate_compare(&self, op: BinOpKind) -> Option<BinOpKind> {
        Some(match op {
            BinOpKind::Eq => BinOpKind::Ne,
            BinOpKind::Ne => BinOpKind::Eq,
            BinOpKind::Lt => BinOpKind::Ge,
            BinOpKind::Le => BinOpKind::Gt,
            BinOpKind::Gt => BinOpKind::Le,
            BinOpKind::Ge => BinOpKind::Lt,
            _ => return None,
        })
    }

    pub(super) fn invert_guard(&self, guard: RangeGuard) -> Option<RangeGuard> {
        match guard {
            RangeGuard::CompareConst { reg, op, value } => Some(RangeGuard::CompareConst {
                reg,
                op: self.negate_compare(op)?,
                value,
            }),
        }
    }

    fn effective_branch_compare(&self, op: BinOpKind, take_true: bool) -> Option<BinOpKind> {
        if take_true {
            Some(op)
        } else {
            self.negate_compare(op)
        }
    }

    fn range_may_equal(&self, range: ValueRange, value: i64) -> bool {
        match range {
            ValueRange::Known { min, max } => value >= min && value <= max,
            ValueRange::Unknown | ValueRange::Unset => true,
        }
    }

    fn range_can_satisfy_const_compare(
        &self,
        range: ValueRange,
        op: BinOpKind,
        value: i64,
    ) -> bool {
        match op {
            BinOpKind::Eq => self.range_may_equal(range, value),
            BinOpKind::Ne => match range {
                ValueRange::Known { min, max } => !(min == max && min == value),
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Lt => match range {
                ValueRange::Known { min, .. } => min < value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Le => match range {
                ValueRange::Known { min, .. } => min <= value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Gt => match range {
                ValueRange::Known { max, .. } => max > value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Ge => match range {
                ValueRange::Known { max, .. } => max >= value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            _ => true,
        }
    }

    pub(super) fn intersect_range(
        &self,
        current: ValueRange,
        min: Option<i64>,
        max: Option<i64>,
    ) -> ValueRange {
        let (cur_min, cur_max) = match current {
            ValueRange::Known { min, max } => (min, max),
            ValueRange::Unknown | ValueRange::Unset => (i64::MIN, i64::MAX),
        };
        let next_min = min.unwrap_or(cur_min).max(cur_min);
        let next_max = max.unwrap_or(cur_max).min(cur_max);
        if next_min > next_max {
            ValueRange::Unknown
        } else {
            ValueRange::known(next_min, next_max)
        }
    }

    fn refine_range(
        &self,
        current: ValueRange,
        op: BinOpKind,
        value: i64,
        take_true: bool,
    ) -> ValueRange {
        let op = if take_true {
            op
        } else {
            let Some(negated) = self.negate_compare(op) else {
                return current;
            };
            negated
        };

        if matches!(op, BinOpKind::Ne) {
            return match current {
                ValueRange::Known { min, max } => {
                    if value < min || value > max {
                        ValueRange::Known { min, max }
                    } else if min == max {
                        ValueRange::Unknown
                    } else if value == min {
                        ValueRange::Known {
                            min: min.saturating_add(1),
                            max,
                        }
                    } else if value == max {
                        ValueRange::Known {
                            min,
                            max: max.saturating_sub(1),
                        }
                    } else {
                        ValueRange::Known { min, max }
                    }
                }
                ValueRange::Unknown | ValueRange::Unset => ValueRange::Unknown,
            };
        }

        let (min, max) = match op {
            BinOpKind::Eq => (Some(value), Some(value)),
            BinOpKind::Lt => (None, Some(value.saturating_sub(1))),
            BinOpKind::Le => (None, Some(value)),
            BinOpKind::Gt => (Some(value.saturating_add(1)), None),
            BinOpKind::Ge => (Some(value), None),
            _ => return current,
        };

        self.intersect_range(current, min, max)
    }

    pub(super) fn refine_range_branch(
        &self,
        state: &[ValueRange],
        source_ranges: &HashMap<RangeSource, ValueRange>,
        reg_sources: &HashMap<VReg, SlotSourceState>,
        cond: VReg,
        guards: &HashMap<VReg, RangeGuard>,
        take_true: bool,
    ) -> Option<(Vec<ValueRange>, HashMap<RangeSource, ValueRange>)> {
        let Some(guard) = guards.get(&cond).copied() else {
            return Some((state.to_vec(), source_ranges.clone()));
        };

        match guard {
            RangeGuard::CompareConst { reg, op, value } => {
                let effective_op = self.effective_branch_compare(op, take_true)?;
                let current = state
                    .get(reg.0 as usize)
                    .copied()
                    .unwrap_or(ValueRange::Unknown);
                if !self.range_can_satisfy_const_compare(current, effective_op, value) {
                    return None;
                }
                let mut next = state.to_vec();
                let mut next_source_ranges = source_ranges.clone();
                let refined = self.refine_range(current, op, value, take_true);
                self.set_state_range(&mut next, reg, refined);
                if matches!(refined, ValueRange::Known { .. })
                    && let Some(SlotSourceState::Known(source)) = reg_sources.get(&reg).cloned()
                {
                    next_source_ranges.insert(source, refined);
                }
                Some((next, next_source_ranges))
            }
        }
    }
}
