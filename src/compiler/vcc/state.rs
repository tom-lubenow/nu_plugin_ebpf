#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VccState {
    reg_types: HashMap<VccReg, VccValueType>,
    not_equal_consts: HashMap<VccReg, Vec<i64>>,
    live_ringbuf_refs: HashMap<VccReg, bool>,
    live_kfunc_refs: HashMap<VccReg, Option<KfuncRefKind>>,
    rcu_read_lock_min_depth: u32,
    rcu_read_lock_max_depth: u32,
    preempt_disable_min_depth: u32,
    preempt_disable_max_depth: u32,
    local_irq_disable_min_depth: u32,
    local_irq_disable_max_depth: u32,
    res_spin_lock_min_depth: u32,
    res_spin_lock_max_depth: u32,
    res_spin_lock_irqsave_min_depth: u32,
    res_spin_lock_irqsave_max_depth: u32,
    cond_refinements: HashMap<VccReg, VccCondRefinement>,
    reachable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VccCondRefinement {
    PtrNull {
        ptr_reg: VccReg,
        ringbuf_ref: Option<VccReg>,
        kfunc_ref: Option<VccReg>,
        true_means_non_null: bool,
    },
    ScalarCmpConst {
        reg: VccReg,
        op: VccBinOp,
        value: i64,
    },
    ScalarCmpRegs {
        lhs: VccReg,
        rhs: VccReg,
        op: VccBinOp,
    },
}

impl VccState {
    const MAX_NOT_EQUAL_FACTS: usize = 8;

    fn with_seed(seed: HashMap<VccReg, VccValueType>) -> Self {
        Self {
            reg_types: seed,
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: HashMap::new(),
            live_kfunc_refs: HashMap::new(),
            rcu_read_lock_min_depth: 0,
            rcu_read_lock_max_depth: 0,
            preempt_disable_min_depth: 0,
            preempt_disable_max_depth: 0,
            local_irq_disable_min_depth: 0,
            local_irq_disable_max_depth: 0,
            res_spin_lock_min_depth: 0,
            res_spin_lock_max_depth: 0,
            res_spin_lock_irqsave_min_depth: 0,
            res_spin_lock_irqsave_max_depth: 0,
            cond_refinements: HashMap::new(),
            reachable: true,
        }
    }

    fn is_reachable(&self) -> bool {
        self.reachable
    }

    fn mark_unreachable(&mut self) {
        self.reachable = false;
    }

    fn set_reg(&mut self, reg: VccReg, ty: VccValueType) {
        self.reg_types.insert(reg, ty);
        self.not_equal_consts.remove(&reg);
        self.cond_refinements.remove(&reg);
    }

    fn set_not_equal_const(&mut self, reg: VccReg, value: i64) {
        let slot = self.not_equal_consts.entry(reg).or_default();
        if slot.contains(&value) {
            return;
        }
        slot.push(value);
        slot.sort_unstable();
        if slot.len() > Self::MAX_NOT_EQUAL_FACTS {
            slot.remove(0);
        }
    }

    fn clear_not_equal_consts(&mut self, reg: VccReg) {
        self.not_equal_consts.remove(&reg);
    }

    fn not_equal_consts(&self, reg: VccReg) -> &[i64] {
        self.not_equal_consts
            .get(&reg)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn retain_not_equal_in_range(&mut self, reg: VccReg, range: Option<VccRange>) {
        let Some(slot) = self.not_equal_consts.get_mut(&reg) else {
            return;
        };
        if let Some(range) = range {
            slot.retain(|value| *value >= range.min && *value <= range.max);
            if slot.is_empty() {
                self.not_equal_consts.remove(&reg);
            }
        }
    }

    fn set_live_ringbuf_ref(&mut self, id: VccReg, live: bool) {
        self.live_ringbuf_refs.insert(id, live);
    }

    fn set_live_kfunc_ref(&mut self, id: VccReg, live: bool, kind: Option<KfuncRefKind>) {
        if live {
            self.live_kfunc_refs.insert(id, kind);
        } else {
            self.live_kfunc_refs.remove(&id);
        }
    }

    fn set_cond_refinement(&mut self, reg: VccReg, refinement: VccCondRefinement) {
        self.cond_refinements.insert(reg, refinement);
    }

    fn cond_refinement(&self, reg: VccReg) -> Option<VccCondRefinement> {
        self.cond_refinements.get(&reg).copied()
    }

    fn is_live_ringbuf_ref(&self, id: VccReg) -> bool {
        self.live_ringbuf_refs.get(&id).copied().unwrap_or(false)
    }

    fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs
            .values()
            .copied()
            .any(std::convert::identity)
    }

    fn is_live_kfunc_ref(&self, id: VccReg) -> bool {
        self.live_kfunc_refs.contains_key(&id)
    }

    fn has_live_kfunc_refs(&self) -> bool {
        !self.live_kfunc_refs.is_empty()
    }

    fn acquire_rcu_read_lock(&mut self) {
        self.rcu_read_lock_min_depth = self.rcu_read_lock_min_depth.saturating_add(1);
        self.rcu_read_lock_max_depth = self.rcu_read_lock_max_depth.saturating_add(1);
    }

    fn release_rcu_read_lock(&mut self) -> bool {
        if self.rcu_read_lock_min_depth == 0 {
            return false;
        }
        self.rcu_read_lock_min_depth -= 1;
        self.rcu_read_lock_max_depth -= 1;
        true
    }

    fn has_live_rcu_read_lock(&self) -> bool {
        self.rcu_read_lock_max_depth > 0
    }

    fn acquire_preempt_disable(&mut self) {
        self.preempt_disable_min_depth = self.preempt_disable_min_depth.saturating_add(1);
        self.preempt_disable_max_depth = self.preempt_disable_max_depth.saturating_add(1);
    }

    fn release_preempt_disable(&mut self) -> bool {
        if self.preempt_disable_min_depth == 0 {
            return false;
        }
        self.preempt_disable_min_depth -= 1;
        self.preempt_disable_max_depth -= 1;
        true
    }

    fn has_live_preempt_disable(&self) -> bool {
        self.preempt_disable_max_depth > 0
    }

    fn acquire_local_irq_disable(&mut self) {
        self.local_irq_disable_min_depth = self.local_irq_disable_min_depth.saturating_add(1);
        self.local_irq_disable_max_depth = self.local_irq_disable_max_depth.saturating_add(1);
    }

    fn release_local_irq_disable(&mut self) -> bool {
        if self.local_irq_disable_min_depth == 0 {
            return false;
        }
        self.local_irq_disable_min_depth -= 1;
        self.local_irq_disable_max_depth -= 1;
        true
    }

    fn has_live_local_irq_disable(&self) -> bool {
        self.local_irq_disable_max_depth > 0
    }

    fn acquire_res_spin_lock(&mut self) {
        self.res_spin_lock_min_depth = self.res_spin_lock_min_depth.saturating_add(1);
        self.res_spin_lock_max_depth = self.res_spin_lock_max_depth.saturating_add(1);
    }

    fn release_res_spin_lock(&mut self) -> bool {
        if self.res_spin_lock_min_depth == 0 {
            return false;
        }
        self.res_spin_lock_min_depth -= 1;
        self.res_spin_lock_max_depth -= 1;
        true
    }

    fn has_live_res_spin_lock(&self) -> bool {
        self.res_spin_lock_max_depth > 0
    }

    fn acquire_res_spin_lock_irqsave(&mut self) {
        self.res_spin_lock_irqsave_min_depth =
            self.res_spin_lock_irqsave_min_depth.saturating_add(1);
        self.res_spin_lock_irqsave_max_depth =
            self.res_spin_lock_irqsave_max_depth.saturating_add(1);
    }

    fn release_res_spin_lock_irqsave(&mut self) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth -= 1;
        self.res_spin_lock_irqsave_max_depth -= 1;
        true
    }

    fn has_live_res_spin_lock_irqsave(&self) -> bool {
        self.res_spin_lock_irqsave_max_depth > 0
    }

    fn kfunc_ref_kind(&self, id: VccReg) -> Option<KfuncRefKind> {
        self.live_kfunc_refs.get(&id).copied().flatten()
    }

    fn invalidate_ringbuf_ref(&mut self, id: VccReg) {
        self.set_live_ringbuf_ref(id, false);
        for (reg, ty) in self.reg_types.iter_mut() {
            let matches_ref = matches!(
                ty,
                VccValueType::Ptr(VccPointerInfo {
                    ringbuf_ref: Some(ref_id),
                    ..
                }) if *ref_id == id
            );
            if matches_ref {
                *ty = VccValueType::Unknown;
                self.not_equal_consts.remove(reg);
            }
        }
        self.cond_refinements.retain(|_, info| match info {
            VccCondRefinement::PtrNull { ringbuf_ref, .. } => *ringbuf_ref != Some(id),
            VccCondRefinement::ScalarCmpConst { .. } => true,
            VccCondRefinement::ScalarCmpRegs { .. } => true,
        });
    }

    fn invalidate_kfunc_ref(&mut self, id: VccReg) {
        self.set_live_kfunc_ref(id, false, None);
        for (reg, ty) in self.reg_types.iter_mut() {
            let matches_ref = matches!(
                ty,
                VccValueType::Ptr(VccPointerInfo {
                    kfunc_ref: Some(ref_id),
                    ..
                }) if *ref_id == id
            );
            if matches_ref {
                *ty = VccValueType::Unknown;
                self.not_equal_consts.remove(reg);
            }
        }
        self.cond_refinements.retain(|_, info| match info {
            VccCondRefinement::PtrNull { kfunc_ref, .. } => *kfunc_ref != Some(id),
            VccCondRefinement::ScalarCmpConst { .. } => true,
            VccCondRefinement::ScalarCmpRegs { .. } => true,
        });
    }

    fn merge_with(&self, other: &VccState) -> VccState {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }
        let mut merged = self.reg_types.clone();
        for (reg, rhs) in &other.reg_types {
            match merged.get(reg).copied() {
                Some(lhs) => {
                    merged.insert(*reg, self.merge_types(lhs, *rhs));
                }
                None => {
                    merged.insert(*reg, *rhs);
                }
            }
        }
        let mut live_ringbuf_refs = self.live_ringbuf_refs.clone();
        for (id, live) in &other.live_ringbuf_refs {
            let current = live_ringbuf_refs.get(id).copied().unwrap_or(false);
            live_ringbuf_refs.insert(*id, current || *live);
        }
        let mut live_kfunc_refs = self.live_kfunc_refs.clone();
        for id in other.live_kfunc_refs.keys() {
            let left_kind = live_kfunc_refs.get(id).copied().flatten();
            let right_kind = other.live_kfunc_refs.get(id).copied().flatten();
            let merged_kind = match (left_kind, right_kind) {
                (Some(a), Some(b)) if a == b => Some(a),
                (Some(_), Some(_)) => None,
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            };
            live_kfunc_refs.insert(*id, merged_kind);
        }
        let mut cond_refinements = HashMap::new();
        for (reg, left) in &self.cond_refinements {
            if let Some(right) = other.cond_refinements.get(reg) {
                if left == right {
                    cond_refinements.insert(*reg, *left);
                }
            }
        }
        let mut not_equal_consts = HashMap::new();
        for (reg, left) in &self.not_equal_consts {
            let Some(right) = other.not_equal_consts.get(reg) else {
                continue;
            };
            if left.is_empty() || right.is_empty() {
                continue;
            }
            let mut shared = Vec::new();
            for value in left {
                if right.contains(value) {
                    shared.push(*value);
                }
            }
            if !shared.is_empty() {
                not_equal_consts.insert(*reg, shared);
            }
        }
        VccState {
            reg_types: merged,
            not_equal_consts,
            live_ringbuf_refs,
            live_kfunc_refs,
            rcu_read_lock_min_depth: self
                .rcu_read_lock_min_depth
                .min(other.rcu_read_lock_min_depth),
            rcu_read_lock_max_depth: self
                .rcu_read_lock_max_depth
                .max(other.rcu_read_lock_max_depth),
            preempt_disable_min_depth: self
                .preempt_disable_min_depth
                .min(other.preempt_disable_min_depth),
            preempt_disable_max_depth: self
                .preempt_disable_max_depth
                .max(other.preempt_disable_max_depth),
            local_irq_disable_min_depth: self
                .local_irq_disable_min_depth
                .min(other.local_irq_disable_min_depth),
            local_irq_disable_max_depth: self
                .local_irq_disable_max_depth
                .max(other.local_irq_disable_max_depth),
            res_spin_lock_min_depth: self
                .res_spin_lock_min_depth
                .min(other.res_spin_lock_min_depth),
            res_spin_lock_max_depth: self
                .res_spin_lock_max_depth
                .max(other.res_spin_lock_max_depth),
            res_spin_lock_irqsave_min_depth: self
                .res_spin_lock_irqsave_min_depth
                .min(other.res_spin_lock_irqsave_min_depth),
            res_spin_lock_irqsave_max_depth: self
                .res_spin_lock_irqsave_max_depth
                .max(other.res_spin_lock_irqsave_max_depth),
            cond_refinements,
            reachable: true,
        }
    }

    fn widened(&self) -> VccState {
        let mut widened = HashMap::new();
        for (reg, ty) in &self.reg_types {
            let widened_ty = match ty {
                VccValueType::Scalar { .. } => VccValueType::Scalar { range: None },
                VccValueType::Ptr(ptr) => VccValueType::Ptr(VccPointerInfo {
                    space: ptr.space,
                    nullability: VccNullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                }),
                VccValueType::Bool => VccValueType::Bool,
                VccValueType::Unknown => VccValueType::Unknown,
                VccValueType::Uninit => VccValueType::Uninit,
            };
            widened.insert(*reg, widened_ty);
        }
        VccState {
            reg_types: widened,
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: self.live_ringbuf_refs.clone(),
            live_kfunc_refs: self.live_kfunc_refs.clone(),
            rcu_read_lock_min_depth: self.rcu_read_lock_min_depth,
            rcu_read_lock_max_depth: self.rcu_read_lock_max_depth,
            preempt_disable_min_depth: self.preempt_disable_min_depth,
            preempt_disable_max_depth: self.preempt_disable_max_depth,
            local_irq_disable_min_depth: self.local_irq_disable_min_depth,
            local_irq_disable_max_depth: self.local_irq_disable_max_depth,
            res_spin_lock_min_depth: self.res_spin_lock_min_depth,
            res_spin_lock_max_depth: self.res_spin_lock_max_depth,
            res_spin_lock_irqsave_min_depth: self.res_spin_lock_irqsave_min_depth,
            res_spin_lock_irqsave_max_depth: self.res_spin_lock_irqsave_max_depth,
            cond_refinements: HashMap::new(),
            reachable: self.reachable,
        }
    }

    fn reg_type(&self, reg: VccReg) -> Result<VccValueType, VccError> {
        match self.reg_types.get(&reg).copied() {
            Some(VccValueType::Uninit) | None => Err(VccError::new(
                VccErrorKind::UseOfUninitializedReg(reg),
                format!("use of uninitialized reg {:?}", reg),
            )),
            Some(ty) => Ok(ty),
        }
    }

    fn value_type(&self, value: VccValue) -> Result<VccValueType, VccError> {
        match value {
            VccValue::Imm(v) => Ok(VccValueType::Scalar {
                range: Some(VccRange { min: v, max: v }),
            }),
            VccValue::Reg(reg) => self.reg_type(reg),
        }
    }

    fn value_range(&self, value: VccValue, ty: VccValueType) -> Option<VccRange> {
        match value {
            VccValue::Imm(v) => Some(VccRange { min: v, max: v }),
            VccValue::Reg(_) => match ty {
                VccValueType::Scalar { range } => range,
                VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
                _ => None,
            },
        }
    }

    fn binop_range(
        &self,
        op: VccBinOp,
        lhs_value: VccValue,
        lhs: VccValueType,
        rhs_value: VccValue,
        rhs: VccValueType,
    ) -> Option<VccRange> {
        let lhs_range = match lhs {
            VccValueType::Scalar { range } => range,
            VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
            _ => None,
        }?;
        let rhs_range = match rhs {
            VccValueType::Scalar { range } => range,
            VccValueType::Bool => Some(VccRange { min: 0, max: 1 }),
            _ => None,
        }?;
        let rhs_non_zero = self.value_excludes_zero(rhs_value, Some(rhs_range));
        let _lhs_non_zero = self.value_excludes_zero(lhs_value, Some(lhs_range));

        match op {
            VccBinOp::Add => Some(lhs_range.add(rhs_range)),
            VccBinOp::Sub => Some(lhs_range.sub(rhs_range)),
            VccBinOp::Mul => Some(self.mul_range(lhs_range, rhs_range)),
            VccBinOp::Div => self.div_range(lhs_range, rhs_range, rhs_non_zero),
            VccBinOp::Mod => self.mod_range(lhs_range, rhs_range, rhs_non_zero),
            VccBinOp::And => self.and_range(lhs_range, rhs_range),
            VccBinOp::Or => self.or_range(lhs_range, rhs_range),
            VccBinOp::Xor => self.xor_range(lhs_range, rhs_range),
            VccBinOp::Shl => self.shl_range(lhs_range, rhs_range),
            VccBinOp::Shr => self.shr_range(lhs_range, rhs_range),
            _ => None,
        }
    }

    fn mul_range(&self, lhs: VccRange, rhs: VccRange) -> VccRange {
        let candidates = [
            lhs.min.saturating_mul(rhs.min),
            lhs.min.saturating_mul(rhs.max),
            lhs.max.saturating_mul(rhs.min),
            lhs.max.saturating_mul(rhs.max),
        ];
        let mut min = candidates[0];
        let mut max = candidates[0];
        for value in candidates.iter().copied() {
            min = min.min(value);
            max = max.max(value);
        }
        VccRange { min, max }
    }

    fn div_range(&self, lhs: VccRange, rhs: VccRange, rhs_non_zero: bool) -> Option<VccRange> {
        let rhs = Self::effective_non_zero_range(rhs, rhs_non_zero)?;
        let divisors = [rhs.min, rhs.max];
        let numerators = [lhs.min, lhs.max];
        let mut min = i64::MAX;
        let mut max = i64::MIN;
        let mut any = false;
        for numerator in numerators {
            for divisor in divisors {
                let Some(value) = numerator.checked_div(divisor) else {
                    continue;
                };
                min = min.min(value);
                max = max.max(value);
                any = true;
            }
        }
        if any {
            Some(VccRange { min, max })
        } else {
            None
        }
    }

    fn mod_range(&self, lhs: VccRange, rhs: VccRange, rhs_non_zero: bool) -> Option<VccRange> {
        let rhs = Self::effective_non_zero_range(rhs, rhs_non_zero)?;
        let abs_min = (rhs.min as i128).abs();
        let abs_max = (rhs.max as i128).abs();
        let max_abs = abs_min.max(abs_max);
        if max_abs == 0 {
            return None;
        }
        let bound = (max_abs - 1).min(i64::MAX as i128) as i64;
        if lhs.min >= 0 {
            Some(VccRange { min: 0, max: bound })
        } else if lhs.max <= 0 {
            Some(VccRange {
                min: -bound,
                max: 0,
            })
        } else {
            Some(VccRange {
                min: -bound,
                max: bound,
            })
        }
    }

    fn and_range(&self, lhs: VccRange, rhs: VccRange) -> Option<VccRange> {
        if lhs.min < 0 || rhs.min < 0 {
            return None;
        }
        Some(VccRange {
            min: 0,
            max: lhs.max.min(rhs.max),
        })
    }

    fn or_range(&self, lhs: VccRange, rhs: VccRange) -> Option<VccRange> {
        if lhs.min < 0 || rhs.min < 0 {
            return None;
        }
        Some(VccRange {
            min: 0,
            max: lhs.max | rhs.max,
        })
    }

    fn xor_range(&self, lhs: VccRange, rhs: VccRange) -> Option<VccRange> {
        if lhs.min < 0 || rhs.min < 0 {
            return None;
        }
        Some(VccRange {
            min: 0,
            max: lhs.max | rhs.max,
        })
    }

    fn shl_range(&self, lhs: VccRange, rhs: VccRange) -> Option<VccRange> {
        if lhs.min < 0 || rhs.min < 0 || rhs.min != rhs.max {
            return None;
        }
        let shift = u32::try_from(rhs.min).ok()?;
        if shift >= i64::BITS {
            return None;
        }
        let min = lhs.min.checked_shl(shift)?;
        let max = lhs.max.checked_shl(shift)?;
        Some(VccRange { min, max })
    }

    fn shr_range(&self, lhs: VccRange, rhs: VccRange) -> Option<VccRange> {
        if lhs.min < 0 || rhs.min < 0 || rhs.min != rhs.max {
            return None;
        }
        let shift = u32::try_from(rhs.min).ok()?;
        if shift >= i64::BITS {
            return None;
        }
        Some(VccRange {
            min: lhs.min >> shift,
            max: lhs.max >> shift,
        })
    }

    fn effective_non_zero_range(range: VccRange, non_zero: bool) -> Option<VccRange> {
        if range.min <= 0 && range.max >= 0 {
            if !non_zero {
                return None;
            }
            if range.min == 0 {
                return Some(VccRange {
                    min: 1,
                    max: range.max,
                });
            }
            if range.max == 0 {
                return Some(VccRange {
                    min: range.min,
                    max: -1,
                });
            }
            return None;
        }
        Some(range)
    }

    fn value_excludes_zero(&self, value: VccValue, range: Option<VccRange>) -> bool {
        match value {
            VccValue::Imm(v) => v != 0,
            VccValue::Reg(reg) => {
                self.not_equal_consts(reg).contains(&0)
                    || matches!(range, Some(VccRange { min, max }) if min > 0 || max < 0)
            }
        }
    }

    fn merge_types(&self, lhs: VccValueType, rhs: VccValueType) -> VccValueType {
        match (lhs, rhs) {
            (VccValueType::Scalar { range: l }, VccValueType::Scalar { range: r }) => {
                VccValueType::Scalar {
                    range: match (l, r) {
                        (Some(lr), Some(rr)) => Some(VccRange {
                            min: lr.min.min(rr.min),
                            max: lr.max.max(rr.max),
                        }),
                        _ => None,
                    },
                }
            }
            (VccValueType::Ptr(lp), VccValueType::Ptr(rp)) if lp.space == rp.space => {
                let bounds = match (lp.bounds, rp.bounds) {
                    (Some(l), Some(r)) if l.limit == r.limit => Some(VccBounds {
                        min: l.min.min(r.min),
                        max: l.max.max(r.max),
                        limit: l.limit,
                    }),
                    _ => None,
                };
                let ringbuf_ref = match (lp.ringbuf_ref, rp.ringbuf_ref) {
                    (Some(a), Some(b)) if a == b => Some(a),
                    _ => None,
                };
                let kfunc_ref = match (lp.kfunc_ref, rp.kfunc_ref) {
                    (Some(a), Some(b)) if a == b => Some(a),
                    _ => None,
                };
                let nullability = Self::join_nullability(lp.nullability, rp.nullability);
                VccValueType::Ptr(VccPointerInfo {
                    space: lp.space,
                    nullability,
                    bounds,
                    ringbuf_ref,
                    kfunc_ref,
                })
            }
            (left, right) if left == right => left,
            _ => VccValueType::Unknown,
        }
    }

    fn join_nullability(lhs: VccNullability, rhs: VccNullability) -> VccNullability {
        match (lhs, rhs) {
            (VccNullability::NonNull, VccNullability::NonNull) => VccNullability::NonNull,
            (VccNullability::Null, VccNullability::Null) => VccNullability::Null,
            _ => VccNullability::MaybeNull,
        }
    }
}
