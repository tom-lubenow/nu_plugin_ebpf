use super::*;

mod refs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Nullability {
    NonNull,
    MaybeNull,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueRange {
    Unknown,
    Known { min: i64, max: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtrOrigin {
    Stack(StackSlotId),
    Map,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PtrBounds {
    origin: PtrOrigin,
    min: i64,
    max: i64,
    limit: i64,
}

impl PtrBounds {
    pub(super) fn new(origin: PtrOrigin, min: i64, max: i64, limit: i64) -> Self {
        Self {
            origin,
            min,
            max,
            limit,
        }
    }

    pub(super) fn origin(self) -> PtrOrigin {
        self.origin
    }

    pub(super) fn min(self) -> i64 {
        self.min
    }

    pub(super) fn max(self) -> i64 {
        self.max
    }

    pub(super) fn limit(self) -> i64 {
        self.limit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerifierType {
    Uninit,
    Unknown,
    Scalar,
    Bool,
    Ptr {
        space: AddressSpace,
        nullability: Nullability,
        bounds: Option<PtrBounds>,
        ringbuf_ref: Option<VReg>,
        kfunc_ref: Option<VReg>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Guard {
    Ptr {
        ptr: VReg,
        true_is_non_null: bool,
    },
    NonZero {
        reg: VReg,
        true_is_non_zero: bool,
    },
    Range {
        reg: VReg,
        op: BinOpKind,
        value: i64,
    },
    RangeCmp {
        lhs: VReg,
        rhs: VReg,
        op: BinOpKind,
    },
}

#[derive(Debug, Clone)]
pub(super) struct VerifierState {
    regs: Vec<VerifierType>,
    ranges: Vec<ValueRange>,
    non_zero: Vec<bool>,
    not_equal: Vec<Vec<i64>>,
    ctx_field_sources: Vec<Option<CtxField>>,
    live_ringbuf_refs: Vec<bool>,
    live_kfunc_refs: Vec<bool>,
    kfunc_ref_kinds: Vec<Option<KfuncRefKind>>,
    reachable: bool,
    guards: HashMap<VReg, Guard>,
}

impl VerifierState {
    const MAX_NOT_EQUAL_FACTS: usize = 8;

    pub(super) fn new(total_vregs: usize) -> Self {
        Self {
            regs: vec![VerifierType::Uninit; total_vregs],
            ranges: vec![ValueRange::Unknown; total_vregs],
            non_zero: vec![false; total_vregs],
            not_equal: vec![Vec::new(); total_vregs],
            ctx_field_sources: vec![None; total_vregs],
            live_ringbuf_refs: vec![false; total_vregs],
            live_kfunc_refs: vec![false; total_vregs],
            kfunc_ref_kinds: vec![None; total_vregs],
            reachable: true,
            guards: HashMap::new(),
        }
    }

    pub(super) fn get(&self, vreg: VReg) -> VerifierType {
        self.regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(VerifierType::Unknown)
    }

    pub(super) fn get_range(&self, vreg: VReg) -> ValueRange {
        self.ranges
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(ValueRange::Unknown)
    }

    pub(super) fn is_non_zero(&self, vreg: VReg) -> bool {
        self.non_zero.get(vreg.0 as usize).copied().unwrap_or(false)
    }

    pub(super) fn set_non_zero(&mut self, vreg: VReg, non_zero: bool) {
        if let Some(slot) = self.non_zero.get_mut(vreg.0 as usize) {
            *slot = non_zero;
        }
    }

    pub(super) fn guard(&self, vreg: VReg) -> Option<Guard> {
        self.guards.get(&vreg).copied()
    }

    pub(super) fn set_guard(&mut self, vreg: VReg, guard: Guard) {
        self.guards.insert(vreg, guard);
    }

    pub(super) fn set_range(&mut self, vreg: VReg, range: ValueRange) {
        if let Some(slot) = self.ranges.get_mut(vreg.0 as usize) {
            *slot = range;
        }
    }

    pub(super) fn not_equal_consts(&self, vreg: VReg) -> &[i64] {
        self.not_equal
            .get(vreg.0 as usize)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(super) fn set(&mut self, vreg: VReg, ty: VerifierType) {
        self.set_with_range(vreg, ty, ValueRange::Unknown);
    }

    pub(super) fn set_with_range(&mut self, vreg: VReg, ty: VerifierType, range: ValueRange) {
        if let Some(slot) = self.regs.get_mut(vreg.0 as usize) {
            *slot = ty;
        }
        if let Some(slot) = self.ranges.get_mut(vreg.0 as usize) {
            *slot = range;
        }
        if let Some(slot) = self.non_zero.get_mut(vreg.0 as usize) {
            *slot = false;
        }
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.clear();
        }
        if let Some(slot) = self.ctx_field_sources.get_mut(vreg.0 as usize) {
            *slot = None;
        }
        self.guards.remove(&vreg);
    }

    pub(super) fn set_ctx_field_source(&mut self, vreg: VReg, source: Option<CtxField>) {
        if let Some(slot) = self.ctx_field_sources.get_mut(vreg.0 as usize) {
            *slot = source;
        }
    }

    pub(super) fn ctx_field_source(&self, vreg: VReg) -> Option<&CtxField> {
        self.ctx_field_sources
            .get(vreg.0 as usize)
            .and_then(|source| source.as_ref())
    }

    pub(super) fn find_ctx_field_type(&self, field: &CtxField) -> Option<VerifierType> {
        for (idx, source) in self.ctx_field_sources.iter().enumerate() {
            if source.as_ref() == Some(field) {
                let ty = self.regs[idx];
                if !matches!(ty, VerifierType::Uninit) {
                    return Some(ty);
                }
            }
        }
        None
    }

    pub(super) fn refine_ctx_field_nullability(
        &mut self,
        field: &CtxField,
        nullability: Nullability,
    ) {
        for idx in 0..self.ctx_field_sources.len() {
            if self.ctx_field_sources[idx].as_ref() != Some(field) {
                continue;
            }
            if let VerifierType::Ptr {
                space,
                bounds,
                ringbuf_ref,
                kfunc_ref,
                ..
            } = self.regs[idx]
            {
                self.regs[idx] = VerifierType::Ptr {
                    space,
                    nullability,
                    bounds,
                    ringbuf_ref,
                    kfunc_ref,
                };
            }
        }
    }

    pub(super) fn set_not_equal_const(&mut self, vreg: VReg, value: i64) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            if !slot.contains(&value) {
                slot.push(value);
                slot.sort_unstable();
                if slot.len() > Self::MAX_NOT_EQUAL_FACTS {
                    slot.remove(0);
                }
            }
        }
    }

    pub(super) fn clear_not_equal_const(&mut self, vreg: VReg) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.clear();
        }
    }

    pub(super) fn retain_not_equal_in_range(&mut self, vreg: VReg, range: ValueRange) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.retain(|value| range_may_equal(range, *value));
        }
    }

    pub(super) fn mark_unreachable(&mut self) {
        self.reachable = false;
    }

    pub(super) fn is_reachable(&self) -> bool {
        self.reachable
    }

    pub(super) fn equivalent(&self, other: &VerifierState) -> bool {
        self.regs == other.regs
            && self.ranges == other.ranges
            && self.non_zero == other.non_zero
            && self.not_equal == other.not_equal
            && self.ctx_field_sources == other.ctx_field_sources
            && self.live_ringbuf_refs == other.live_ringbuf_refs
            && self.live_kfunc_refs == other.live_kfunc_refs
            && self.kfunc_ref_kinds == other.kfunc_ref_kinds
            && self.guards == other.guards
            && self.reachable == other.reachable
    }

    pub(super) fn join(&self, other: &VerifierState) -> VerifierState {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }

        let mut regs = Vec::with_capacity(self.regs.len());
        for i in 0..self.regs.len() {
            let a = self.regs[i];
            let b = other.regs[i];
            regs.push(join_type(a, b));
        }
        let mut ranges = Vec::with_capacity(self.ranges.len());
        for i in 0..self.ranges.len() {
            let a = self.ranges[i];
            let b = other.ranges[i];
            ranges.push(join_range(a, b));
        }
        let mut non_zero = Vec::with_capacity(self.non_zero.len());
        for i in 0..self.non_zero.len() {
            non_zero.push(self.non_zero[i] && other.non_zero[i]);
        }
        let mut not_equal = Vec::with_capacity(self.not_equal.len());
        for i in 0..self.not_equal.len() {
            let left = &self.not_equal[i];
            let right = &other.not_equal[i];
            if left.is_empty() || right.is_empty() {
                not_equal.push(Vec::new());
                continue;
            }
            let mut shared = Vec::new();
            for value in left {
                if right.contains(value) {
                    shared.push(*value);
                }
            }
            not_equal.push(shared);
        }
        let mut ctx_field_sources = Vec::with_capacity(self.ctx_field_sources.len());
        for i in 0..self.ctx_field_sources.len() {
            let merged = match (&self.ctx_field_sources[i], &other.ctx_field_sources[i]) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                _ => None,
            };
            ctx_field_sources.push(merged);
        }
        let mut live_ringbuf_refs = Vec::with_capacity(self.live_ringbuf_refs.len());
        for i in 0..self.live_ringbuf_refs.len() {
            live_ringbuf_refs.push(self.live_ringbuf_refs[i] || other.live_ringbuf_refs[i]);
        }
        let mut live_kfunc_refs = Vec::with_capacity(self.live_kfunc_refs.len());
        let mut kfunc_ref_kinds = Vec::with_capacity(self.kfunc_ref_kinds.len());
        for i in 0..self.live_kfunc_refs.len() {
            let left_live = self.live_kfunc_refs[i];
            let right_live = other.live_kfunc_refs[i];
            let live = left_live || right_live;
            live_kfunc_refs.push(live);

            let left_kind = if left_live {
                self.kfunc_ref_kinds[i]
            } else {
                None
            };
            let right_kind = if right_live {
                other.kfunc_ref_kinds[i]
            } else {
                None
            };
            let merged_kind = match (left_kind, right_kind) {
                (Some(a), Some(b)) if a == b => Some(a),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (Some(_), Some(_)) => None,
                (None, None) => None,
            };
            kfunc_ref_kinds.push(merged_kind);
        }
        let mut guards = HashMap::new();
        for (reg, left) in &self.guards {
            if let Some(right) = other.guards.get(reg)
                && left == right
            {
                guards.insert(*reg, *left);
            }
        }
        VerifierState {
            regs,
            ranges,
            non_zero,
            not_equal,
            ctx_field_sources,
            live_ringbuf_refs,
            live_kfunc_refs,
            kfunc_ref_kinds,
            reachable: true,
            guards,
        }
    }
}
