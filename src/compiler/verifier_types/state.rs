#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nullability {
    NonNull,
    MaybeNull,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueRange {
    Unknown,
    Known { min: i64, max: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtrOrigin {
    Stack(StackSlotId),
    Map,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PtrBounds {
    origin: PtrOrigin,
    min: i64,
    max: i64,
    limit: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifierType {
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
enum Guard {
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
struct VerifierState {
    regs: Vec<VerifierType>,
    ranges: Vec<ValueRange>,
    non_zero: Vec<bool>,
    not_equal: Vec<Vec<i64>>,
    live_ringbuf_refs: Vec<bool>,
    live_kfunc_refs: Vec<bool>,
    kfunc_ref_kinds: Vec<Option<KfuncRefKind>>,
    reachable: bool,
    guards: HashMap<VReg, Guard>,
}

impl VerifierState {
    const MAX_NOT_EQUAL_FACTS: usize = 8;

    fn new(total_vregs: usize) -> Self {
        Self {
            regs: vec![VerifierType::Uninit; total_vregs],
            ranges: vec![ValueRange::Unknown; total_vregs],
            non_zero: vec![false; total_vregs],
            not_equal: vec![Vec::new(); total_vregs],
            live_ringbuf_refs: vec![false; total_vregs],
            live_kfunc_refs: vec![false; total_vregs],
            kfunc_ref_kinds: vec![None; total_vregs],
            reachable: true,
            guards: HashMap::new(),
        }
    }

    fn get(&self, vreg: VReg) -> VerifierType {
        self.regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(VerifierType::Unknown)
    }

    fn get_range(&self, vreg: VReg) -> ValueRange {
        self.ranges
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(ValueRange::Unknown)
    }

    fn is_non_zero(&self, vreg: VReg) -> bool {
        self.non_zero.get(vreg.0 as usize).copied().unwrap_or(false)
    }

    fn not_equal_consts(&self, vreg: VReg) -> &[i64] {
        self.not_equal
            .get(vreg.0 as usize)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn set(&mut self, vreg: VReg, ty: VerifierType) {
        self.set_with_range(vreg, ty, ValueRange::Unknown);
    }

    fn set_with_range(&mut self, vreg: VReg, ty: VerifierType, range: ValueRange) {
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
        self.guards.remove(&vreg);
    }

    fn set_not_equal_const(&mut self, vreg: VReg, value: i64) {
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

    fn clear_not_equal_const(&mut self, vreg: VReg) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.clear();
        }
    }

    fn retain_not_equal_in_range(&mut self, vreg: VReg, range: ValueRange) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.retain(|value| range_may_equal(range, *value));
        }
    }

    fn mark_unreachable(&mut self) {
        self.reachable = false;
    }

    fn set_live_ringbuf_ref(&mut self, id: VReg, live: bool) {
        if let Some(slot) = self.live_ringbuf_refs.get_mut(id.0 as usize) {
            *slot = live;
        }
    }

    fn set_live_kfunc_ref(&mut self, id: VReg, live: bool, kind: Option<KfuncRefKind>) {
        if let Some(slot) = self.live_kfunc_refs.get_mut(id.0 as usize) {
            *slot = live;
        }
        if let Some(slot) = self.kfunc_ref_kinds.get_mut(id.0 as usize) {
            *slot = if live { kind } else { None };
        }
    }

    fn invalidate_ringbuf_ref(&mut self, id: VReg) {
        self.set_live_ringbuf_ref(id, false);
        for idx in 0..self.regs.len() {
            let reg = VReg(idx as u32);
            let is_ref = matches!(
                self.regs[idx],
                VerifierType::Ptr {
                    ringbuf_ref: Some(ref_id),
                    ..
                } if ref_id == id
            );
            if is_ref {
                self.regs[idx] = VerifierType::Unknown;
                self.ranges[idx] = ValueRange::Unknown;
                self.non_zero[idx] = false;
                self.not_equal[idx].clear();
                self.guards.remove(&reg);
            }
        }
    }

    fn invalidate_kfunc_ref(&mut self, id: VReg) {
        self.set_live_kfunc_ref(id, false, None);
        for idx in 0..self.regs.len() {
            let reg = VReg(idx as u32);
            let is_ref = matches!(
                self.regs[idx],
                VerifierType::Ptr {
                    kfunc_ref: Some(ref_id),
                    ..
                } if ref_id == id
            );
            if is_ref {
                self.regs[idx] = VerifierType::Unknown;
                self.ranges[idx] = ValueRange::Unknown;
                self.non_zero[idx] = false;
                self.not_equal[idx].clear();
                self.guards.remove(&reg);
            }
        }
    }

    fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    fn has_live_kfunc_refs(&self) -> bool {
        self.live_kfunc_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    fn is_live_kfunc_ref(&self, id: VReg) -> bool {
        self.live_kfunc_refs
            .get(id.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    fn kfunc_ref_kind(&self, id: VReg) -> Option<KfuncRefKind> {
        self.kfunc_ref_kinds.get(id.0 as usize).copied().flatten()
    }

    fn is_reachable(&self) -> bool {
        self.reachable
    }

    fn join(&self, other: &VerifierState) -> VerifierState {
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
            live_ringbuf_refs,
            live_kfunc_refs,
            kfunc_ref_kinds,
            reachable: true,
            guards,
        }
    }
}
