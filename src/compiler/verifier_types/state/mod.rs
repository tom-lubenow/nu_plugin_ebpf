use super::*;
use std::collections::HashSet;

mod join;
mod refs;

type UnknownStackObjectTypeKey = (String, Option<u32>);

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
    rcu_read_lock_min_depth: u32,
    rcu_read_lock_max_depth: u32,
    preempt_disable_min_depth: u32,
    preempt_disable_max_depth: u32,
    local_irq_disable_min_depth: u32,
    local_irq_disable_max_depth: u32,
    local_irq_disable_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_task_vma_min_depth: u32,
    iter_task_vma_max_depth: u32,
    iter_task_vma_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_task_min_depth: u32,
    iter_task_max_depth: u32,
    iter_task_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_scx_dsq_min_depth: u32,
    iter_scx_dsq_max_depth: u32,
    iter_scx_dsq_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_num_min_depth: u32,
    iter_num_max_depth: u32,
    iter_num_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_bits_min_depth: u32,
    iter_bits_max_depth: u32,
    iter_bits_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_css_min_depth: u32,
    iter_css_max_depth: u32,
    iter_css_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_css_task_min_depth: u32,
    iter_css_task_max_depth: u32,
    iter_css_task_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_dmabuf_min_depth: u32,
    iter_dmabuf_max_depth: u32,
    iter_dmabuf_slots: HashMap<StackSlotId, (u32, u32)>,
    iter_kmem_cache_min_depth: u32,
    iter_kmem_cache_max_depth: u32,
    iter_kmem_cache_slots: HashMap<StackSlotId, (u32, u32)>,
    res_spin_lock_min_depth: u32,
    res_spin_lock_max_depth: u32,
    res_spin_lock_irqsave_min_depth: u32,
    res_spin_lock_irqsave_max_depth: u32,
    res_spin_lock_irqsave_slots: HashMap<StackSlotId, (u32, u32)>,
    dynptr_initialized_slots: HashSet<StackSlotId>,
    unknown_stack_object_slots: HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
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
            rcu_read_lock_min_depth: 0,
            rcu_read_lock_max_depth: 0,
            preempt_disable_min_depth: 0,
            preempt_disable_max_depth: 0,
            local_irq_disable_min_depth: 0,
            local_irq_disable_max_depth: 0,
            local_irq_disable_slots: HashMap::new(),
            iter_task_vma_min_depth: 0,
            iter_task_vma_max_depth: 0,
            iter_task_vma_slots: HashMap::new(),
            iter_task_min_depth: 0,
            iter_task_max_depth: 0,
            iter_task_slots: HashMap::new(),
            iter_scx_dsq_min_depth: 0,
            iter_scx_dsq_max_depth: 0,
            iter_scx_dsq_slots: HashMap::new(),
            iter_num_min_depth: 0,
            iter_num_max_depth: 0,
            iter_num_slots: HashMap::new(),
            iter_bits_min_depth: 0,
            iter_bits_max_depth: 0,
            iter_bits_slots: HashMap::new(),
            iter_css_min_depth: 0,
            iter_css_max_depth: 0,
            iter_css_slots: HashMap::new(),
            iter_css_task_min_depth: 0,
            iter_css_task_max_depth: 0,
            iter_css_task_slots: HashMap::new(),
            iter_dmabuf_min_depth: 0,
            iter_dmabuf_max_depth: 0,
            iter_dmabuf_slots: HashMap::new(),
            iter_kmem_cache_min_depth: 0,
            iter_kmem_cache_max_depth: 0,
            iter_kmem_cache_slots: HashMap::new(),
            res_spin_lock_min_depth: 0,
            res_spin_lock_max_depth: 0,
            res_spin_lock_irqsave_min_depth: 0,
            res_spin_lock_irqsave_max_depth: 0,
            res_spin_lock_irqsave_slots: HashMap::new(),
            dynptr_initialized_slots: HashSet::new(),
            unknown_stack_object_slots: HashMap::new(),
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
}
