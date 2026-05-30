use super::*;
use std::collections::HashSet;

mod join;
mod refs;

type UnknownStackObjectTypeKey = (String, Option<u32>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ResSpinLockIdentity {
    Reg(VReg),
    CtxField(CtxField),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResSpinLockFrame {
    identity: ResSpinLockIdentity,
    irqsave_slot: Option<StackSlotId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BpfSpinLockIdentity {
    Reg(VReg),
    MapBounds {
        root: VReg,
        min: i64,
        max: i64,
        limit: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MapLookupSource {
    pub map: MapRef,
    pub key: VReg,
}

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
    Map(VReg),
    Packet(VReg),
    ContextBuffer(VReg),
    KernelBtf(VReg),
}

pub(super) const UNKNOWN_PACKET_LIMIT: i64 = i64::MAX / 4;
pub(super) const UNKNOWN_CONTEXT_BUFFER_LIMIT: i64 = i64::MAX / 4;
pub(super) const UNKNOWN_KERNEL_BTF_LIMIT: i64 = i64::MAX / 4;

fn value_range_satisfies_only<F>(range: ValueRange, predicate: &F) -> bool
where
    F: Fn(i64) -> bool,
{
    match range {
        ValueRange::Known { min, max } if min <= max => {
            let width = max.saturating_sub(min);
            width <= 64 && (min..=max).all(predicate)
        }
        _ => false,
    }
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

    pub(super) fn with_limit(self, limit: i64) -> Self {
        Self {
            origin: self.origin,
            min: self.min,
            max: self.max,
            limit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerifierType {
    Uninit,
    Unknown,
    StalePacketPtr,
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
    PacketEnd {
        ptr: VReg,
        op: BinOpKind,
    },
    ContextBufferEnd {
        ptr: VReg,
        op: BinOpKind,
    },
}

#[derive(Debug, Clone)]
pub(super) struct VerifierState {
    regs: Vec<VerifierType>,
    ranges: Vec<ValueRange>,
    scalar_alias_roots: Vec<Option<VReg>>,
    non_zero: Vec<bool>,
    not_equal: Vec<Vec<i64>>,
    ctx_field_sources: Vec<Option<CtxField>>,
    map_lookup_sources: Vec<Option<MapLookupSource>>,
    map_fd_sources: Vec<Option<MapRef>>,
    live_ringbuf_refs: Vec<bool>,
    released_ringbuf_record_regs: Vec<bool>,
    live_kfunc_refs: Vec<bool>,
    released_kfunc_ref_regs: Vec<bool>,
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
    bpf_spin_lock_min_depth: u32,
    bpf_spin_lock_max_depth: u32,
    bpf_spin_lock_identity: Option<BpfSpinLockIdentity>,
    res_spin_lock_irqsave_min_depth: u32,
    res_spin_lock_irqsave_max_depth: u32,
    res_spin_lock_irqsave_slots: HashMap<StackSlotId, (u32, u32)>,
    res_spin_lock_stack: Option<Vec<ResSpinLockFrame>>,
    dynptr_initialized_slots: HashSet<StackSlotId>,
    maybe_initialized_dynptr_slots: HashSet<StackSlotId>,
    ringbuf_dynptr_slots: HashMap<StackSlotId, (u32, u32)>,
    ringbuf_dynptr_alias_roots: HashMap<StackSlotId, StackSlotId>,
    released_ringbuf_dynptr_slots: HashSet<StackSlotId>,
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
            scalar_alias_roots: vec![None; total_vregs],
            non_zero: vec![false; total_vregs],
            not_equal: vec![Vec::new(); total_vregs],
            ctx_field_sources: vec![None; total_vregs],
            map_lookup_sources: vec![None; total_vregs],
            map_fd_sources: vec![None; total_vregs],
            live_ringbuf_refs: vec![false; total_vregs],
            released_ringbuf_record_regs: vec![false; total_vregs],
            live_kfunc_refs: vec![false; total_vregs],
            released_kfunc_ref_regs: vec![false; total_vregs],
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
            bpf_spin_lock_min_depth: 0,
            bpf_spin_lock_max_depth: 0,
            bpf_spin_lock_identity: None,
            res_spin_lock_irqsave_min_depth: 0,
            res_spin_lock_irqsave_max_depth: 0,
            res_spin_lock_irqsave_slots: HashMap::new(),
            res_spin_lock_stack: Some(Vec::new()),
            dynptr_initialized_slots: HashSet::new(),
            maybe_initialized_dynptr_slots: HashSet::new(),
            ringbuf_dynptr_slots: HashMap::new(),
            ringbuf_dynptr_alias_roots: HashMap::new(),
            released_ringbuf_dynptr_slots: HashSet::new(),
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

    pub(super) fn scalar_alias_root(&self, vreg: VReg) -> VReg {
        self.scalar_alias_roots
            .get(vreg.0 as usize)
            .and_then(|root| *root)
            .unwrap_or(vreg)
    }

    pub(super) fn set_scalar_alias(&mut self, dst: VReg, src: VReg) {
        let root = self.scalar_alias_root(src);
        if let Some(slot) = self.scalar_alias_roots.get_mut(dst.0 as usize) {
            *slot = Some(root);
        }
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
        if let Some(slot) = self.scalar_alias_roots.get_mut(vreg.0 as usize) {
            *slot = None;
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
        if let Some(slot) = self.map_lookup_sources.get_mut(vreg.0 as usize) {
            *slot = None;
        }
        if let Some(slot) = self.map_fd_sources.get_mut(vreg.0 as usize) {
            *slot = None;
        }
        if let Some(slot) = self.released_ringbuf_record_regs.get_mut(vreg.0 as usize) {
            *slot = false;
        }
        if let Some(slot) = self.released_kfunc_ref_regs.get_mut(vreg.0 as usize) {
            *slot = false;
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

    pub(super) fn set_map_lookup_source(&mut self, root: VReg, map: &MapRef, key: VReg) {
        if let Some(slot) = self.map_lookup_sources.get_mut(root.0 as usize) {
            *slot = Some(MapLookupSource {
                map: map.clone(),
                key,
            });
        }
    }

    pub(super) fn map_lookup_source(&self, root: VReg) -> Option<&MapLookupSource> {
        self.map_lookup_sources
            .get(root.0 as usize)
            .and_then(|source| source.as_ref())
    }

    pub(super) fn set_map_fd_source(&mut self, fd: VReg, map: &MapRef) {
        if let Some(slot) = self.map_fd_sources.get_mut(fd.0 as usize) {
            *slot = Some(map.clone());
        }
    }

    pub(super) fn map_fd_source(&self, fd: VReg) -> Option<&MapRef> {
        self.map_fd_sources
            .get(fd.0 as usize)
            .and_then(|source| source.as_ref())
    }

    pub(super) fn map_roots_may_alias_same_lookup(&self, lhs: VReg, rhs: VReg) -> bool {
        if lhs == rhs {
            return true;
        }
        let (Some(lhs), Some(rhs)) = (self.map_lookup_source(lhs), self.map_lookup_source(rhs))
        else {
            return false;
        };
        lhs.map == rhs.map && self.map_lookup_keys_may_alias(lhs.key, rhs.key)
    }

    pub(super) fn map_lookup_keys_may_alias(&self, lhs: VReg, rhs: VReg) -> bool {
        lhs == rhs
            || self.scalar_alias_root(lhs) == self.scalar_alias_root(rhs)
            || self.ctx_field_values_may_alias(lhs, rhs)
            || matches!(
                (self.get_range(lhs), self.get_range(rhs)),
                (
                    ValueRange::Known { min: lhs_min, max: lhs_max },
                    ValueRange::Known { min: rhs_min, max: rhs_max },
                ) if lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min
            )
    }

    fn ctx_field_values_may_alias(&self, lhs: VReg, rhs: VReg) -> bool {
        let Some(lhs_field) = self.ctx_field_source(lhs) else {
            return false;
        };
        if self.ctx_field_source(rhs) != Some(lhs_field) {
            return false;
        }
        matches!(
            (self.get(lhs), self.get(rhs)),
            (
                VerifierType::Scalar | VerifierType::Bool,
                VerifierType::Scalar | VerifierType::Bool,
            )
        )
    }

    fn ctx_field_invalidated_by_packet_mutation(field: &CtxField) -> bool {
        matches!(
            field,
            CtxField::Data | CtxField::DataMeta | CtxField::DataEnd | CtxField::PacketLen
        )
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

    pub(super) fn proves_ctx_field_value_range<F>(&self, field: &CtxField, predicate: F) -> bool
    where
        F: Fn(i64) -> bool,
    {
        self.ctx_field_sources
            .iter()
            .enumerate()
            .any(|(idx, source)| {
                source.as_ref() == Some(field)
                    && !matches!(self.regs[idx], VerifierType::Uninit)
                    && value_range_satisfies_only(self.ranges[idx], &predicate)
            })
    }

    pub(super) fn refine_packet_prefix_limit(&mut self, root: VReg, safe_limit: i64) {
        for reg in &mut self.regs {
            let VerifierType::Ptr {
                space,
                nullability,
                bounds: Some(bounds),
                ringbuf_ref,
                kfunc_ref,
            } = *reg
            else {
                continue;
            };
            if space != AddressSpace::Packet || bounds.origin() != PtrOrigin::Packet(root) {
                continue;
            }
            let next_limit = if bounds.limit() == UNKNOWN_PACKET_LIMIT {
                safe_limit
            } else {
                bounds.limit().max(safe_limit)
            };
            *reg = VerifierType::Ptr {
                space,
                nullability,
                bounds: Some(bounds.with_limit(next_limit)),
                ringbuf_ref,
                kfunc_ref,
            };
        }
    }

    pub(super) fn invalidate_packet_pointers(&mut self) {
        for idx in 0..self.regs.len() {
            if !matches!(
                self.regs[idx],
                VerifierType::Ptr {
                    space: AddressSpace::Packet,
                    ..
                }
            ) {
                continue;
            }
            self.regs[idx] = VerifierType::StalePacketPtr;
            self.ranges[idx] = ValueRange::Unknown;
            self.non_zero[idx] = false;
            self.not_equal[idx].clear();
            self.ctx_field_sources[idx] = None;
            self.guards.remove(&VReg(idx as u32));
        }
        for source in &mut self.ctx_field_sources {
            if source
                .as_ref()
                .is_some_and(Self::ctx_field_invalidated_by_packet_mutation)
            {
                *source = None;
            }
        }
    }

    pub(super) fn refine_context_buffer_prefix_limit(&mut self, root: VReg, safe_limit: i64) {
        for reg in &mut self.regs {
            let VerifierType::Ptr {
                space,
                nullability,
                bounds: Some(bounds),
                ringbuf_ref,
                kfunc_ref,
            } = *reg
            else {
                continue;
            };
            if space != AddressSpace::Kernel || bounds.origin() != PtrOrigin::ContextBuffer(root) {
                continue;
            }
            let next_limit = if bounds.limit() == UNKNOWN_CONTEXT_BUFFER_LIMIT {
                safe_limit
            } else {
                bounds.limit().max(safe_limit)
            };
            *reg = VerifierType::Ptr {
                space,
                nullability,
                bounds: Some(bounds.with_limit(next_limit)),
                ringbuf_ref,
                kfunc_ref,
            };
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
