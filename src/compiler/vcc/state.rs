type UnknownStackObjectTypeKey = (String, Option<u32>);

fn unknown_stack_object_type_key(
    type_name: &str,
    type_id: Option<u32>,
) -> UnknownStackObjectTypeKey {
    (type_name.to_string(), type_id)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VccState {
    reg_types: HashMap<VccReg, VccValueType>,
    ctx_field_sources: HashMap<VccReg, CtxField>,
    not_equal_consts: HashMap<VccReg, Vec<i64>>,
    live_ringbuf_refs: HashMap<VccReg, bool>,
    live_kfunc_refs: HashMap<VccReg, Option<KfuncRefKind>>,
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
    res_spin_lock_irqsave_min_depth: u32,
    res_spin_lock_irqsave_max_depth: u32,
    res_spin_lock_irqsave_slots: HashMap<StackSlotId, (u32, u32)>,
    dynptr_initialized_slots: HashSet<StackSlotId>,
    ringbuf_dynptr_slots: HashMap<StackSlotId, (u32, u32)>,
    ringbuf_dynptr_alias_roots: HashMap<StackSlotId, StackSlotId>,
    released_ringbuf_dynptr_slots: HashSet<StackSlotId>,
    unknown_stack_object_slots: HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
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
    PacketEnd {
        ptr_reg: VccReg,
        op: VccBinOp,
    },
    ContextBufferEnd {
        ptr_reg: VccReg,
        op: VccBinOp,
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
            ctx_field_sources: HashMap::new(),
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: HashMap::new(),
            live_kfunc_refs: HashMap::new(),
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
            res_spin_lock_irqsave_min_depth: 0,
            res_spin_lock_irqsave_max_depth: 0,
            res_spin_lock_irqsave_slots: HashMap::new(),
            dynptr_initialized_slots: HashSet::new(),
            ringbuf_dynptr_slots: HashMap::new(),
            ringbuf_dynptr_alias_roots: HashMap::new(),
            released_ringbuf_dynptr_slots: HashSet::new(),
            unknown_stack_object_slots: HashMap::new(),
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
        self.ctx_field_sources.remove(&reg);
        self.not_equal_consts.remove(&reg);
        self.cond_refinements.remove(&reg);
    }

    fn set_ctx_field_source(&mut self, reg: VccReg, source: Option<CtxField>) {
        if let Some(source) = source {
            self.ctx_field_sources.insert(reg, source);
        } else {
            self.ctx_field_sources.remove(&reg);
        }
    }

    fn ctx_field_source(&self, reg: VccReg) -> Option<&CtxField> {
        self.ctx_field_sources.get(&reg)
    }

    fn proves_ctx_field_value_range<F>(&self, field: &CtxField, predicate: F) -> bool
    where
        F: Fn(i64) -> bool,
    {
        self.ctx_field_sources.iter().any(|(reg, source)| {
            if source != field {
                return false;
            }
            let Ok(VccValueType::Scalar { range: Some(range) }) = self.reg_type(*reg) else {
                return false;
            };
            let width = range.max.saturating_sub(range.min);
            width <= 64 && (range.min..=range.max).all(&predicate)
        })
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

    fn refine_packet_prefix_limit(&mut self, root: VccReg, safe_limit: i64) {
        for ty in self.reg_types.values_mut() {
            let VccValueType::Ptr(ptr) = ty else {
                continue;
            };
            if ptr.space != VccAddrSpace::Packet || ptr.packet_root != Some(root) {
                continue;
            }
            let Some(bounds) = ptr.bounds else {
                continue;
            };
            let next_limit = if bounds.limit == UNKNOWN_PACKET_LIMIT {
                safe_limit
            } else {
                bounds.limit.max(safe_limit)
            };
            ptr.bounds = Some(VccBounds {
                min: bounds.min,
                max: bounds.max,
                limit: next_limit,
            });
        }
    }

    pub(super) fn invalidate_packet_pointers(&mut self) {
        let mut invalidated = Vec::new();
        for (reg, ty) in self.reg_types.iter_mut() {
            let is_packet_ptr = matches!(
                ty,
                VccValueType::Ptr(VccPointerInfo {
                    space: VccAddrSpace::Packet,
                    ..
                })
            );
            if is_packet_ptr {
                *ty = VccValueType::StalePacketPtr;
                invalidated.push(*reg);
            }
        }
        for reg in &invalidated {
            self.ctx_field_sources.remove(reg);
            self.not_equal_consts.remove(reg);
        }
        self.cond_refinements.retain(|reg, info| {
            if invalidated.contains(reg) {
                return false;
            }
            match info {
                VccCondRefinement::PtrNull { ptr_reg, .. }
                | VccCondRefinement::PacketEnd { ptr_reg, .. } => !invalidated.contains(ptr_reg),
                VccCondRefinement::ContextBufferEnd { .. }
                | VccCondRefinement::ScalarCmpConst { .. }
                | VccCondRefinement::ScalarCmpRegs { .. } => true,
            }
        });
    }

    fn refine_context_buffer_prefix_limit(&mut self, root: VccReg, safe_limit: i64) {
        for ty in self.reg_types.values_mut() {
            let VccValueType::Ptr(ptr) = ty else {
                continue;
            };
            if ptr.space != VccAddrSpace::Kernel || ptr.context_buffer_root != Some(root) {
                continue;
            }
            let Some(bounds) = ptr.bounds else {
                continue;
            };
            let next_limit = if bounds.limit == UNKNOWN_CONTEXT_BUFFER_LIMIT {
                safe_limit
            } else {
                bounds.limit.max(safe_limit)
            };
            ptr.bounds = Some(VccBounds {
                min: bounds.min,
                max: bounds.max,
                limit: next_limit,
            });
        }
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

    fn acquire_local_irq_disable_slot(&mut self, slot: StackSlotId) {
        self.acquire_local_irq_disable();
        increment_slot_depth(&mut self.local_irq_disable_slots, slot);
    }

    fn release_local_irq_disable(&mut self) -> bool {
        if self.local_irq_disable_min_depth == 0 {
            return false;
        }
        self.local_irq_disable_min_depth -= 1;
        self.local_irq_disable_max_depth -= 1;
        true
    }

    fn release_local_irq_disable_slot(&mut self, slot: StackSlotId) -> bool {
        if self.local_irq_disable_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.local_irq_disable_slots, slot) {
            return false;
        }
        self.release_local_irq_disable()
    }

    fn has_live_local_irq_disable(&self) -> bool {
        self.local_irq_disable_max_depth > 0
    }

    fn acquire_iter_task_vma_slot(&mut self, slot: StackSlotId) {
        self.iter_task_vma_min_depth = self.iter_task_vma_min_depth.saturating_add(1);
        self.iter_task_vma_max_depth = self.iter_task_vma_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_task_vma_slots, slot);
    }

    fn use_iter_task_vma_slot(&self, slot: StackSlotId) -> bool {
        self.iter_task_vma_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_task_vma_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_task_vma_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_task_vma_slots, slot) {
            return false;
        }
        self.iter_task_vma_min_depth -= 1;
        self.iter_task_vma_max_depth -= 1;
        true
    }

    fn has_live_iter_task_vma(&self) -> bool {
        self.iter_task_vma_max_depth > 0
    }

    fn acquire_iter_task_slot(&mut self, slot: StackSlotId) {
        self.iter_task_min_depth = self.iter_task_min_depth.saturating_add(1);
        self.iter_task_max_depth = self.iter_task_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_task_slots, slot);
    }

    fn use_iter_task_slot(&self, slot: StackSlotId) -> bool {
        self.iter_task_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_task_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_task_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_task_slots, slot) {
            return false;
        }
        self.iter_task_min_depth -= 1;
        self.iter_task_max_depth -= 1;
        true
    }

    fn has_live_iter_task(&self) -> bool {
        self.iter_task_max_depth > 0
    }

    fn acquire_iter_scx_dsq_slot(&mut self, slot: StackSlotId) {
        self.iter_scx_dsq_min_depth = self.iter_scx_dsq_min_depth.saturating_add(1);
        self.iter_scx_dsq_max_depth = self.iter_scx_dsq_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_scx_dsq_slots, slot);
    }

    fn use_iter_scx_dsq_slot(&self, slot: StackSlotId) -> bool {
        self.iter_scx_dsq_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_scx_dsq_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_scx_dsq_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_scx_dsq_slots, slot) {
            return false;
        }
        self.iter_scx_dsq_min_depth -= 1;
        self.iter_scx_dsq_max_depth -= 1;
        true
    }

    fn has_live_iter_scx_dsq(&self) -> bool {
        self.iter_scx_dsq_max_depth > 0
    }

    fn acquire_iter_num_slot(&mut self, slot: StackSlotId) {
        self.iter_num_min_depth = self.iter_num_min_depth.saturating_add(1);
        self.iter_num_max_depth = self.iter_num_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_num_slots, slot);
    }

    fn use_iter_num_slot(&self, slot: StackSlotId) -> bool {
        self.iter_num_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_num_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_num_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_num_slots, slot) {
            return false;
        }
        self.iter_num_min_depth -= 1;
        self.iter_num_max_depth -= 1;
        true
    }

    fn has_live_iter_num(&self) -> bool {
        self.iter_num_max_depth > 0
    }

    fn acquire_iter_bits_slot(&mut self, slot: StackSlotId) {
        self.iter_bits_min_depth = self.iter_bits_min_depth.saturating_add(1);
        self.iter_bits_max_depth = self.iter_bits_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_bits_slots, slot);
    }

    fn use_iter_bits_slot(&self, slot: StackSlotId) -> bool {
        self.iter_bits_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_bits_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_bits_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_bits_slots, slot) {
            return false;
        }
        self.iter_bits_min_depth -= 1;
        self.iter_bits_max_depth -= 1;
        true
    }

    fn has_live_iter_bits(&self) -> bool {
        self.iter_bits_max_depth > 0
    }

    fn acquire_iter_css_slot(&mut self, slot: StackSlotId) {
        self.iter_css_min_depth = self.iter_css_min_depth.saturating_add(1);
        self.iter_css_max_depth = self.iter_css_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_css_slots, slot);
    }

    fn use_iter_css_slot(&self, slot: StackSlotId) -> bool {
        self.iter_css_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_css_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_css_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_css_slots, slot) {
            return false;
        }
        self.iter_css_min_depth -= 1;
        self.iter_css_max_depth -= 1;
        true
    }

    fn has_live_iter_css(&self) -> bool {
        self.iter_css_max_depth > 0
    }

    fn acquire_iter_css_task_slot(&mut self, slot: StackSlotId) {
        self.iter_css_task_min_depth = self.iter_css_task_min_depth.saturating_add(1);
        self.iter_css_task_max_depth = self.iter_css_task_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_css_task_slots, slot);
    }

    fn use_iter_css_task_slot(&self, slot: StackSlotId) -> bool {
        self.iter_css_task_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_css_task_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_css_task_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_css_task_slots, slot) {
            return false;
        }
        self.iter_css_task_min_depth -= 1;
        self.iter_css_task_max_depth -= 1;
        true
    }

    fn has_live_iter_css_task(&self) -> bool {
        self.iter_css_task_max_depth > 0
    }

    fn acquire_iter_dmabuf_slot(&mut self, slot: StackSlotId) {
        self.iter_dmabuf_min_depth = self.iter_dmabuf_min_depth.saturating_add(1);
        self.iter_dmabuf_max_depth = self.iter_dmabuf_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_dmabuf_slots, slot);
    }

    fn use_iter_dmabuf_slot(&self, slot: StackSlotId) -> bool {
        self.iter_dmabuf_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_dmabuf_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_dmabuf_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_dmabuf_slots, slot) {
            return false;
        }
        self.iter_dmabuf_min_depth -= 1;
        self.iter_dmabuf_max_depth -= 1;
        true
    }

    fn has_live_iter_dmabuf(&self) -> bool {
        self.iter_dmabuf_max_depth > 0
    }

    fn acquire_iter_kmem_cache_slot(&mut self, slot: StackSlotId) {
        self.iter_kmem_cache_min_depth = self.iter_kmem_cache_min_depth.saturating_add(1);
        self.iter_kmem_cache_max_depth = self.iter_kmem_cache_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_kmem_cache_slots, slot);
    }

    fn use_iter_kmem_cache_slot(&self, slot: StackSlotId) -> bool {
        self.iter_kmem_cache_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_iter_kmem_cache_slot(&mut self, slot: StackSlotId) -> bool {
        if self.iter_kmem_cache_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_kmem_cache_slots, slot) {
            return false;
        }
        self.iter_kmem_cache_min_depth -= 1;
        self.iter_kmem_cache_max_depth -= 1;
        true
    }

    fn has_live_iter_kmem_cache(&self) -> bool {
        self.iter_kmem_cache_max_depth > 0
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

    fn acquire_bpf_spin_lock(&mut self) -> bool {
        if self.bpf_spin_lock_max_depth > 0 {
            return false;
        }
        self.bpf_spin_lock_min_depth = 1;
        self.bpf_spin_lock_max_depth = 1;
        true
    }

    fn release_bpf_spin_lock(&mut self) -> bool {
        if self.bpf_spin_lock_min_depth == 0 {
            return false;
        }
        self.bpf_spin_lock_min_depth = 0;
        self.bpf_spin_lock_max_depth = 0;
        true
    }

    fn has_live_bpf_spin_lock(&self) -> bool {
        self.bpf_spin_lock_max_depth > 0
    }

    fn acquire_res_spin_lock_irqsave(&mut self) {
        self.res_spin_lock_irqsave_min_depth =
            self.res_spin_lock_irqsave_min_depth.saturating_add(1);
        self.res_spin_lock_irqsave_max_depth =
            self.res_spin_lock_irqsave_max_depth.saturating_add(1);
    }

    fn acquire_res_spin_lock_irqsave_slot(&mut self, slot: StackSlotId) {
        self.acquire_res_spin_lock_irqsave();
        increment_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot);
    }

    fn release_res_spin_lock_irqsave(&mut self) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth -= 1;
        self.res_spin_lock_irqsave_max_depth -= 1;
        true
    }

    fn release_res_spin_lock_irqsave_slot(&mut self, slot: StackSlotId) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot) {
            return false;
        }
        self.release_res_spin_lock_irqsave()
    }

    fn has_live_res_spin_lock_irqsave(&self) -> bool {
        self.res_spin_lock_irqsave_max_depth > 0
    }

    fn initialize_dynptr_slot(&mut self, slot: StackSlotId) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.remove(&slot);
        self.dynptr_initialized_slots.insert(slot);
    }

    fn is_dynptr_slot_initialized(&self, slot: StackSlotId) -> bool {
        self.dynptr_initialized_slots.contains(&slot)
    }

    fn deinitialize_dynptr_slot(&mut self, slot: StackSlotId) {
        self.dynptr_initialized_slots.remove(&slot);
    }

    fn acquire_ringbuf_dynptr_slot(&mut self, slot: StackSlotId) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.insert(slot, slot);
        increment_slot_depth(&mut self.ringbuf_dynptr_slots, slot);
    }

    fn release_ringbuf_dynptr_slot(&mut self, slot: StackSlotId) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        let released = decrement_slot_depth(&mut self.ringbuf_dynptr_slots, root);
        if released {
            for member in self.ringbuf_dynptr_alias_members(root) {
                self.released_ringbuf_dynptr_slots.insert(member);
                self.dynptr_initialized_slots.remove(&member);
                self.ringbuf_dynptr_alias_roots.remove(&member);
            }
        }
        released
    }

    fn copy_ringbuf_dynptr_slot(
        &mut self,
        src: StackSlotId,
        dst: StackSlotId,
        move_semantics: bool,
    ) {
        let Some(root) = self.ringbuf_dynptr_root(src) else {
            return;
        };
        if !self
            .ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(_, max_depth)| *max_depth > 0)
        {
            return;
        }
        self.released_ringbuf_dynptr_slots.remove(&dst);
        if move_semantics && src == root {
            if let Some(depth) = self.ringbuf_dynptr_slots.remove(&root) {
                self.ringbuf_dynptr_slots.insert(dst, depth);
                for alias_root in self.ringbuf_dynptr_alias_roots.values_mut() {
                    if *alias_root == root {
                        *alias_root = dst;
                    }
                }
            }
            self.ringbuf_dynptr_alias_roots.remove(&src);
            self.ringbuf_dynptr_alias_roots.insert(dst, dst);
            return;
        }
        self.ringbuf_dynptr_alias_roots.insert(dst, root);
        if move_semantics {
            self.ringbuf_dynptr_alias_roots.remove(&src);
        }
    }

    fn is_released_ringbuf_dynptr_slot(&self, slot: StackSlotId) -> bool {
        self.released_ringbuf_dynptr_slots.contains(&slot)
    }

    fn has_ringbuf_dynptr_slot(&self, slot: StackSlotId) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        self.ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn has_live_ringbuf_dynptr_slot(&self, slot: StackSlotId) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        self.ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(_, max_depth)| *max_depth > 0)
    }

    fn first_live_ringbuf_dynptr_slot(&self) -> Option<StackSlotId> {
        self.ringbuf_dynptr_alias_roots
            .iter()
            .find(|(_, root)| {
                self.ringbuf_dynptr_slots
                    .get(root)
                    .is_some_and(|(_, max_depth)| *max_depth > 0)
            })
            .map(|(slot, _)| *slot)
    }

    fn ringbuf_dynptr_root(&self, slot: StackSlotId) -> Option<StackSlotId> {
        self.ringbuf_dynptr_alias_roots.get(&slot).copied()
    }

    fn ringbuf_dynptr_alias_members(&self, root: StackSlotId) -> Vec<StackSlotId> {
        self.ringbuf_dynptr_alias_roots
            .iter()
            .filter_map(|(slot, alias_root)| (*alias_root == root).then_some(*slot))
            .collect()
    }

    fn initialize_unknown_stack_object_slot(
        &mut self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) {
        increment_typed_slot_depth(
            &mut self.unknown_stack_object_slots,
            (slot, unknown_stack_object_type_key(type_name, type_id)),
        );
    }

    fn has_unknown_stack_object_slot(
        &self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) -> bool {
        self.unknown_stack_object_slots
            .get(&(slot, unknown_stack_object_type_key(type_name, type_id)))
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    fn release_unknown_stack_object_slot(
        &mut self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) -> bool {
        decrement_typed_slot_depth(
            &mut self.unknown_stack_object_slots,
            (slot, unknown_stack_object_type_key(type_name, type_id)),
        )
    }

    fn first_live_unknown_stack_object(&self) -> Option<(StackSlotId, String)> {
        self.unknown_stack_object_slots
            .iter()
            .find(|(_, (_, max_depth))| *max_depth > 0)
            .map(|((slot, (type_name, _)), _)| (*slot, type_name.clone()))
    }

    fn has_live_unknown_stack_object_slot(&self, slot: StackSlotId) -> bool {
        self.unknown_stack_object_slots
            .iter()
            .any(|((candidate_slot, _), (_, max_depth))| *candidate_slot == slot && *max_depth > 0)
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
            VccCondRefinement::PacketEnd { .. } => true,
            VccCondRefinement::ContextBufferEnd { .. } => true,
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
            VccCondRefinement::PacketEnd { .. } => true,
            VccCondRefinement::ContextBufferEnd { .. } => true,
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
        let mut ctx_field_sources = HashMap::new();
        for (reg, left) in &self.ctx_field_sources {
            if let Some(right) = other.ctx_field_sources.get(reg)
                && left == right
            {
                ctx_field_sources.insert(*reg, left.clone());
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
        let dynptr_initialized_slots = self
            .dynptr_initialized_slots
            .intersection(&other.dynptr_initialized_slots)
            .copied()
            .collect();
        let unknown_stack_object_slots = merge_typed_slot_depths(
            &self.unknown_stack_object_slots,
            &other.unknown_stack_object_slots,
        );
        let ringbuf_dynptr_slots =
            merge_slot_depths(&self.ringbuf_dynptr_slots, &other.ringbuf_dynptr_slots);
        let ringbuf_dynptr_alias_roots = merge_ringbuf_dynptr_alias_roots(
            &self.ringbuf_dynptr_alias_roots,
            &other.ringbuf_dynptr_alias_roots,
            &ringbuf_dynptr_slots,
            &dynptr_initialized_slots,
        );
        let released_ringbuf_dynptr_slots = self
            .released_ringbuf_dynptr_slots
            .union(&other.released_ringbuf_dynptr_slots)
            .copied()
            .collect();
        VccState {
            reg_types: merged,
            ctx_field_sources,
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
            local_irq_disable_slots: merge_slot_depths(
                &self.local_irq_disable_slots,
                &other.local_irq_disable_slots,
            ),
            iter_task_vma_min_depth: self.iter_task_vma_min_depth.min(other.iter_task_vma_min_depth),
            iter_task_vma_max_depth: self.iter_task_vma_max_depth.max(other.iter_task_vma_max_depth),
            iter_task_vma_slots: merge_slot_depths(&self.iter_task_vma_slots, &other.iter_task_vma_slots),
            iter_task_min_depth: self.iter_task_min_depth.min(other.iter_task_min_depth),
            iter_task_max_depth: self.iter_task_max_depth.max(other.iter_task_max_depth),
            iter_task_slots: merge_slot_depths(&self.iter_task_slots, &other.iter_task_slots),
            iter_scx_dsq_min_depth: self.iter_scx_dsq_min_depth.min(other.iter_scx_dsq_min_depth),
            iter_scx_dsq_max_depth: self.iter_scx_dsq_max_depth.max(other.iter_scx_dsq_max_depth),
            iter_scx_dsq_slots: merge_slot_depths(&self.iter_scx_dsq_slots, &other.iter_scx_dsq_slots),
            iter_num_min_depth: self.iter_num_min_depth.min(other.iter_num_min_depth),
            iter_num_max_depth: self.iter_num_max_depth.max(other.iter_num_max_depth),
            iter_num_slots: merge_slot_depths(&self.iter_num_slots, &other.iter_num_slots),
            iter_bits_min_depth: self.iter_bits_min_depth.min(other.iter_bits_min_depth),
            iter_bits_max_depth: self.iter_bits_max_depth.max(other.iter_bits_max_depth),
            iter_bits_slots: merge_slot_depths(&self.iter_bits_slots, &other.iter_bits_slots),
            iter_css_min_depth: self.iter_css_min_depth.min(other.iter_css_min_depth),
            iter_css_max_depth: self.iter_css_max_depth.max(other.iter_css_max_depth),
            iter_css_slots: merge_slot_depths(&self.iter_css_slots, &other.iter_css_slots),
            iter_css_task_min_depth: self.iter_css_task_min_depth.min(other.iter_css_task_min_depth),
            iter_css_task_max_depth: self.iter_css_task_max_depth.max(other.iter_css_task_max_depth),
            iter_css_task_slots: merge_slot_depths(
                &self.iter_css_task_slots,
                &other.iter_css_task_slots,
            ),
            iter_dmabuf_min_depth: self.iter_dmabuf_min_depth.min(other.iter_dmabuf_min_depth),
            iter_dmabuf_max_depth: self.iter_dmabuf_max_depth.max(other.iter_dmabuf_max_depth),
            iter_dmabuf_slots: merge_slot_depths(
                &self.iter_dmabuf_slots,
                &other.iter_dmabuf_slots,
            ),
            iter_kmem_cache_min_depth: self
                .iter_kmem_cache_min_depth
                .min(other.iter_kmem_cache_min_depth),
            iter_kmem_cache_max_depth: self
                .iter_kmem_cache_max_depth
                .max(other.iter_kmem_cache_max_depth),
            iter_kmem_cache_slots: merge_slot_depths(
                &self.iter_kmem_cache_slots,
                &other.iter_kmem_cache_slots,
            ),
            res_spin_lock_min_depth: self
                .res_spin_lock_min_depth
                .min(other.res_spin_lock_min_depth),
            res_spin_lock_max_depth: self
                .res_spin_lock_max_depth
                .max(other.res_spin_lock_max_depth),
            bpf_spin_lock_min_depth: self
                .bpf_spin_lock_min_depth
                .min(other.bpf_spin_lock_min_depth),
            bpf_spin_lock_max_depth: self
                .bpf_spin_lock_max_depth
                .max(other.bpf_spin_lock_max_depth),
            res_spin_lock_irqsave_min_depth: self
                .res_spin_lock_irqsave_min_depth
                .min(other.res_spin_lock_irqsave_min_depth),
            res_spin_lock_irqsave_max_depth: self
                .res_spin_lock_irqsave_max_depth
                .max(other.res_spin_lock_irqsave_max_depth),
            res_spin_lock_irqsave_slots: merge_slot_depths(
                &self.res_spin_lock_irqsave_slots,
                &other.res_spin_lock_irqsave_slots,
            ),
            dynptr_initialized_slots,
            ringbuf_dynptr_slots,
            ringbuf_dynptr_alias_roots,
            released_ringbuf_dynptr_slots,
            unknown_stack_object_slots,
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
                    packet_root: ptr.packet_root,
                    packet_root_field: ptr.packet_root_field,
                    packet_ctx_field: ptr.packet_ctx_field,
                    packet_end: ptr.packet_end,
                    context_buffer_root: ptr.context_buffer_root,
                    context_buffer_end: ptr.context_buffer_end,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                }),
                VccValueType::Bool => VccValueType::Bool,
                VccValueType::StalePacketPtr => VccValueType::StalePacketPtr,
                VccValueType::Unknown => VccValueType::Unknown,
                VccValueType::Uninit => VccValueType::Uninit,
            };
            widened.insert(*reg, widened_ty);
        }
        VccState {
            reg_types: widened,
            ctx_field_sources: self.ctx_field_sources.clone(),
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: self.live_ringbuf_refs.clone(),
            live_kfunc_refs: self.live_kfunc_refs.clone(),
            rcu_read_lock_min_depth: self.rcu_read_lock_min_depth,
            rcu_read_lock_max_depth: self.rcu_read_lock_max_depth,
            preempt_disable_min_depth: self.preempt_disable_min_depth,
            preempt_disable_max_depth: self.preempt_disable_max_depth,
            local_irq_disable_min_depth: self.local_irq_disable_min_depth,
            local_irq_disable_max_depth: self.local_irq_disable_max_depth,
            local_irq_disable_slots: self.local_irq_disable_slots.clone(),
            iter_task_vma_min_depth: self.iter_task_vma_min_depth,
            iter_task_vma_max_depth: self.iter_task_vma_max_depth,
            iter_task_vma_slots: self.iter_task_vma_slots.clone(),
            iter_task_min_depth: self.iter_task_min_depth,
            iter_task_max_depth: self.iter_task_max_depth,
            iter_task_slots: self.iter_task_slots.clone(),
            iter_scx_dsq_min_depth: self.iter_scx_dsq_min_depth,
            iter_scx_dsq_max_depth: self.iter_scx_dsq_max_depth,
            iter_scx_dsq_slots: self.iter_scx_dsq_slots.clone(),
            iter_num_min_depth: self.iter_num_min_depth,
            iter_num_max_depth: self.iter_num_max_depth,
            iter_num_slots: self.iter_num_slots.clone(),
            iter_bits_min_depth: self.iter_bits_min_depth,
            iter_bits_max_depth: self.iter_bits_max_depth,
            iter_bits_slots: self.iter_bits_slots.clone(),
            iter_css_min_depth: self.iter_css_min_depth,
            iter_css_max_depth: self.iter_css_max_depth,
            iter_css_slots: self.iter_css_slots.clone(),
            iter_css_task_min_depth: self.iter_css_task_min_depth,
            iter_css_task_max_depth: self.iter_css_task_max_depth,
            iter_css_task_slots: self.iter_css_task_slots.clone(),
            iter_dmabuf_min_depth: self.iter_dmabuf_min_depth,
            iter_dmabuf_max_depth: self.iter_dmabuf_max_depth,
            iter_dmabuf_slots: self.iter_dmabuf_slots.clone(),
            iter_kmem_cache_min_depth: self.iter_kmem_cache_min_depth,
            iter_kmem_cache_max_depth: self.iter_kmem_cache_max_depth,
            iter_kmem_cache_slots: self.iter_kmem_cache_slots.clone(),
            res_spin_lock_min_depth: self.res_spin_lock_min_depth,
            res_spin_lock_max_depth: self.res_spin_lock_max_depth,
            bpf_spin_lock_min_depth: self.bpf_spin_lock_min_depth,
            bpf_spin_lock_max_depth: self.bpf_spin_lock_max_depth,
            res_spin_lock_irqsave_min_depth: self.res_spin_lock_irqsave_min_depth,
            res_spin_lock_irqsave_max_depth: self.res_spin_lock_irqsave_max_depth,
            res_spin_lock_irqsave_slots: self.res_spin_lock_irqsave_slots.clone(),
            dynptr_initialized_slots: self.dynptr_initialized_slots.clone(),
            ringbuf_dynptr_slots: self.ringbuf_dynptr_slots.clone(),
            ringbuf_dynptr_alias_roots: self.ringbuf_dynptr_alias_roots.clone(),
            released_ringbuf_dynptr_slots: self.released_ringbuf_dynptr_slots.clone(),
            unknown_stack_object_slots: self.unknown_stack_object_slots.clone(),
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
            (VccValueType::Ptr(lp), VccValueType::Ptr(rp)) => self
                .merge_ptr_types(lp, rp)
                .map(VccValueType::Ptr)
                .unwrap_or(VccValueType::Unknown),
            (VccValueType::StalePacketPtr, _) | (_, VccValueType::StalePacketPtr) => {
                VccValueType::StalePacketPtr
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

    fn merge_ptr_types(&self, lhs: VccPointerInfo, rhs: VccPointerInfo) -> Option<VccPointerInfo> {
        if lhs.space != rhs.space {
            if lhs.space == VccAddrSpace::Unknown && lhs.nullability == VccNullability::Null {
                return Some(self.merge_null_wildcard_ptr(rhs, lhs));
            }
            if rhs.space == VccAddrSpace::Unknown && rhs.nullability == VccNullability::Null {
                return Some(self.merge_null_wildcard_ptr(lhs, rhs));
            }
            if Self::is_generic_stack_null_wildcard(lhs)
                && matches!(rhs.space, VccAddrSpace::Stack(_))
            {
                return Some(self.merge_null_wildcard_ptr(rhs, lhs));
            }
            if Self::is_generic_stack_null_wildcard(rhs)
                && matches!(lhs.space, VccAddrSpace::Stack(_))
            {
                return Some(self.merge_null_wildcard_ptr(lhs, rhs));
            }
            return None;
        }

        let bounds = match (lhs.bounds, rhs.bounds) {
            (Some(l), Some(r)) if l.limit == r.limit => Some(VccBounds {
                min: l.min.min(r.min),
                max: l.max.max(r.max),
                limit: l.limit,
            }),
            (Some(l), Some(r))
                if lhs.space == VccAddrSpace::Packet && lhs.packet_root == rhs.packet_root =>
            {
                Some(VccBounds {
                    min: l.min.min(r.min),
                    max: l.max.max(r.max),
                    limit: l.limit.max(r.limit),
                })
            }
            (Some(l), Some(r))
                if lhs.space == VccAddrSpace::Kernel
                    && lhs.context_buffer_root == rhs.context_buffer_root =>
            {
                Some(VccBounds {
                    min: l.min.min(r.min),
                    max: l.max.max(r.max),
                    limit: l.limit.max(r.limit),
                })
            }
            _ => None,
        };
        let ringbuf_ref = match (lhs.ringbuf_ref, rhs.ringbuf_ref) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        };
        let kfunc_ref = match (lhs.kfunc_ref, rhs.kfunc_ref) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        };
        let nullability = Self::join_nullability(lhs.nullability, rhs.nullability);
        Some(VccPointerInfo {
            space: lhs.space,
            nullability,
            bounds,
            packet_root: if lhs.packet_root == rhs.packet_root {
                lhs.packet_root
            } else {
                None
            },
            packet_root_field: if lhs.packet_root_field == rhs.packet_root_field {
                lhs.packet_root_field
            } else {
                None
            },
            packet_ctx_field: if lhs.packet_ctx_field == rhs.packet_ctx_field {
                lhs.packet_ctx_field
            } else {
                None
            },
            packet_end: lhs.packet_end && rhs.packet_end,
            context_buffer_root: if lhs.context_buffer_root == rhs.context_buffer_root {
                lhs.context_buffer_root
            } else {
                None
            },
            context_buffer_end: lhs.context_buffer_end && rhs.context_buffer_end,
            ringbuf_ref,
            kfunc_ref,
        })
    }

    fn merge_null_wildcard_ptr(
        &self,
        concrete: VccPointerInfo,
        null_ptr: VccPointerInfo,
    ) -> VccPointerInfo {
        let ringbuf_ref = match (concrete.ringbuf_ref, null_ptr.ringbuf_ref) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        };
        let kfunc_ref = match (concrete.kfunc_ref, null_ptr.kfunc_ref) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        };
        VccPointerInfo {
            space: concrete.space,
            nullability: Self::join_nullability(concrete.nullability, null_ptr.nullability),
            bounds: concrete.bounds,
            packet_root: concrete.packet_root,
            packet_root_field: concrete.packet_root_field,
            packet_ctx_field: concrete.packet_ctx_field,
            packet_end: concrete.packet_end,
            context_buffer_root: concrete.context_buffer_root,
            context_buffer_end: concrete.context_buffer_end,
            ringbuf_ref,
            kfunc_ref,
        }
    }

    fn is_generic_stack_null_wildcard(ptr: VccPointerInfo) -> bool {
        matches!(
            ptr.space,
            VccAddrSpace::Stack(StackSlotId(slot)) if slot == u32::MAX
        ) && ptr.nullability == VccNullability::Null
    }
}

fn increment_slot_depth(depths: &mut HashMap<StackSlotId, (u32, u32)>, slot: StackSlotId) {
    let entry = depths.entry(slot).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = entry.1.saturating_add(1);
}

fn decrement_slot_depth(depths: &mut HashMap<StackSlotId, (u32, u32)>, slot: StackSlotId) -> bool {
    let Some((min_depth, max_depth)) = depths.get_mut(&slot) else {
        return false;
    };
    if *min_depth == 0 {
        return false;
    }
    *min_depth -= 1;
    *max_depth -= 1;
    if *max_depth == 0 {
        depths.remove(&slot);
    }
    true
}

fn merge_slot_depths(
    lhs: &HashMap<StackSlotId, (u32, u32)>,
    rhs: &HashMap<StackSlotId, (u32, u32)>,
) -> HashMap<StackSlotId, (u32, u32)> {
    let mut merged = HashMap::new();
    for slot in lhs.keys().chain(rhs.keys()) {
        let (lhs_min, lhs_max) = lhs.get(slot).copied().unwrap_or((0, 0));
        let (rhs_min, rhs_max) = rhs.get(slot).copied().unwrap_or((0, 0));
        let min_depth = lhs_min.min(rhs_min);
        let max_depth = lhs_max.max(rhs_max);
        if max_depth > 0 {
            merged.insert(*slot, (min_depth, max_depth));
        }
    }
    merged
}

fn merge_ringbuf_dynptr_alias_roots(
    lhs: &HashMap<StackSlotId, StackSlotId>,
    rhs: &HashMap<StackSlotId, StackSlotId>,
    ringbuf_dynptr_slots: &HashMap<StackSlotId, (u32, u32)>,
    dynptr_initialized_slots: &HashSet<StackSlotId>,
) -> HashMap<StackSlotId, StackSlotId> {
    let mut merged = HashMap::new();
    for (slot, lhs_root) in lhs {
        if rhs.get(slot) == Some(lhs_root)
            && dynptr_initialized_slots.contains(slot)
            && ringbuf_dynptr_slots
                .get(lhs_root)
                .is_some_and(|(_, max_depth)| *max_depth > 0)
        {
            merged.insert(*slot, *lhs_root);
        }
    }
    merged
}

fn increment_typed_slot_depth(
    depths: &mut HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    slot: (StackSlotId, UnknownStackObjectTypeKey),
) {
    let entry = depths.entry(slot).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = entry.1.saturating_add(1);
}

fn decrement_typed_slot_depth(
    depths: &mut HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    slot: (StackSlotId, UnknownStackObjectTypeKey),
) -> bool {
    let Some((min_depth, max_depth)) = depths.get_mut(&slot) else {
        return false;
    };
    if *min_depth == 0 {
        return false;
    }
    *min_depth -= 1;
    *max_depth -= 1;
    if *max_depth == 0 {
        depths.remove(&slot);
    }
    true
}

fn merge_typed_slot_depths(
    lhs: &HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    rhs: &HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
) -> HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)> {
    let mut merged = HashMap::new();
    for key in lhs.keys().chain(rhs.keys()) {
        let (lhs_min, lhs_max) = lhs.get(key).copied().unwrap_or((0, 0));
        let (rhs_min, rhs_max) = rhs.get(key).copied().unwrap_or((0, 0));
        let min_depth = lhs_min.min(rhs_min);
        let max_depth = lhs_max.max(rhs_max);
        if max_depth > 0 {
            merged.insert(key.clone(), (min_depth, max_depth));
        }
    }
    merged
}
