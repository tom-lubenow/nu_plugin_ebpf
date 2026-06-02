type UnknownStackObjectTypeKey = (String, Option<u32>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResSpinLockIdentity {
    Reg(VccReg),
    CtxField(CtxField),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResSpinLockFrame {
    identity: ResSpinLockIdentity,
    irqsave_slot: Option<StackSlotId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BpfSpinLockIdentity {
    Reg(VccReg),
    MapBounds {
        root: VccReg,
        min: i64,
        max: i64,
        limit: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VccMapLookupSource {
    map: MapRef,
    key: VccReg,
}

fn unknown_stack_object_type_key(
    type_name: &str,
    type_id: Option<u32>,
) -> UnknownStackObjectTypeKey {
    (type_name.to_string(), type_id)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VccState {
    reg_types: HashMap<VccReg, VccValueType>,
    scalar_alias_roots: HashMap<VccReg, VccReg>,
    ctx_field_sources: HashMap<VccReg, CtxField>,
    map_lookup_sources: HashMap<VccReg, VccMapLookupSource>,
    ambiguous_map_lookup_sources: HashSet<VccReg>,
    ambiguous_map_lookup_maps: HashMap<VccReg, MapRef>,
    map_fd_sources: HashMap<VccReg, MapRef>,
    not_equal_consts: HashMap<VccReg, Vec<i64>>,
    live_ringbuf_refs: HashMap<VccReg, bool>,
    live_kfunc_refs: HashMap<VccReg, Option<KfuncRefKind>>,
    released_kfunc_ref_regs: HashSet<VccReg>,
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
            scalar_alias_roots: HashMap::new(),
            ctx_field_sources: HashMap::new(),
            map_lookup_sources: HashMap::new(),
            ambiguous_map_lookup_sources: HashSet::new(),
            ambiguous_map_lookup_maps: HashMap::new(),
            map_fd_sources: HashMap::new(),
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: HashMap::new(),
            live_kfunc_refs: HashMap::new(),
            released_kfunc_ref_regs: HashSet::new(),
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
        self.scalar_alias_roots.remove(&reg);
        self.ctx_field_sources.remove(&reg);
        self.map_lookup_sources.remove(&reg);
        self.ambiguous_map_lookup_sources.remove(&reg);
        self.ambiguous_map_lookup_maps.remove(&reg);
        self.map_fd_sources.remove(&reg);
        self.not_equal_consts.remove(&reg);
        self.released_kfunc_ref_regs.remove(&reg);
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

    fn scalar_alias_root(&self, reg: VccReg) -> VccReg {
        self.scalar_alias_roots.get(&reg).copied().unwrap_or(reg)
    }

    fn set_scalar_alias(&mut self, dst: VccReg, src: VccReg) {
        let root = self.scalar_alias_root(src);
        self.scalar_alias_roots.insert(dst, root);
    }

    fn set_map_lookup_source(&mut self, root: VccReg, map: MapRef, key: VccReg) {
        self.ambiguous_map_lookup_sources.remove(&root);
        self.ambiguous_map_lookup_maps.remove(&root);
        self.map_lookup_sources
            .insert(root, VccMapLookupSource { map, key });
    }

    fn map_lookup_source(&self, root: VccReg) -> Option<&VccMapLookupSource> {
        self.map_lookup_sources.get(&root)
    }

    fn set_ambiguous_map_lookup_source(&mut self, root: VccReg) {
        self.map_lookup_sources.remove(&root);
        self.ambiguous_map_lookup_sources.insert(root);
        self.ambiguous_map_lookup_maps.remove(&root);
    }

    fn set_ambiguous_map_lookup_source_with_map(&mut self, root: VccReg, map: MapRef) {
        self.set_ambiguous_map_lookup_source(root);
        self.ambiguous_map_lookup_maps.insert(root, map);
    }

    fn map_lookup_source_is_ambiguous(&self, root: VccReg) -> bool {
        self.ambiguous_map_lookup_sources.contains(&root)
    }

    fn ambiguous_map_lookup_source_map(&self, root: VccReg) -> Option<&MapRef> {
        self.ambiguous_map_lookup_maps.get(&root)
    }

    fn set_map_fd_source(&mut self, fd: VccReg, map: MapRef) {
        self.map_fd_sources.insert(fd, map);
    }

    fn map_fd_source(&self, fd: VccReg) -> Option<&MapRef> {
        self.map_fd_sources.get(&fd)
    }

    fn map_roots_may_alias_same_lookup(&self, lhs: VccReg, rhs: VccReg) -> bool {
        if lhs == rhs {
            return true;
        }
        let (Some(lhs), Some(rhs)) = (self.map_lookup_source(lhs), self.map_lookup_source(rhs))
        else {
            return false;
        };
        lhs.map == rhs.map && self.map_lookup_keys_may_alias(lhs.key, rhs.key)
    }

    fn map_lookup_keys_may_alias(&self, lhs: VccReg, rhs: VccReg) -> bool {
        if lhs == rhs || self.scalar_alias_root(lhs) == self.scalar_alias_root(rhs) {
            return true;
        }
        if self.ctx_field_values_may_alias(lhs, rhs) {
            return true;
        }
        matches!(
            (self.reg_type(lhs), self.reg_type(rhs)),
            (
                Ok(VccValueType::Scalar {
                    range: Some(VccRange {
                        min: lhs_min,
                        max: lhs_max,
                    }),
                }),
                Ok(VccValueType::Scalar {
                    range: Some(VccRange {
                        min: rhs_min,
                        max: rhs_max,
                    }),
                }),
            ) if lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min
        )
    }

    fn ctx_field_values_may_alias(&self, lhs: VccReg, rhs: VccReg) -> bool {
        let Some(lhs_field) = self.ctx_field_source(lhs) else {
            return false;
        };
        if self.ctx_field_source(rhs) != Some(lhs_field) {
            return false;
        }
        matches!(
            (self.reg_type(lhs), self.reg_type(rhs)),
            (Ok(lhs_ty), Ok(rhs_ty))
                if matches!(lhs_ty.class(), VccTypeClass::Scalar | VccTypeClass::Bool)
                    && matches!(rhs_ty.class(), VccTypeClass::Scalar | VccTypeClass::Bool)
        )
    }

    fn ctx_field_invalidated_by_packet_mutation(field: &CtxField) -> bool {
        matches!(
            field,
            CtxField::Data | CtxField::DataMeta | CtxField::DataEnd | CtxField::PacketLen
        )
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
            self.released_kfunc_ref_regs.remove(&id);
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
        self.ctx_field_sources
            .retain(|_, field| !Self::ctx_field_invalidated_by_packet_mutation(field));
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

    fn has_live_ringbuf_refs_except(&self, allowed: Option<VccReg>) -> bool {
        self.live_ringbuf_refs
            .iter()
            .any(|(id, live)| *live && Some(*id) != allowed)
    }

    fn is_live_kfunc_ref(&self, id: VccReg) -> bool {
        self.live_kfunc_refs.contains_key(&id)
    }

    fn has_live_kfunc_refs_except(&self, allowed: Option<VccReg>) -> bool {
        self.live_kfunc_refs
            .keys()
            .any(|id| Some(*id) != allowed)
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

    fn has_live_rcu_read_lock_except(&self, allowed_depth: u32) -> bool {
        self.rcu_read_lock_max_depth > allowed_depth
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

    fn has_live_preempt_disable_except(&self, allowed_depth: u32) -> bool {
        self.preempt_disable_max_depth > allowed_depth
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

    fn has_live_local_irq_disable_except_slots(
        &self,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> bool {
        let allowed_total = allowed_slots.values().copied().sum();
        let tracked_total: u32 = self
            .local_irq_disable_slots
            .values()
            .map(|(_, max_depth)| *max_depth)
            .sum();
        if self.local_irq_disable_max_depth > tracked_total {
            return true;
        }
        if self.local_irq_disable_max_depth > allowed_total {
            return true;
        }
        self.local_irq_disable_slots
            .iter()
            .any(|(slot, (_, max_depth))| {
                *max_depth > allowed_slots.get(slot).copied().unwrap_or(0)
            })
    }

    fn acquire_iter_task_vma_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_task_vma_slots,
            &mut self.iter_task_vma_min_depth,
            &mut self.iter_task_vma_max_depth,
            slot,
        )
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

    fn acquire_iter_task_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_task_slots,
            &mut self.iter_task_min_depth,
            &mut self.iter_task_max_depth,
            slot,
        )
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

    fn acquire_iter_scx_dsq_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_scx_dsq_slots,
            &mut self.iter_scx_dsq_min_depth,
            &mut self.iter_scx_dsq_max_depth,
            slot,
        )
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

    fn acquire_iter_num_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_num_slots,
            &mut self.iter_num_min_depth,
            &mut self.iter_num_max_depth,
            slot,
        )
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

    fn acquire_iter_bits_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_bits_slots,
            &mut self.iter_bits_min_depth,
            &mut self.iter_bits_max_depth,
            slot,
        )
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

    fn acquire_iter_css_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_css_slots,
            &mut self.iter_css_min_depth,
            &mut self.iter_css_max_depth,
            slot,
        )
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

    fn acquire_iter_css_task_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_css_task_slots,
            &mut self.iter_css_task_min_depth,
            &mut self.iter_css_task_max_depth,
            slot,
        )
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

    fn acquire_iter_dmabuf_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_dmabuf_slots,
            &mut self.iter_dmabuf_min_depth,
            &mut self.iter_dmabuf_max_depth,
            slot,
        )
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

    fn acquire_iter_kmem_cache_slot(&mut self, slot: StackSlotId) -> bool {
        acquire_slot_depth(
            &mut self.iter_kmem_cache_slots,
            &mut self.iter_kmem_cache_min_depth,
            &mut self.iter_kmem_cache_max_depth,
            slot,
        )
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

    fn has_live_iter_family_except_slots(
        &self,
        family: KfuncIterFamily,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> bool {
        match family {
            KfuncIterFamily::TaskVma => has_live_slot_depth_except(
                &self.iter_task_vma_slots,
                self.iter_task_vma_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Task => has_live_slot_depth_except(
                &self.iter_task_slots,
                self.iter_task_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::ScxDsq => has_live_slot_depth_except(
                &self.iter_scx_dsq_slots,
                self.iter_scx_dsq_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Num => has_live_slot_depth_except(
                &self.iter_num_slots,
                self.iter_num_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Bits => has_live_slot_depth_except(
                &self.iter_bits_slots,
                self.iter_bits_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Css => has_live_slot_depth_except(
                &self.iter_css_slots,
                self.iter_css_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::CssTask => has_live_slot_depth_except(
                &self.iter_css_task_slots,
                self.iter_css_task_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Dmabuf => has_live_slot_depth_except(
                &self.iter_dmabuf_slots,
                self.iter_dmabuf_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::KmemCache => has_live_slot_depth_except(
                &self.iter_kmem_cache_slots,
                self.iter_kmem_cache_max_depth,
                allowed_slots,
            ),
        }
    }

    fn res_spin_lock_identity(&self, reg: VccReg) -> ResSpinLockIdentity {
        self.ctx_field_source(reg)
            .cloned()
            .map(ResSpinLockIdentity::CtxField)
            .unwrap_or(ResSpinLockIdentity::Reg(reg))
    }

    fn acquire_res_spin_lock(&mut self, identity: ResSpinLockIdentity) -> bool {
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        if stack.iter().any(|frame| frame.identity == identity) {
            return false;
        }
        self.res_spin_lock_min_depth = self.res_spin_lock_min_depth.saturating_add(1);
        self.res_spin_lock_max_depth = self.res_spin_lock_max_depth.saturating_add(1);
        stack.push(ResSpinLockFrame {
            identity,
            irqsave_slot: None,
        });
        true
    }

    fn release_res_spin_lock(&mut self, identity: ResSpinLockIdentity) -> bool {
        if self.res_spin_lock_min_depth == 0 {
            return false;
        }
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        let Some(frame) = stack.last() else {
            return false;
        };
        if frame.identity != identity || frame.irqsave_slot.is_some() {
            return false;
        }
        self.res_spin_lock_min_depth -= 1;
        self.res_spin_lock_max_depth -= 1;
        stack.pop();
        true
    }

    fn has_live_res_spin_lock(&self) -> bool {
        self.res_spin_lock_max_depth > 0
    }

    fn bpf_spin_lock_identity(&self, reg: VccReg) -> BpfSpinLockIdentity {
        if let Some((root, bounds)) = self.map_value_root_and_bounds(reg) {
            return BpfSpinLockIdentity::MapBounds {
                root,
                min: bounds.min,
                max: bounds.max,
                limit: bounds.limit,
            };
        }
        BpfSpinLockIdentity::Reg(reg)
    }

    fn map_value_root_and_bounds(&self, reg: VccReg) -> Option<(VccReg, VccBounds)> {
        match self.reg_type(reg) {
            Ok(VccValueType::Ptr(VccPointerInfo {
                space: VccAddrSpace::MapValue,
                bounds: Some(bounds),
                map_root: Some(root),
                ..
            })) => Some((root, bounds)),
            _ => None,
        }
    }

    fn map_value_source(&self, reg: VccReg) -> Option<&VccMapLookupSource> {
        if let Some(source) = self.map_lookup_source(reg) {
            return Some(source);
        }
        let (root, _) = self.map_value_root_and_bounds(reg)?;
        self.map_lookup_source(root)
    }

    fn map_value_source_is_ambiguous(&self, reg: VccReg) -> bool {
        if self.map_lookup_source_is_ambiguous(reg) {
            return true;
        }
        let Some((root, _)) = self.map_value_root_and_bounds(reg) else {
            return false;
        };
        self.map_lookup_source_is_ambiguous(root)
    }

    fn map_value_ambiguous_map_source(&self, reg: VccReg) -> Option<&MapRef> {
        if let Some(map) = self.ambiguous_map_lookup_source_map(reg) {
            return Some(map);
        }
        let (root, _) = self.map_value_root_and_bounds(reg)?;
        self.ambiguous_map_lookup_source_map(root)
    }

    fn has_bpf_spin_lock_for_map_root(&self, reg: VccReg) -> bool {
        if !self.has_live_bpf_spin_lock() {
            return false;
        }
        let Some((root, _)) = self.map_value_root_and_bounds(reg) else {
            return true;
        };
        match &self.bpf_spin_lock_identity {
            Some(BpfSpinLockIdentity::MapBounds {
                root: lock_root, ..
            }) => self.map_roots_may_alias_same_lookup(*lock_root, root),
            Some(BpfSpinLockIdentity::Reg(_)) => true,
            None => false,
        }
    }

    fn acquire_bpf_spin_lock(&mut self, identity: BpfSpinLockIdentity) -> bool {
        if self.bpf_spin_lock_max_depth > 0 {
            return false;
        }
        self.bpf_spin_lock_min_depth = 1;
        self.bpf_spin_lock_max_depth = 1;
        self.bpf_spin_lock_identity = Some(identity);
        true
    }

    fn release_bpf_spin_lock(&mut self, identity: BpfSpinLockIdentity) -> bool {
        if self.bpf_spin_lock_min_depth == 0 {
            return false;
        }
        if !self.bpf_spin_lock_identity_matches(&identity) {
            return false;
        }
        self.bpf_spin_lock_min_depth = 0;
        self.bpf_spin_lock_max_depth = 0;
        self.bpf_spin_lock_identity = None;
        true
    }

    fn has_live_bpf_spin_lock(&self) -> bool {
        self.bpf_spin_lock_max_depth > 0
    }

    fn bpf_spin_lock_identity_matches(&self, unlock: &BpfSpinLockIdentity) -> bool {
        match (self.bpf_spin_lock_identity.as_ref(), unlock) {
            (Some(lhs), rhs) if lhs == rhs => true,
            (
                Some(BpfSpinLockIdentity::MapBounds {
                    root: lhs_root,
                    min: lhs_min,
                    max: lhs_max,
                    limit: lhs_limit,
                }),
                BpfSpinLockIdentity::MapBounds {
                    root: rhs_root,
                    min: rhs_min,
                    max: rhs_max,
                    limit: rhs_limit,
                },
            ) => {
                lhs_min == rhs_min
                    && lhs_max == rhs_max
                    && lhs_limit == rhs_limit
                    && self.map_roots_may_alias_same_lookup(*lhs_root, *rhs_root)
            }
            _ => false,
        }
    }

    fn live_kernel_lock_description(&self) -> Option<&'static str> {
        if self.has_live_bpf_spin_lock() {
            Some("bpf_spin_lock")
        } else if self.has_live_res_spin_lock() {
            Some("resource spin lock")
        } else if self.has_live_res_spin_lock_irqsave() {
            Some("resource spin lock irqsave")
        } else {
            None
        }
    }

    fn acquire_res_spin_lock_irqsave(
        &mut self,
        identity: ResSpinLockIdentity,
        slot: StackSlotId,
    ) -> bool {
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        if stack.iter().any(|frame| frame.identity == identity) {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth =
            self.res_spin_lock_irqsave_min_depth.saturating_add(1);
        self.res_spin_lock_irqsave_max_depth =
            self.res_spin_lock_irqsave_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot);
        stack.push(ResSpinLockFrame {
            identity,
            irqsave_slot: Some(slot),
        });
        true
    }

    fn release_res_spin_lock_irqsave(
        &mut self,
        identity: ResSpinLockIdentity,
        slot: StackSlotId,
    ) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        let Some(frame) = stack.last() else {
            return false;
        };
        if frame.identity != identity || frame.irqsave_slot != Some(slot) {
            return false;
        }
        if !decrement_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot) {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth -= 1;
        self.res_spin_lock_irqsave_max_depth -= 1;
        stack.pop();
        true
    }

    fn has_live_res_spin_lock_irqsave(&self) -> bool {
        self.res_spin_lock_irqsave_max_depth > 0
    }

    fn initialize_dynptr_slot(&mut self, slot: StackSlotId) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.remove(&slot);
        self.dynptr_initialized_slots.insert(slot);
        self.maybe_initialized_dynptr_slots.insert(slot);
    }

    fn is_dynptr_slot_initialized(&self, slot: StackSlotId) -> bool {
        self.dynptr_initialized_slots.contains(&slot)
    }

    fn is_dynptr_slot_maybe_initialized(&self, slot: StackSlotId) -> bool {
        self.maybe_initialized_dynptr_slots.contains(&slot)
    }

    fn deinitialize_dynptr_slot(&mut self, slot: StackSlotId) {
        self.dynptr_initialized_slots.remove(&slot);
        self.maybe_initialized_dynptr_slots.remove(&slot);
    }

    fn mark_dynptr_slot_maybe_initialized(&mut self, slot: StackSlotId) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.remove(&slot);
        self.dynptr_initialized_slots.remove(&slot);
        self.maybe_initialized_dynptr_slots.insert(slot);
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
                self.maybe_initialized_dynptr_slots.remove(&member);
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

    fn first_live_ringbuf_dynptr_slot_except_slots(
        &self,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> Option<StackSlotId> {
        self.ringbuf_dynptr_slots
            .iter()
            .find_map(|(slot, (_, max_depth))| {
                (*max_depth > allowed_slots.get(slot).copied().unwrap_or(0)).then_some(*slot)
            })
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

    fn mark_unknown_stack_object_slot_maybe_initialized(
        &mut self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) {
        increment_typed_slot_max_depth(
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

    #[cfg(test)]
    fn first_live_unknown_stack_object(&self) -> Option<(StackSlotId, String)> {
        self.unknown_stack_object_slots
            .iter()
            .find(|(_, (_, max_depth))| *max_depth > 0)
            .map(|((slot, (type_name, _)), _)| (*slot, type_name.clone()))
    }

    fn first_live_unknown_stack_object_except_slots(
        &self,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> Option<(StackSlotId, String)> {
        let mut live_by_slot: HashMap<StackSlotId, u32> = HashMap::new();
        for ((slot, _), (_, max_depth)) in &self.unknown_stack_object_slots {
            let entry = live_by_slot.entry(*slot).or_insert(0u32);
            *entry = entry.saturating_add(*max_depth);
        }
        let leaked_slot = live_by_slot.into_iter().find_map(|(slot, max_depth)| {
            (max_depth > allowed_slots.get(&slot).copied().unwrap_or(0)).then_some(slot)
        })?;
        self.unknown_stack_object_slots
            .iter()
            .find(|((slot, _), (_, max_depth))| *slot == leaked_slot && *max_depth > 0)
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

    fn is_released_kfunc_ref(&self, reg: VccReg) -> bool {
        self.released_kfunc_ref_regs.contains(&reg)
    }

    fn mark_released_kfunc_ref(&mut self, reg: VccReg) {
        self.set_reg(reg, VccValueType::Unknown);
        self.released_kfunc_ref_regs.insert(reg);
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
        let mut released = Vec::new();
        for (reg, ty) in self.reg_types.iter() {
            let matches_ref = matches!(
                ty,
                VccValueType::Ptr(VccPointerInfo {
                    kfunc_ref: Some(ref_id),
                    ..
                }) if *ref_id == id
            );
            if matches_ref {
                released.push(*reg);
            }
        }
        for reg in released {
            self.mark_released_kfunc_ref(reg);
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
        let mut reg_keys: HashSet<VccReg> = self.reg_types.keys().copied().collect();
        reg_keys.extend(other.reg_types.keys().copied());
        let mut merged = HashMap::new();
        for reg in reg_keys {
            let ty = match (
                self.reg_types.get(&reg).copied(),
                other.reg_types.get(&reg).copied(),
            ) {
                (Some(lhs), Some(rhs)) => self.merge_types(lhs, rhs),
                (Some(lhs), None) => Self::clear_resource_refs_after_partial_join(lhs),
                (None, Some(rhs)) => Self::clear_resource_refs_after_partial_join(rhs),
                (None, None) => continue,
            };
            merged.insert(reg, ty);
        }
        let mut scalar_alias_regs: HashSet<VccReg> =
            self.scalar_alias_roots.keys().copied().collect();
        scalar_alias_regs.extend(other.scalar_alias_roots.keys().copied());
        let mut scalar_alias_roots = HashMap::new();
        for reg in scalar_alias_regs {
            let merged = match (
                self.scalar_alias_roots.get(&reg).copied(),
                other.scalar_alias_roots.get(&reg).copied(),
            ) {
                (Some(left), Some(right)) if left == right => Some(left),
                (Some(left), None)
                    if !other.reg_types.contains_key(&reg)
                        || matches!(other.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(left)
                }
                (None, Some(right))
                    if !self.reg_types.contains_key(&reg)
                        || matches!(self.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(right)
                }
                _ => None,
            };
            if let Some(root) = merged {
                scalar_alias_roots.insert(reg, root);
            }
        }
        let mut ctx_field_source_regs: HashSet<VccReg> =
            self.ctx_field_sources.keys().copied().collect();
        ctx_field_source_regs.extend(other.ctx_field_sources.keys().copied());
        let mut ctx_field_sources = HashMap::new();
        for reg in ctx_field_source_regs {
            let merged = match (
                self.ctx_field_sources.get(&reg),
                other.ctx_field_sources.get(&reg),
            ) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                (Some(left), None)
                    if !other.reg_types.contains_key(&reg)
                        || matches!(other.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(left.clone())
                }
                (None, Some(right))
                    if !self.reg_types.contains_key(&reg)
                        || matches!(self.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(right.clone())
                }
                _ => None,
            };
            if let Some(source) = merged {
                ctx_field_sources.insert(reg, source);
            }
        }
        for (reg, source) in &ctx_field_sources {
            if let Some(ty) = merged.get(reg).copied() {
                merged.insert(*reg, Self::join_context_field_pointer_type(*reg, ty, source));
            }
        }
        let mut map_lookup_source_regs: HashSet<VccReg> =
            self.map_lookup_sources.keys().copied().collect();
        map_lookup_source_regs.extend(other.map_lookup_sources.keys().copied());
        map_lookup_source_regs.extend(self.ambiguous_map_lookup_sources.iter().copied());
        map_lookup_source_regs.extend(other.ambiguous_map_lookup_sources.iter().copied());
        map_lookup_source_regs.extend(self.ambiguous_map_lookup_maps.keys().copied());
        map_lookup_source_regs.extend(other.ambiguous_map_lookup_maps.keys().copied());
        let mut map_lookup_sources = HashMap::new();
        let mut ambiguous_map_lookup_sources = HashSet::new();
        let mut ambiguous_map_lookup_maps = HashMap::new();
        for reg in map_lookup_source_regs {
            let left_absent_or_uninit = !self.reg_types.contains_key(&reg)
                || matches!(self.reg_types.get(&reg), Some(VccValueType::Uninit));
            let right_absent_or_uninit = !other.reg_types.contains_key(&reg)
                || matches!(other.reg_types.get(&reg), Some(VccValueType::Uninit));
            let left_ambiguous = self.ambiguous_map_lookup_sources.contains(&reg);
            let right_ambiguous = other.ambiguous_map_lookup_sources.contains(&reg);
            let same_lookup = |left: &VccMapLookupSource, right: &VccMapLookupSource| {
                left.map == right.map
                    && (self.map_lookup_keys_may_alias(left.key, right.key)
                        || other.map_lookup_keys_may_alias(left.key, right.key))
            };
            let left_map = if left_ambiguous {
                self.ambiguous_map_lookup_maps.get(&reg).cloned()
            } else {
                self.map_lookup_sources
                    .get(&reg)
                    .map(|source| source.map.clone())
            };
            let right_map = if right_ambiguous {
                other.ambiguous_map_lookup_maps.get(&reg).cloned()
            } else {
                other
                    .map_lookup_sources
                    .get(&reg)
                    .map(|source| source.map.clone())
            };
            let same_known_map = match (&left_map, &right_map) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                _ => None,
            };
            let merged = match (
                self.map_lookup_sources.get(&reg),
                other.map_lookup_sources.get(&reg),
            ) {
                _ if left_ambiguous || right_ambiguous => None,
                (Some(left), Some(right)) if same_lookup(left, right) => Some(left.clone()),
                (Some(_), Some(_)) => None,
                (Some(left), None)
                    if right_absent_or_uninit => Some(left.clone()),
                (None, Some(right))
                    if left_absent_or_uninit => Some(right.clone()),
                _ => None,
            };
            let ambiguous = left_ambiguous
                || right_ambiguous
                || matches!(
                    (
                        self.map_lookup_sources.get(&reg),
                        other.map_lookup_sources.get(&reg)
                    ),
                    (Some(left), Some(right)) if !same_lookup(left, right)
                );
            if ambiguous {
                ambiguous_map_lookup_sources.insert(reg);
                let ambiguous_map = if left_ambiguous && right_absent_or_uninit {
                    left_map
                } else if right_ambiguous && left_absent_or_uninit {
                    right_map
                } else {
                    same_known_map
                };
                if let Some(map) = ambiguous_map {
                    ambiguous_map_lookup_maps.insert(reg, map);
                }
            }
            if let Some(source) = merged {
                map_lookup_sources.insert(reg, source);
            }
        }
        let mut map_fd_source_regs: HashSet<VccReg> =
            self.map_fd_sources.keys().copied().collect();
        map_fd_source_regs.extend(other.map_fd_sources.keys().copied());
        let mut map_fd_sources = HashMap::new();
        for reg in map_fd_source_regs {
            let merged = match (
                self.map_fd_sources.get(&reg),
                other.map_fd_sources.get(&reg),
            ) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                (Some(left), None)
                    if !other.reg_types.contains_key(&reg)
                        || matches!(other.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(left.clone())
                }
                (None, Some(right))
                    if !self.reg_types.contains_key(&reg)
                        || matches!(self.reg_types.get(&reg), Some(VccValueType::Uninit)) =>
                {
                    Some(right.clone())
                }
                _ => None,
            };
            if let Some(source) = merged {
                map_fd_sources.insert(reg, source);
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
        let released_kfunc_ref_regs = self
            .released_kfunc_ref_regs
            .union(&other.released_kfunc_ref_regs)
            .copied()
            .collect();
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
        let maybe_initialized_dynptr_slots = self
            .maybe_initialized_dynptr_slots
            .union(&other.maybe_initialized_dynptr_slots)
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
            scalar_alias_roots,
            ctx_field_sources,
            map_lookup_sources,
            ambiguous_map_lookup_sources,
            ambiguous_map_lookup_maps,
            map_fd_sources,
            not_equal_consts,
            live_ringbuf_refs,
            live_kfunc_refs,
            released_kfunc_ref_regs,
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
            iter_task_vma_min_depth: self
                .iter_task_vma_min_depth
                .min(other.iter_task_vma_min_depth),
            iter_task_vma_max_depth: self
                .iter_task_vma_max_depth
                .max(other.iter_task_vma_max_depth),
            iter_task_vma_slots: merge_slot_depths(
                &self.iter_task_vma_slots,
                &other.iter_task_vma_slots,
            ),
            iter_task_min_depth: self.iter_task_min_depth.min(other.iter_task_min_depth),
            iter_task_max_depth: self.iter_task_max_depth.max(other.iter_task_max_depth),
            iter_task_slots: merge_slot_depths(&self.iter_task_slots, &other.iter_task_slots),
            iter_scx_dsq_min_depth: self
                .iter_scx_dsq_min_depth
                .min(other.iter_scx_dsq_min_depth),
            iter_scx_dsq_max_depth: self
                .iter_scx_dsq_max_depth
                .max(other.iter_scx_dsq_max_depth),
            iter_scx_dsq_slots: merge_slot_depths(
                &self.iter_scx_dsq_slots,
                &other.iter_scx_dsq_slots,
            ),
            iter_num_min_depth: self.iter_num_min_depth.min(other.iter_num_min_depth),
            iter_num_max_depth: self.iter_num_max_depth.max(other.iter_num_max_depth),
            iter_num_slots: merge_slot_depths(&self.iter_num_slots, &other.iter_num_slots),
            iter_bits_min_depth: self.iter_bits_min_depth.min(other.iter_bits_min_depth),
            iter_bits_max_depth: self.iter_bits_max_depth.max(other.iter_bits_max_depth),
            iter_bits_slots: merge_slot_depths(&self.iter_bits_slots, &other.iter_bits_slots),
            iter_css_min_depth: self.iter_css_min_depth.min(other.iter_css_min_depth),
            iter_css_max_depth: self.iter_css_max_depth.max(other.iter_css_max_depth),
            iter_css_slots: merge_slot_depths(&self.iter_css_slots, &other.iter_css_slots),
            iter_css_task_min_depth: self
                .iter_css_task_min_depth
                .min(other.iter_css_task_min_depth),
            iter_css_task_max_depth: self
                .iter_css_task_max_depth
                .max(other.iter_css_task_max_depth),
            iter_css_task_slots: merge_slot_depths(
                &self.iter_css_task_slots,
                &other.iter_css_task_slots,
            ),
            iter_dmabuf_min_depth: self.iter_dmabuf_min_depth.min(other.iter_dmabuf_min_depth),
            iter_dmabuf_max_depth: self.iter_dmabuf_max_depth.max(other.iter_dmabuf_max_depth),
            iter_dmabuf_slots: merge_slot_depths(&self.iter_dmabuf_slots, &other.iter_dmabuf_slots),
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
            bpf_spin_lock_identity: merge_bpf_spin_lock_identity(
                &self.bpf_spin_lock_identity,
                &other.bpf_spin_lock_identity,
                self.bpf_spin_lock_max_depth
                    .max(other.bpf_spin_lock_max_depth),
            ),
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
            res_spin_lock_stack: merge_res_spin_lock_stacks(
                &self.res_spin_lock_stack,
                &other.res_spin_lock_stack,
                self.res_spin_lock_max_depth
                    .max(other.res_spin_lock_max_depth)
                    + self
                        .res_spin_lock_irqsave_max_depth
                        .max(other.res_spin_lock_irqsave_max_depth),
            ),
            dynptr_initialized_slots,
            maybe_initialized_dynptr_slots,
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
                    map_root: ptr.map_root,
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
            scalar_alias_roots: self.scalar_alias_roots.clone(),
            ctx_field_sources: self.ctx_field_sources.clone(),
            map_lookup_sources: self.map_lookup_sources.clone(),
            ambiguous_map_lookup_sources: self.ambiguous_map_lookup_sources.clone(),
            ambiguous_map_lookup_maps: self.ambiguous_map_lookup_maps.clone(),
            map_fd_sources: self.map_fd_sources.clone(),
            not_equal_consts: HashMap::new(),
            live_ringbuf_refs: self.live_ringbuf_refs.clone(),
            live_kfunc_refs: self.live_kfunc_refs.clone(),
            released_kfunc_ref_regs: self.released_kfunc_ref_regs.clone(),
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
            bpf_spin_lock_identity: self.bpf_spin_lock_identity.clone(),
            res_spin_lock_irqsave_min_depth: self.res_spin_lock_irqsave_min_depth,
            res_spin_lock_irqsave_max_depth: self.res_spin_lock_irqsave_max_depth,
            res_spin_lock_irqsave_slots: self.res_spin_lock_irqsave_slots.clone(),
            res_spin_lock_stack: self.res_spin_lock_stack.clone(),
            dynptr_initialized_slots: self.dynptr_initialized_slots.clone(),
            maybe_initialized_dynptr_slots: self.maybe_initialized_dynptr_slots.clone(),
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
            (VccValueType::Uninit, other) | (other, VccValueType::Uninit) => {
                Self::clear_resource_refs_after_partial_join(other)
            }
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
            (VccValueType::Bool, VccValueType::Scalar { range })
            | (VccValueType::Scalar { range }, VccValueType::Bool) => {
                VccValueType::Scalar {
                    range: range.map(|range| VccRange {
                        min: range.min.min(0),
                        max: range.max.max(1),
                    }),
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

    fn clear_resource_refs_after_partial_join(ty: VccValueType) -> VccValueType {
        match ty {
            VccValueType::Ptr(mut ptr) => {
                ptr.ringbuf_ref = None;
                ptr.kfunc_ref = None;
                VccValueType::Ptr(ptr)
            }
            other => other,
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
            if Self::kernel_spaces_compatible(lhs.space, rhs.space) {
                if lhs.nullability == VccNullability::Null {
                    return Some(self.merge_null_wildcard_ptr(rhs, lhs));
                }
                if rhs.nullability == VccNullability::Null {
                    return Some(self.merge_null_wildcard_ptr(lhs, rhs));
                }
            }
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
        let ringbuf_ref = Self::join_resource_ref_through_null(
            lhs.ringbuf_ref,
            lhs.nullability,
            rhs.ringbuf_ref,
            rhs.nullability,
        );
        let kfunc_ref = Self::join_resource_ref_through_null(
            lhs.kfunc_ref,
            lhs.nullability,
            rhs.kfunc_ref,
            rhs.nullability,
        );
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
            map_root: if lhs.map_root == rhs.map_root {
                lhs.map_root
            } else {
                None
            },
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
        let ringbuf_ref = Self::join_resource_ref_through_null(
            concrete.ringbuf_ref,
            concrete.nullability,
            null_ptr.ringbuf_ref,
            null_ptr.nullability,
        );
        let kfunc_ref = Self::join_resource_ref_through_null(
            concrete.kfunc_ref,
            concrete.nullability,
            null_ptr.kfunc_ref,
            null_ptr.nullability,
        );
        VccPointerInfo {
            space: concrete.space,
            nullability: Self::join_nullability(concrete.nullability, null_ptr.nullability),
            bounds: concrete.bounds,
            packet_root: concrete.packet_root,
            packet_root_field: concrete.packet_root_field,
            packet_ctx_field: concrete.packet_ctx_field,
            packet_end: concrete.packet_end,
            map_root: concrete.map_root,
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

    fn kernel_spaces_compatible(lhs: VccAddrSpace, rhs: VccAddrSpace) -> bool {
        matches!(
            (lhs, rhs),
            (VccAddrSpace::Kernel, VccAddrSpace::KernelBtf)
                | (VccAddrSpace::KernelBtf, VccAddrSpace::Kernel)
        )
    }

    fn join_resource_ref_through_null<T: Copy + Eq>(
        lhs_ref: Option<T>,
        lhs_nullability: VccNullability,
        rhs_ref: Option<T>,
        rhs_nullability: VccNullability,
    ) -> Option<T> {
        match (lhs_ref, rhs_ref) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(a), None) if rhs_nullability == VccNullability::Null => Some(a),
            (None, Some(b)) if lhs_nullability == VccNullability::Null => Some(b),
            _ => None,
        }
    }

    fn join_context_field_pointer_type(
        reg: VccReg,
        ty: VccValueType,
        field: &CtxField,
    ) -> VccValueType {
        let VccValueType::Ptr(mut info) = ty else {
            return ty;
        };
        match field {
            CtxField::Data if info.space == VccAddrSpace::Packet => {
                if info.bounds.is_none() {
                    info.bounds = Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: UNKNOWN_PACKET_LIMIT,
                    });
                }
                info.packet_root = Some(reg);
                info.packet_root_field = Some(VccPacketCtxField::Data);
                info.packet_ctx_field = Some(VccPacketCtxField::Data);
                info.packet_end = false;
            }
            CtxField::DataMeta if info.space == VccAddrSpace::Packet => {
                if info.bounds.is_none() {
                    info.bounds = Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: UNKNOWN_PACKET_LIMIT,
                    });
                }
                info.packet_root = Some(reg);
                info.packet_root_field = Some(VccPacketCtxField::DataMeta);
                info.packet_ctx_field = Some(VccPacketCtxField::DataMeta);
                info.packet_end = false;
            }
            CtxField::DataEnd if info.space == VccAddrSpace::Packet => {
                info.packet_root = None;
                info.packet_root_field = None;
                info.packet_ctx_field = Some(VccPacketCtxField::DataEnd);
                info.packet_end = true;
            }
            CtxField::SockoptOptval if info.space == VccAddrSpace::Kernel => {
                if info.bounds.is_none() {
                    info.bounds = Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: UNKNOWN_CONTEXT_BUFFER_LIMIT,
                    });
                }
                info.context_buffer_root = Some(reg);
                info.context_buffer_end = false;
            }
            CtxField::SockoptOptvalEnd if info.space == VccAddrSpace::Kernel => {
                info.context_buffer_root = None;
                info.context_buffer_end = true;
            }
            _ => {}
        }
        VccValueType::Ptr(info)
    }
}

fn increment_slot_depth(depths: &mut HashMap<StackSlotId, (u32, u32)>, slot: StackSlotId) {
    let entry = depths.entry(slot).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = entry.1.saturating_add(1);
}

fn has_live_slot_depth_except(
    depths: &HashMap<StackSlotId, (u32, u32)>,
    max_depth: u32,
    allowed_slots: &HashMap<StackSlotId, u32>,
) -> bool {
    let tracked_total: u32 = depths.values().map(|(_, max_depth)| *max_depth).sum();
    if max_depth > tracked_total {
        return true;
    }
    let allowed_total = allowed_slots.values().copied().sum();
    if max_depth > allowed_total {
        return true;
    }
    depths
        .iter()
        .any(|(slot, (_, slot_max))| *slot_max > allowed_slots.get(slot).copied().unwrap_or(0))
}

fn acquire_slot_depth(
    depths: &mut HashMap<StackSlotId, (u32, u32)>,
    min_depth: &mut u32,
    max_depth: &mut u32,
    slot: StackSlotId,
) -> bool {
    if depths
        .get(&slot)
        .is_some_and(|(_, max_depth)| *max_depth > 0)
    {
        return false;
    }
    *min_depth = (*min_depth).saturating_add(1);
    *max_depth = (*max_depth).saturating_add(1);
    increment_slot_depth(depths, slot);
    true
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

fn merge_bpf_spin_lock_identity(
    lhs: &Option<BpfSpinLockIdentity>,
    rhs: &Option<BpfSpinLockIdentity>,
    max_depth: u32,
) -> Option<BpfSpinLockIdentity> {
    if lhs == rhs {
        return lhs.clone();
    }
    if max_depth == 0 {
        return None;
    }
    None
}

fn merge_res_spin_lock_stacks(
    lhs: &Option<Vec<ResSpinLockFrame>>,
    rhs: &Option<Vec<ResSpinLockFrame>>,
    max_depth: u32,
) -> Option<Vec<ResSpinLockFrame>> {
    if lhs == rhs {
        return lhs.clone();
    }
    if max_depth == 0 {
        return Some(Vec::new());
    }
    None
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

fn increment_typed_slot_max_depth(
    depths: &mut HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    slot: (StackSlotId, UnknownStackObjectTypeKey),
) {
    let entry = depths.entry(slot).or_insert((0, 0));
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
