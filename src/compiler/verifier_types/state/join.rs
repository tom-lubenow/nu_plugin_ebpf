use super::*;

impl VerifierState {
    pub(in crate::compiler::verifier_types) fn equivalent(&self, other: &VerifierState) -> bool {
        self.regs == other.regs
            && self.ranges == other.ranges
            && self.scalar_alias_roots == other.scalar_alias_roots
            && self.non_zero == other.non_zero
            && self.not_equal == other.not_equal
            && self.ctx_field_sources == other.ctx_field_sources
            && self.map_lookup_sources == other.map_lookup_sources
            && self.ambiguous_map_lookup_sources == other.ambiguous_map_lookup_sources
            && self.ambiguous_map_lookup_maps == other.ambiguous_map_lookup_maps
            && self.map_fd_sources == other.map_fd_sources
            && self.stack_slot_value_ranges == other.stack_slot_value_ranges
            && self.live_ringbuf_refs == other.live_ringbuf_refs
            && self.released_ringbuf_record_regs == other.released_ringbuf_record_regs
            && self.live_kfunc_refs == other.live_kfunc_refs
            && self.released_kfunc_ref_regs == other.released_kfunc_ref_regs
            && self.kfunc_ref_kinds == other.kfunc_ref_kinds
            && self.rcu_read_lock_min_depth == other.rcu_read_lock_min_depth
            && self.rcu_read_lock_max_depth == other.rcu_read_lock_max_depth
            && self.preempt_disable_min_depth == other.preempt_disable_min_depth
            && self.preempt_disable_max_depth == other.preempt_disable_max_depth
            && self.local_irq_disable_min_depth == other.local_irq_disable_min_depth
            && self.local_irq_disable_max_depth == other.local_irq_disable_max_depth
            && self.local_irq_disable_slots == other.local_irq_disable_slots
            && self.iter_task_vma_min_depth == other.iter_task_vma_min_depth
            && self.iter_task_vma_max_depth == other.iter_task_vma_max_depth
            && self.iter_task_vma_slots == other.iter_task_vma_slots
            && self.iter_task_min_depth == other.iter_task_min_depth
            && self.iter_task_max_depth == other.iter_task_max_depth
            && self.iter_task_slots == other.iter_task_slots
            && self.iter_scx_dsq_min_depth == other.iter_scx_dsq_min_depth
            && self.iter_scx_dsq_max_depth == other.iter_scx_dsq_max_depth
            && self.iter_scx_dsq_slots == other.iter_scx_dsq_slots
            && self.iter_num_min_depth == other.iter_num_min_depth
            && self.iter_num_max_depth == other.iter_num_max_depth
            && self.iter_num_slots == other.iter_num_slots
            && self.iter_bits_min_depth == other.iter_bits_min_depth
            && self.iter_bits_max_depth == other.iter_bits_max_depth
            && self.iter_bits_slots == other.iter_bits_slots
            && self.iter_css_min_depth == other.iter_css_min_depth
            && self.iter_css_max_depth == other.iter_css_max_depth
            && self.iter_css_slots == other.iter_css_slots
            && self.iter_css_task_min_depth == other.iter_css_task_min_depth
            && self.iter_css_task_max_depth == other.iter_css_task_max_depth
            && self.iter_css_task_slots == other.iter_css_task_slots
            && self.iter_dmabuf_min_depth == other.iter_dmabuf_min_depth
            && self.iter_dmabuf_max_depth == other.iter_dmabuf_max_depth
            && self.iter_dmabuf_slots == other.iter_dmabuf_slots
            && self.iter_kmem_cache_min_depth == other.iter_kmem_cache_min_depth
            && self.iter_kmem_cache_max_depth == other.iter_kmem_cache_max_depth
            && self.iter_kmem_cache_slots == other.iter_kmem_cache_slots
            && self.res_spin_lock_min_depth == other.res_spin_lock_min_depth
            && self.res_spin_lock_max_depth == other.res_spin_lock_max_depth
            && self.bpf_spin_lock_min_depth == other.bpf_spin_lock_min_depth
            && self.bpf_spin_lock_max_depth == other.bpf_spin_lock_max_depth
            && self.bpf_spin_lock_identity == other.bpf_spin_lock_identity
            && self.res_spin_lock_irqsave_min_depth == other.res_spin_lock_irqsave_min_depth
            && self.res_spin_lock_irqsave_max_depth == other.res_spin_lock_irqsave_max_depth
            && self.res_spin_lock_irqsave_slots == other.res_spin_lock_irqsave_slots
            && self.res_spin_lock_stack == other.res_spin_lock_stack
            && self.dynptr_initialized_slots == other.dynptr_initialized_slots
            && self.maybe_initialized_dynptr_slots == other.maybe_initialized_dynptr_slots
            && self.ringbuf_dynptr_slots == other.ringbuf_dynptr_slots
            && self.ringbuf_dynptr_alias_roots == other.ringbuf_dynptr_alias_roots
            && self.released_ringbuf_dynptr_slots == other.released_ringbuf_dynptr_slots
            && self.unknown_stack_object_slots == other.unknown_stack_object_slots
            && self.guards == other.guards
            && self.reachable == other.reachable
    }

    pub(in crate::compiler::verifier_types) fn join(&self, other: &VerifierState) -> VerifierState {
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
        let mut scalar_alias_roots = Vec::with_capacity(self.scalar_alias_roots.len());
        for i in 0..self.scalar_alias_roots.len() {
            let merged = match (self.scalar_alias_roots[i], other.scalar_alias_roots[i]) {
                (Some(left), Some(right)) if left == right => Some(left),
                (Some(left), None) if matches!(other.regs[i], VerifierType::Uninit) => Some(left),
                (None, Some(right)) if matches!(self.regs[i], VerifierType::Uninit) => Some(right),
                _ => None,
            };
            scalar_alias_roots.push(merged);
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
                (Some(left), None) if matches!(other.regs[i], VerifierType::Uninit) => {
                    Some(left.clone())
                }
                (None, Some(right)) if matches!(self.regs[i], VerifierType::Uninit) => {
                    Some(right.clone())
                }
                _ => None,
            };
            ctx_field_sources.push(merged);
        }
        for (idx, source) in ctx_field_sources.iter().enumerate() {
            if let Some(source) = source {
                regs[idx] =
                    Self::join_context_field_pointer_type(VReg(idx as u32), regs[idx], source);
            }
        }
        let mut map_lookup_sources = Vec::with_capacity(self.map_lookup_sources.len());
        let mut ambiguous_map_lookup_sources =
            Vec::with_capacity(self.ambiguous_map_lookup_sources.len());
        let mut ambiguous_map_lookup_maps =
            Vec::with_capacity(self.ambiguous_map_lookup_maps.len());
        for i in 0..self.map_lookup_sources.len() {
            let left_ambiguous = self.ambiguous_map_lookup_sources[i];
            let right_ambiguous = other.ambiguous_map_lookup_sources[i];
            let same_lookup = |left: &MapLookupSource, right: &MapLookupSource| {
                left.map == right.map
                    && self.join_map_lookup_keys_may_alias(other, left.key, right.key)
            };
            let left_map = if left_ambiguous {
                self.ambiguous_map_lookup_maps[i].clone()
            } else {
                self.map_lookup_sources[i]
                    .as_ref()
                    .map(|source| source.map.clone())
            };
            let right_map = if right_ambiguous {
                other.ambiguous_map_lookup_maps[i].clone()
            } else {
                other.map_lookup_sources[i]
                    .as_ref()
                    .map(|source| source.map.clone())
            };
            let same_known_map = match (&left_map, &right_map) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                _ => None,
            };
            let merged = match (&self.map_lookup_sources[i], &other.map_lookup_sources[i]) {
                _ if left_ambiguous || right_ambiguous => None,
                (Some(left), Some(right)) if same_lookup(left, right) => Some(left.clone()),
                (Some(_), Some(_)) => None,
                (Some(left), None) if matches!(other.regs[i], VerifierType::Uninit) => {
                    Some(left.clone())
                }
                (None, Some(right)) if matches!(self.regs[i], VerifierType::Uninit) => {
                    Some(right.clone())
                }
                _ => None,
            };
            let ambiguous = left_ambiguous
                || right_ambiguous
                || matches!(
                    (&self.map_lookup_sources[i], &other.map_lookup_sources[i]),
                    (Some(left), Some(right)) if !same_lookup(left, right)
                );
            let ambiguous_map = if ambiguous {
                if left_ambiguous && matches!(other.regs[i], VerifierType::Uninit) {
                    left_map
                } else if right_ambiguous && matches!(self.regs[i], VerifierType::Uninit) {
                    right_map
                } else {
                    same_known_map
                }
            } else {
                None
            };
            map_lookup_sources.push(merged);
            ambiguous_map_lookup_sources.push(ambiguous);
            ambiguous_map_lookup_maps.push(ambiguous_map);
        }
        let mut map_fd_sources = Vec::with_capacity(self.map_fd_sources.len());
        for i in 0..self.map_fd_sources.len() {
            let merged = match (&self.map_fd_sources[i], &other.map_fd_sources[i]) {
                (Some(left), Some(right)) if left == right => Some(left.clone()),
                (Some(left), None) if matches!(other.regs[i], VerifierType::Uninit) => {
                    Some(left.clone())
                }
                (None, Some(right)) if matches!(self.regs[i], VerifierType::Uninit) => {
                    Some(right.clone())
                }
                _ => None,
            };
            map_fd_sources.push(merged);
        }
        let stack_slot_value_ranges = merge_stack_slot_value_ranges(
            &self.stack_slot_value_ranges,
            &other.stack_slot_value_ranges,
        );
        let mut live_ringbuf_refs = Vec::with_capacity(self.live_ringbuf_refs.len());
        for i in 0..self.live_ringbuf_refs.len() {
            live_ringbuf_refs.push(self.live_ringbuf_refs[i] || other.live_ringbuf_refs[i]);
        }
        let mut released_ringbuf_record_regs =
            Vec::with_capacity(self.released_ringbuf_record_regs.len());
        for i in 0..self.released_ringbuf_record_regs.len() {
            released_ringbuf_record_regs.push(
                self.released_ringbuf_record_regs[i] || other.released_ringbuf_record_regs[i],
            );
        }
        let mut live_kfunc_refs = Vec::with_capacity(self.live_kfunc_refs.len());
        let mut released_kfunc_ref_regs = Vec::with_capacity(self.released_kfunc_ref_regs.len());
        let mut kfunc_ref_kinds = Vec::with_capacity(self.kfunc_ref_kinds.len());
        for i in 0..self.live_kfunc_refs.len() {
            let left_live = self.live_kfunc_refs[i];
            let right_live = other.live_kfunc_refs[i];
            let live = left_live || right_live;
            live_kfunc_refs.push(live);
            released_kfunc_ref_regs
                .push(self.released_kfunc_ref_regs[i] || other.released_kfunc_ref_regs[i]);

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
        let unknown_stack_object_slots = join_typed_slot_depths(
            &self.unknown_stack_object_slots,
            &other.unknown_stack_object_slots,
        );
        let ringbuf_dynptr_slots =
            join_slot_depths(&self.ringbuf_dynptr_slots, &other.ringbuf_dynptr_slots);
        let ringbuf_dynptr_alias_roots = join_ringbuf_dynptr_alias_roots(
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
        VerifierState {
            regs,
            ranges,
            scalar_alias_roots,
            non_zero,
            not_equal,
            ctx_field_sources,
            map_lookup_sources,
            ambiguous_map_lookup_sources,
            ambiguous_map_lookup_maps,
            map_fd_sources,
            stack_slot_value_ranges,
            live_ringbuf_refs,
            released_ringbuf_record_regs,
            live_kfunc_refs,
            released_kfunc_ref_regs,
            kfunc_ref_kinds,
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
            local_irq_disable_slots: join_slot_depths(
                &self.local_irq_disable_slots,
                &other.local_irq_disable_slots,
            ),
            iter_task_vma_min_depth: self
                .iter_task_vma_min_depth
                .min(other.iter_task_vma_min_depth),
            iter_task_vma_max_depth: self
                .iter_task_vma_max_depth
                .max(other.iter_task_vma_max_depth),
            iter_task_vma_slots: join_slot_depths(
                &self.iter_task_vma_slots,
                &other.iter_task_vma_slots,
            ),
            iter_task_min_depth: self.iter_task_min_depth.min(other.iter_task_min_depth),
            iter_task_max_depth: self.iter_task_max_depth.max(other.iter_task_max_depth),
            iter_task_slots: join_slot_depths(&self.iter_task_slots, &other.iter_task_slots),
            iter_scx_dsq_min_depth: self
                .iter_scx_dsq_min_depth
                .min(other.iter_scx_dsq_min_depth),
            iter_scx_dsq_max_depth: self
                .iter_scx_dsq_max_depth
                .max(other.iter_scx_dsq_max_depth),
            iter_scx_dsq_slots: join_slot_depths(
                &self.iter_scx_dsq_slots,
                &other.iter_scx_dsq_slots,
            ),
            iter_num_min_depth: self.iter_num_min_depth.min(other.iter_num_min_depth),
            iter_num_max_depth: self.iter_num_max_depth.max(other.iter_num_max_depth),
            iter_num_slots: join_slot_depths(&self.iter_num_slots, &other.iter_num_slots),
            iter_bits_min_depth: self.iter_bits_min_depth.min(other.iter_bits_min_depth),
            iter_bits_max_depth: self.iter_bits_max_depth.max(other.iter_bits_max_depth),
            iter_bits_slots: join_slot_depths(&self.iter_bits_slots, &other.iter_bits_slots),
            iter_css_min_depth: self.iter_css_min_depth.min(other.iter_css_min_depth),
            iter_css_max_depth: self.iter_css_max_depth.max(other.iter_css_max_depth),
            iter_css_slots: join_slot_depths(&self.iter_css_slots, &other.iter_css_slots),
            iter_css_task_min_depth: self
                .iter_css_task_min_depth
                .min(other.iter_css_task_min_depth),
            iter_css_task_max_depth: self
                .iter_css_task_max_depth
                .max(other.iter_css_task_max_depth),
            iter_css_task_slots: join_slot_depths(
                &self.iter_css_task_slots,
                &other.iter_css_task_slots,
            ),
            iter_dmabuf_min_depth: self.iter_dmabuf_min_depth.min(other.iter_dmabuf_min_depth),
            iter_dmabuf_max_depth: self.iter_dmabuf_max_depth.max(other.iter_dmabuf_max_depth),
            iter_dmabuf_slots: join_slot_depths(&self.iter_dmabuf_slots, &other.iter_dmabuf_slots),
            iter_kmem_cache_min_depth: self
                .iter_kmem_cache_min_depth
                .min(other.iter_kmem_cache_min_depth),
            iter_kmem_cache_max_depth: self
                .iter_kmem_cache_max_depth
                .max(other.iter_kmem_cache_max_depth),
            iter_kmem_cache_slots: join_slot_depths(
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
            bpf_spin_lock_identity: join_bpf_spin_lock_identity(
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
            res_spin_lock_irqsave_slots: join_slot_depths(
                &self.res_spin_lock_irqsave_slots,
                &other.res_spin_lock_irqsave_slots,
            ),
            res_spin_lock_stack: join_res_spin_lock_stacks(
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
            reachable: true,
            guards,
        }
    }

    fn join_context_field_pointer_type(
        reg: VReg,
        ty: VerifierType,
        field: &CtxField,
    ) -> VerifierType {
        let VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        } = ty
        else {
            return ty;
        };

        let bounds = match (field, space, bounds) {
            (CtxField::Data | CtxField::DataMeta, AddressSpace::Packet, None) => Some(
                PtrBounds::new(PtrOrigin::Packet(reg), 0, 0, UNKNOWN_PACKET_LIMIT),
            ),
            (CtxField::SockoptOptval, AddressSpace::Kernel, None) => Some(PtrBounds::new(
                PtrOrigin::ContextBuffer(reg),
                0,
                0,
                UNKNOWN_CONTEXT_BUFFER_LIMIT,
            )),
            _ => bounds,
        };

        VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        }
    }

    fn join_map_lookup_keys_may_alias(&self, other: &VerifierState, lhs: VReg, rhs: VReg) -> bool {
        self.map_lookup_keys_may_alias(lhs, rhs)
            || other.map_lookup_keys_may_alias(lhs, rhs)
            || self.scalar_alias_root(lhs) == other.scalar_alias_root(rhs)
            || other.scalar_alias_root(lhs) == self.scalar_alias_root(rhs)
            || Self::same_known_const_range(self.get_range(lhs), other.get_range(rhs))
            || Self::same_known_const_range(other.get_range(lhs), self.get_range(rhs))
            || Self::ctx_field_values_may_alias_across(self, lhs, other, rhs)
            || Self::ctx_field_values_may_alias_across(other, lhs, self, rhs)
    }

    fn same_known_const_range(lhs: ValueRange, rhs: ValueRange) -> bool {
        matches!(
            (lhs, rhs),
            (
                ValueRange::Known { min: lhs_min, max: lhs_max },
                ValueRange::Known { min: rhs_min, max: rhs_max },
            ) if lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min
        )
    }

    fn ctx_field_values_may_alias_across(
        lhs_state: &VerifierState,
        lhs: VReg,
        rhs_state: &VerifierState,
        rhs: VReg,
    ) -> bool {
        let Some(lhs_field) = lhs_state.ctx_field_source(lhs) else {
            return false;
        };
        if rhs_state.ctx_field_source(rhs) != Some(lhs_field) {
            return false;
        }
        matches!(
            (lhs_state.get(lhs), rhs_state.get(rhs)),
            (
                VerifierType::Scalar | VerifierType::Bool,
                VerifierType::Scalar | VerifierType::Bool,
            )
        )
    }
}

fn join_bpf_spin_lock_identity(
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

fn join_res_spin_lock_stacks(
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

fn merge_stack_slot_value_ranges(
    lhs: &HashMap<StackSlotId, ValueRange>,
    rhs: &HashMap<StackSlotId, ValueRange>,
) -> HashMap<StackSlotId, ValueRange> {
    let mut merged = HashMap::new();
    for slot in lhs.keys().chain(rhs.keys()) {
        let Some(lhs_range) = lhs.get(slot).copied() else {
            continue;
        };
        let Some(rhs_range) = rhs.get(slot).copied() else {
            continue;
        };
        if let ValueRange::Known { .. } = join_range(lhs_range, rhs_range) {
            merged.insert(*slot, join_range(lhs_range, rhs_range));
        }
    }
    merged
}

fn join_slot_depths(
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

fn join_ringbuf_dynptr_alias_roots(
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

fn join_typed_slot_depths(
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
