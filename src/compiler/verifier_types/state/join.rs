use super::*;

impl VerifierState {
    pub(in crate::compiler::verifier_types) fn equivalent(&self, other: &VerifierState) -> bool {
        self.regs == other.regs
            && self.ranges == other.ranges
            && self.non_zero == other.non_zero
            && self.not_equal == other.not_equal
            && self.ctx_field_sources == other.ctx_field_sources
            && self.live_ringbuf_refs == other.live_ringbuf_refs
            && self.live_kfunc_refs == other.live_kfunc_refs
            && self.kfunc_ref_kinds == other.kfunc_ref_kinds
            && self.rcu_read_lock_min_depth == other.rcu_read_lock_min_depth
            && self.rcu_read_lock_max_depth == other.rcu_read_lock_max_depth
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
            rcu_read_lock_min_depth: self
                .rcu_read_lock_min_depth
                .min(other.rcu_read_lock_min_depth),
            rcu_read_lock_max_depth: self
                .rcu_read_lock_max_depth
                .max(other.rcu_read_lock_max_depth),
            reachable: true,
            guards,
        }
    }
}
