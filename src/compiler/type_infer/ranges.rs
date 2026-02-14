use super::*;

impl<'a> TypeInference<'a> {
    pub(super) fn compute_list_caps(&self, func: &MirFunction) -> HashMap<VReg, usize> {
        let mut caps: HashMap<VReg, usize> = HashMap::new();
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let mut changed = true;
        let max_iters = func.vreg_count.max(1);

        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;
            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    match inst {
                        MirInst::ListNew {
                            dst,
                            buffer,
                            max_len,
                        } => {
                            let cap = slot_caps
                                .get(buffer)
                                .copied()
                                .map(|slot_cap| (*max_len).min(slot_cap))
                                .unwrap_or(*max_len);
                            let entry = caps.entry(*dst).or_insert(cap);
                            if *entry != cap {
                                *entry = cap;
                                changed = true;
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::StackSlot(slot),
                        } => {
                            if let Some(&cap) = slot_caps.get(slot) {
                                let entry = caps.entry(*dst).or_insert(cap);
                                if *entry != cap {
                                    *entry = cap;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::VReg(src),
                        } => {
                            if let Some(&cap) = caps.get(src) {
                                let entry = caps.entry(*dst).or_insert(cap);
                                if *entry != cap {
                                    *entry = cap;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Phi { dst, args } => {
                            let mut cap = None;
                            let mut consistent = true;
                            for (_, vreg) in args {
                                match (cap, caps.get(vreg)) {
                                    (None, Some(&c)) => cap = Some(c),
                                    (Some(c), Some(&c2)) if c == c2 => {}
                                    _ => {
                                        consistent = false;
                                        break;
                                    }
                                }
                            }
                            if consistent {
                                if let Some(c) = cap {
                                    let entry = caps.entry(*dst).or_insert(c);
                                    if *entry != c {
                                        *entry = c;
                                        changed = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        caps
    }

    pub(super) fn list_len_range(cap: usize) -> ValueRange {
        // We intentionally cap at max_len-1 to keep list element addressing bounded.
        let max = cap.saturating_sub(1) as i64;
        ValueRange::known(0, max)
    }

    pub(super) fn compute_value_ranges(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
    ) -> HashMap<VReg, ValueRange> {
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let total_vregs = func.vreg_count.max(func.param_count as u32);
        let mut ranges: HashMap<VReg, ValueRange> = HashMap::new();
        for i in 0..total_vregs {
            ranges.insert(VReg(i), ValueRange::Unset);
        }

        let mut changed = true;
        let max_iters = func.vreg_count.max(1);
        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;
            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    let Some(dst) = inst.def() else {
                        continue;
                    };
                    let dst_ty = types.get(&dst).cloned().unwrap_or(MirType::Unknown);
                    if !Self::mir_is_numeric(&dst_ty) {
                        continue;
                    }

                    let new_range = match inst {
                        MirInst::Copy { src, .. } => self.value_range_for(src, &ranges),
                        MirInst::BinOp { op, lhs, rhs, .. } => {
                            let lhs_range = self.value_range_for(lhs, &ranges);
                            let rhs_range = self.value_range_for(rhs, &ranges);
                            self.range_for_binop(*op, lhs_range, rhs_range)
                        }
                        MirInst::UnaryOp { op, src, .. } => {
                            let src_range = self.value_range_for(src, &ranges);
                            self.range_for_unary(*op, src_range)
                        }
                        MirInst::ListLen { list, .. } => list_caps
                            .get(list)
                            .map(|cap| Self::list_len_range(*cap))
                            .unwrap_or(ValueRange::Unknown),
                        MirInst::Load { ptr, offset, .. } => {
                            if *offset == 0 {
                                list_caps
                                    .get(ptr)
                                    .map(|cap| Self::list_len_range(*cap))
                                    .unwrap_or(ValueRange::Unknown)
                            } else {
                                ValueRange::Unknown
                            }
                        }
                        MirInst::LoadSlot { slot, offset, .. } => {
                            if *offset == 0 {
                                slot_caps
                                    .get(slot)
                                    .map(|cap| Self::list_len_range(*cap))
                                    .unwrap_or(ValueRange::Unknown)
                            } else {
                                ValueRange::Unknown
                            }
                        }
                        MirInst::Phi { args, .. } => {
                            let mut merged: Option<ValueRange> = None;
                            for (_, vreg) in args {
                                let range =
                                    ranges.get(vreg).copied().unwrap_or(ValueRange::Unknown);
                                merged = Some(match merged {
                                    None => range,
                                    Some(existing) => existing.merge(range),
                                });
                            }
                            merged.unwrap_or(ValueRange::Unknown)
                        }
                        _ => ValueRange::Unknown,
                    };

                    let entry = ranges.entry(dst).or_insert(ValueRange::Unknown);
                    let merged = entry.merge(new_range);
                    if *entry != merged {
                        *entry = merged;
                        changed = true;
                    }
                }
            }
        }

        ranges
    }

    pub(super) fn compute_stack_bounds(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
    ) -> HashMap<VReg, StackBounds> {
        let mut slot_limits: HashMap<StackSlotId, i64> = HashMap::new();
        for slot in &func.stack_slots {
            let limit = slot.size.saturating_sub(1) as i64;
            slot_limits.insert(slot.id, limit);
        }

        let mut bounds: HashMap<VReg, StackBounds> = HashMap::new();
        let mut changed = true;
        let max_iters = func.vreg_count.max(1);

        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;
            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    let update = match inst {
                        MirInst::ListNew {
                            dst,
                            buffer,
                            max_len,
                        } => {
                            let list_limit = (*max_len as i64) * 8;
                            let limit = slot_limits
                                .get(buffer)
                                .map(|slot_limit| list_limit.min(*slot_limit))
                                .unwrap_or(list_limit);
                            Some((
                                *dst,
                                StackBounds {
                                    slot: *buffer,
                                    min: 0,
                                    max: 0,
                                    limit,
                                },
                            ))
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::StackSlot(slot),
                        } => {
                            let limit = slot_limits.get(slot).copied().unwrap_or(0);
                            Some((
                                *dst,
                                StackBounds {
                                    slot: *slot,
                                    min: 0,
                                    max: 0,
                                    limit,
                                },
                            ))
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::VReg(src),
                        } => bounds.get(src).copied().map(|b| (*dst, b)),
                        MirInst::Phi { dst, args } => {
                            let mut merged: Option<StackBounds> = None;
                            let mut consistent = true;
                            for (_, vreg) in args {
                                let Some(b) = bounds.get(vreg).copied() else {
                                    consistent = false;
                                    break;
                                };
                                merged = Some(match merged {
                                    None => b,
                                    Some(existing) => {
                                        if existing.slot != b.slot || existing.limit != b.limit {
                                            consistent = false;
                                            break;
                                        }
                                        StackBounds {
                                            slot: existing.slot,
                                            min: existing.min.min(b.min),
                                            max: existing.max.max(b.max),
                                            limit: existing.limit,
                                        }
                                    }
                                });
                                if !consistent {
                                    break;
                                }
                            }
                            if consistent {
                                merged.map(|b| (*dst, b))
                            } else {
                                None
                            }
                        }
                        MirInst::BinOp { dst, op, lhs, rhs } => {
                            if !matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                                None
                            } else {
                                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                                if !matches!(
                                    dst_ty,
                                    MirType::Ptr {
                                        address_space: AddressSpace::Stack,
                                        ..
                                    }
                                ) {
                                    None
                                } else {
                                    let base_info = if matches!(op, BinOpKind::Add) {
                                        let lhs_bounds = match lhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        let rhs_bounds = match rhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if lhs_bounds.is_some() {
                                            Some((lhs, rhs, true))
                                        } else if rhs_bounds.is_some() {
                                            Some((rhs, lhs, true))
                                        } else {
                                            None
                                        }
                                    } else {
                                        let lhs_bounds = match lhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if lhs_bounds.is_some() {
                                            Some((lhs, rhs, false))
                                        } else {
                                            None
                                        }
                                    };

                                    if let Some((base, offset, is_add)) = base_info {
                                        let base_bounds = match base {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if let Some(base_bounds) = base_bounds {
                                            let offset_range =
                                                self.value_range_for(offset, value_ranges);
                                            if let ValueRange::Known { min, max } = offset_range {
                                                if min < 0 {
                                                    None
                                                } else {
                                                    let (new_min, new_max) = if is_add {
                                                        (
                                                            base_bounds.min + min,
                                                            base_bounds.max + max,
                                                        )
                                                    } else {
                                                        (
                                                            base_bounds.min - max,
                                                            base_bounds.max - min,
                                                        )
                                                    };
                                                    if new_min < 0 || new_max > base_bounds.limit {
                                                        None
                                                    } else {
                                                        Some((
                                                            *dst,
                                                            StackBounds {
                                                                slot: base_bounds.slot,
                                                                min: new_min,
                                                                max: new_max,
                                                                limit: base_bounds.limit,
                                                            },
                                                        ))
                                                    }
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                            }
                        }
                        _ => None,
                    };

                    if let Some((dst, new_bounds)) = update {
                        match bounds.get(&dst).copied() {
                            None => {
                                bounds.insert(dst, new_bounds);
                                changed = true;
                            }
                            Some(existing) => {
                                if existing.slot != new_bounds.slot
                                    || existing.limit != new_bounds.limit
                                {
                                    bounds.remove(&dst);
                                    changed = true;
                                } else {
                                    let merged = StackBounds {
                                        slot: existing.slot,
                                        min: existing.min.min(new_bounds.min),
                                        max: existing.max.max(new_bounds.max),
                                        limit: existing.limit,
                                    };
                                    if merged != existing {
                                        bounds.insert(dst, merged);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        bounds
    }

    pub(super) fn value_range_for(
        &self,
        value: &MirValue,
        ranges: &HashMap<VReg, ValueRange>,
    ) -> ValueRange {
        match value {
            MirValue::Const(c) => ValueRange::known(*c, *c),
            MirValue::VReg(v) => ranges.get(v).copied().unwrap_or(ValueRange::Unknown),
            MirValue::StackSlot(_) => ValueRange::Unknown,
        }
    }

    pub(super) fn stack_bounds_for_value<'b>(
        &self,
        value: &MirValue,
        stack_bounds: &'b HashMap<VReg, StackBounds>,
    ) -> Option<&'b StackBounds> {
        match value {
            MirValue::VReg(v) => stack_bounds.get(v),
            _ => None,
        }
    }

    pub(super) fn range_for_binop(
        &self,
        op: BinOpKind,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match op {
            BinOpKind::Add => self.range_add(lhs, rhs),
            BinOpKind::Sub => self.range_sub(lhs, rhs),
            BinOpKind::Mul => self.range_mul(lhs, rhs),
            BinOpKind::Shl | BinOpKind::Shr => self.range_shift(lhs, rhs),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_for_unary(&self, op: UnaryOpKind, src: ValueRange) -> ValueRange {
        match op {
            UnaryOpKind::Neg => match src {
                ValueRange::Known { min, max } => ValueRange::known(-max, -min),
                ValueRange::Unknown | ValueRange::Unset => ValueRange::Unknown,
            },
            UnaryOpKind::Not => ValueRange::known(0, 1),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_add(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(lmin + rmin, lmax + rmax),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_sub(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(lmin - rmax, lmax - rmin),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_mul(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let (lmin, lmax, rmin, rmax) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => (lmin, lmax, rmin, rmax),
            _ => return ValueRange::Unknown,
        };
        let candidates = [
            lmin.saturating_mul(rmin),
            lmin.saturating_mul(rmax),
            lmax.saturating_mul(rmin),
            lmax.saturating_mul(rmax),
        ];
        let min = *candidates.iter().min().unwrap_or(&0);
        let max = *candidates.iter().max().unwrap_or(&0);
        ValueRange::known(min, max)
    }

    pub(super) fn range_shift(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let _ = (lhs, rhs);
        ValueRange::Unknown
    }
}
