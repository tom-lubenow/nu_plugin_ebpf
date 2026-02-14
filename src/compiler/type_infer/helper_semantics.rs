use super::*;

impl<'a> TypeInference<'a> {
    pub(super) fn mir_type_for_vreg(&self, vreg: VReg, types: &HashMap<VReg, MirType>) -> MirType {
        types.get(&vreg).cloned().unwrap_or(MirType::Unknown)
    }

    pub(super) fn mir_type_for_value(
        &self,
        value: &MirValue,
        types: &HashMap<VReg, MirType>,
    ) -> MirType {
        match value {
            MirValue::VReg(vreg) => self.mir_type_for_vreg(*vreg, types),
            MirValue::Const(_) => MirType::I64,
            MirValue::StackSlot(_) => MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        }
    }

    pub(super) fn mir_is_numeric(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
        )
    }

    pub(super) fn mir_ptr_space(ty: &MirType) -> Option<AddressSpace> {
        match ty {
            MirType::Ptr { address_space, .. } => Some(*address_space),
            _ => None,
        }
    }

    pub(super) fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_shared(kfunc, arg_idx)
    }

    pub(super) fn helper_pointer_arg_allows_const_zero(helper_id: u32, arg_idx: usize) -> bool {
        matches!(
            (BpfHelper::from_u32(helper_id), arg_idx),
            (Some(BpfHelper::KptrXchg), 1)
                | (Some(BpfHelper::SkAssign), 1)
                | (Some(BpfHelper::SkStorageGet), 2)
                | (Some(BpfHelper::InodeStorageGet), 2)
                | (Some(BpfHelper::TaskStorageGet), 2)
        )
    }

    pub(super) fn helper_ptr_space_allowed(
        space: AddressSpace,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> bool {
        match space {
            AddressSpace::Stack => allow_stack,
            AddressSpace::Map => allow_map,
            AddressSpace::Kernel => allow_kernel,
            AddressSpace::User => allow_user,
        }
    }

    pub(super) fn helper_allowed_spaces_label(
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> &'static str {
        match (allow_stack, allow_map, allow_kernel, allow_user) {
            (true, true, false, false) => "[Stack, Map]",
            (true, true, true, false) => "[Stack, Map, Kernel]",
            (false, false, true, false) => "[Kernel]",
            (false, false, false, true) => "[User]",
            (true, false, false, false) => "[Stack]",
            (false, true, false, false) => "[Map]",
            (false, false, false, false) => "[]",
            _ => "[Stack, Map, Kernel, User]",
        }
    }

    pub(super) fn helper_positive_size_upper_bound(
        &self,
        helper_id: u32,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) -> Option<usize> {
        match self.value_range_for(value, value_ranges) {
            ValueRange::Known { min, max } => {
                if max <= 0 || min <= 0 {
                    errors.push(TypeError::new(format!(
                        "helper {} arg{} must be > 0",
                        helper_id, arg_idx
                    )));
                    return None;
                }
                usize::try_from(max).ok()
            }
            _ => None,
        }
    }

    pub(super) fn validate_helper_semantics(
        &self,
        helper_id: u32,
        args: &[MirValue],
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
        stack_bounds: &HashMap<VReg, StackBounds>,
        slot_sizes: &HashMap<StackSlotId, i64>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some(helper) = BpfHelper::from_u32(helper_id) else {
            return;
        };

        let semantics = helper.semantics();
        let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
        for size_arg in semantics.positive_size_args {
            if let Some(value) = args.get(*size_arg) {
                positive_size_bounds[*size_arg] = self.helper_positive_size_upper_bound(
                    helper_id,
                    *size_arg,
                    value,
                    value_ranges,
                    errors,
                );
            }
        }

        for rule in semantics.ptr_arg_rules {
            let Some(arg) = args.get(rule.arg_idx) else {
                continue;
            };
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => positive_size_bounds[size_arg],
                (None, None) => None,
            };
            if matches!(arg, MirValue::Const(0))
                && Self::helper_pointer_arg_allows_const_zero(helper_id, rule.arg_idx)
            {
                continue;
            }
            match arg {
                MirValue::VReg(vreg) => match self.mir_type_for_vreg(*vreg, types) {
                    MirType::Ptr {
                        address_space,
                        pointee,
                    } => {
                        let allowed = Self::helper_allowed_spaces_label(
                            rule.allowed.allow_stack,
                            rule.allowed.allow_map,
                            rule.allowed.allow_kernel,
                            rule.allowed.allow_user,
                        );
                        if !Self::helper_ptr_space_allowed(
                            address_space,
                            rule.allowed.allow_stack,
                            rule.allowed.allow_map,
                            rule.allowed.allow_kernel,
                            rule.allowed.allow_user,
                        ) {
                            errors.push(TypeError::new(format!(
                                "{} expects pointer in {}, got {:?}",
                                rule.op, allowed, address_space
                            )));
                            continue;
                        }
                        if let Some(size) = access_size {
                            match address_space {
                                AddressSpace::Stack => {
                                    if let Some(bounds) = stack_bounds.get(vreg) {
                                        let end = bounds.max + size as i64 - 1;
                                        if bounds.min < 0 || end > bounds.limit {
                                            errors.push(TypeError::new(format!(
                                                "{} requires {} bytes, stack pointer range [{}..{}] exceeds [0..{}]",
                                                rule.op, size, bounds.min, bounds.max, bounds.limit
                                            )));
                                        }
                                    }
                                }
                                AddressSpace::Map => {
                                    let pointee_size = pointee.size();
                                    if pointee_size > 0 && size > pointee_size {
                                        errors.push(TypeError::new(format!(
                                            "{} requires {} bytes, map value pointee is {} bytes",
                                            rule.op, size, pointee_size
                                        )));
                                    }
                                }
                                AddressSpace::Kernel | AddressSpace::User => {}
                            }
                        }
                    }
                    other => errors.push(TypeError::new(format!(
                        "helper {} arg{} expects pointer value, got {:?}",
                        helper_id, rule.arg_idx, other
                    ))),
                },
                MirValue::StackSlot(slot) => {
                    if !rule.allowed.allow_stack {
                        let allowed = Self::helper_allowed_spaces_label(
                            rule.allowed.allow_stack,
                            rule.allowed.allow_map,
                            rule.allowed.allow_kernel,
                            rule.allowed.allow_user,
                        );
                        errors.push(TypeError::new(format!(
                            "{} expects pointer in {}, got stack slot {}",
                            rule.op, allowed, slot.0
                        )));
                        continue;
                    }
                    if let Some(size) = access_size {
                        let slot_size = slot_sizes.get(slot).copied().unwrap_or(0);
                        if size as i64 > slot_size {
                            errors.push(TypeError::new(format!(
                                "{} requires {} bytes, stack slot {} has {} bytes",
                                rule.op, size, slot.0, slot_size
                            )));
                        }
                    }
                }
                MirValue::Const(_) => errors.push(TypeError::new(format!(
                    "helper {} arg{} expects pointer value",
                    helper_id, rule.arg_idx
                ))),
            }
        }
    }

    pub(super) fn is_const_zero(value: &MirValue) -> bool {
        matches!(value, MirValue::Const(c) if *c == 0)
    }

    pub(super) fn const_value(value: &MirValue) -> Option<i64> {
        match value {
            MirValue::Const(c) => Some(*c),
            _ => None,
        }
    }

    pub(super) fn record_field_size(ty: &MirType) -> usize {
        match ty {
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => {
                if *len == 16 {
                    16
                } else {
                    (*len + 7) & !7
                }
            }
            _ => 8,
        }
    }
}
