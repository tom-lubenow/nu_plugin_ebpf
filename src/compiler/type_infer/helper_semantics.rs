use super::*;
use crate::compiler::EbpfProgramType;
use crate::kernel_btf::KernelBtf;

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
            MirValue::StackSlot(slot) => self
                .stack_slot_hints
                .and_then(|hints| hints.get(slot))
                .cloned()
                .map(|ty| MirType::Ptr {
                    pointee: Box::new(ty),
                    address_space: AddressSpace::Stack,
                })
                .unwrap_or(MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                }),
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

    pub(super) fn mir_is_stack_or_map_ptr(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::Ptr {
                address_space: AddressSpace::Stack | AddressSpace::Map,
                ..
            }
        )
    }

    pub(super) fn mir_requires_pointer_value(ty: &MirType) -> bool {
        matches!(ty, MirType::Array { .. } | MirType::Struct { .. }) || ty.size() > 8
    }

    pub(super) fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_user(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_user_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack_slot_base(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_slot_base_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack_or_map(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_or_map_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_allows_const_zero(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_allows_const_zero_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_size_from_scalar(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_size_from_scalar_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_fixed_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_fixed_size_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_min_access_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_min_access_size_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_scalar_arg_requires_known_const(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_scalar_arg_requires_known_const_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_scalar_arg_requires_positive(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_scalar_arg_requires_positive_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_unknown_dynptr_copy(kfunc: &str) -> Vec<KfuncUnknownDynptrCopy> {
        kfunc_unknown_dynptr_copy_shared(kfunc)
    }

    pub(super) fn kfunc_unknown_stack_object_copy(kfunc: &str) -> Vec<KfuncUnknownStackObjectCopy> {
        kfunc_unknown_stack_object_copy_shared(kfunc)
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
            AddressSpace::Packet => false,
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

    pub(super) fn kfunc_positive_size_upper_bound(
        &self,
        kfunc: &str,
        arg_idx: usize,
        value: VReg,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) -> Option<usize> {
        match self.value_range_for(&MirValue::VReg(value), value_ranges) {
            ValueRange::Known { min, max } => {
                if max <= 0 || min <= 0 {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' arg{} must be > 0",
                        kfunc, arg_idx
                    )));
                    return None;
                }
                usize::try_from(max).ok()
            }
            _ => None,
        }
    }

    fn known_const_vreg(
        &self,
        vreg: VReg,
        value_ranges: &HashMap<VReg, ValueRange>,
    ) -> Option<i64> {
        match self.value_range_for(&MirValue::VReg(vreg), value_ranges) {
            ValueRange::Known { min, max } if min == max => Some(min),
            _ => None,
        }
    }

    fn sched_ext_kick_flag_bits() -> (i64, i64, i64) {
        let mut idle = None;
        let mut preempt = None;
        let mut wait = None;

        if let Ok(info) = KernelBtf::get().kernel_named_enum_info("scx_kick_flags") {
            for (name, value) in info.entries {
                match name.as_str() {
                    "SCX_KICK_IDLE" => idle = Some(value),
                    "SCX_KICK_PREEMPT" => preempt = Some(value),
                    "SCX_KICK_WAIT" => wait = Some(value),
                    _ => {}
                }
            }
        }

        (idle.unwrap_or(1), preempt.unwrap_or(2), wait.unwrap_or(4))
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
            if Self::helper_pointer_arg_allows_const_zero(helper_id, rule.arg_idx)
                && matches!(
                    self.value_range_for(arg, value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
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
                                AddressSpace::Kernel
                                | AddressSpace::User
                                | AddressSpace::Packet => {}
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

        if matches!(helper, BpfHelper::Redirect)
            && self
                .probe_ctx
                .as_ref()
                .is_some_and(|ctx| ctx.probe_type == EbpfProgramType::Xdp)
        {
            let flags_ok = args.get(1).is_some_and(|value| {
                matches!(
                    self.value_range_for(value, value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
            });
            if !flags_ok {
                errors.push(TypeError::new(
                    "helper 'bpf_redirect' requires arg1 = 0 in xdp programs",
                ));
            }
        }

        if matches!(helper, BpfHelper::RedirectPeer) {
            let flags_ok = args.get(1).is_some_and(|value| {
                matches!(
                    self.value_range_for(value, value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
            });
            if !flags_ok {
                errors.push(TypeError::new(
                    "helper 'bpf_redirect_peer' requires arg1 = 0",
                ));
            }
        }
    }

    pub(super) fn validate_kfunc_semantics(
        &self,
        kfunc: &str,
        args: &[VReg],
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
        stack_bounds: &HashMap<VReg, StackBounds>,
        errors: &mut Vec<TypeError>,
    ) {
        let semantics = kfunc_semantics(kfunc);
        let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
        for (arg_idx, vreg) in args.iter().enumerate() {
            if Self::kfunc_scalar_arg_requires_positive(kfunc, arg_idx) {
                positive_size_bounds[arg_idx] = self.kfunc_positive_size_upper_bound(
                    kfunc,
                    arg_idx,
                    *vreg,
                    value_ranges,
                    errors,
                );
            }
        }

        for rule in semantics.ptr_arg_rules {
            let Some(vreg) = args.get(rule.arg_idx) else {
                continue;
            };
            if Self::kfunc_pointer_arg_allows_const_zero(kfunc, rule.arg_idx)
                && !matches!(self.mir_type_for_vreg(*vreg, types), MirType::Ptr { .. })
                && matches!(
                    self.value_range_for(&MirValue::VReg(*vreg), value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
            {
                continue;
            }
            let size_from_arg = rule.size_from_arg;
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => positive_size_bounds[size_arg],
                (None, None) => None,
            };
            match self.mir_type_for_vreg(*vreg, types) {
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
                    if address_space == AddressSpace::Stack
                        && Self::kfunc_pointer_arg_requires_stack_slot_base(kfunc, rule.arg_idx)
                    {
                        let is_base = stack_bounds
                            .get(vreg)
                            .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
                        if !is_base {
                            errors.push(TypeError::new(format!(
                                "kfunc '{}' arg{} expects stack slot base pointer",
                                kfunc, rule.arg_idx
                            )));
                        }
                    }
                    if let Some(size_arg) = size_from_arg
                        && access_size.is_none()
                        && matches!(address_space, AddressSpace::Stack | AddressSpace::Map)
                    {
                        errors.push(TypeError::new(format!(
                            "kfunc '{}' arg{} must have bounded upper range for {}",
                            kfunc, size_arg, rule.op
                        )));
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
                            AddressSpace::Kernel | AddressSpace::User | AddressSpace::Packet => {}
                        }
                    }
                }
                other => errors.push(TypeError::new(format!(
                    "kfunc '{}' arg{} expects pointer value, got {:?}",
                    kfunc, rule.arg_idx, other
                ))),
            }
        }

        for (ptr_arg_idx, ptr_vreg) in args.iter().enumerate() {
            if semantics
                .ptr_arg_rules
                .iter()
                .any(|rule| rule.arg_idx == ptr_arg_idx)
            {
                continue;
            }
            let access_size = if let Some(size_arg_idx) =
                Self::kfunc_pointer_arg_size_from_scalar(kfunc, ptr_arg_idx)
            {
                let access_size = positive_size_bounds.get(size_arg_idx).copied().flatten();
                if access_size.is_none()
                    && matches!(
                        self.mir_type_for_vreg(*ptr_vreg, types),
                        MirType::Ptr {
                            address_space: AddressSpace::Stack | AddressSpace::Map,
                            ..
                        }
                    )
                {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' arg{} must have bounded upper range for arg{} pointer access",
                        kfunc, size_arg_idx, ptr_arg_idx
                    )));
                }
                access_size
            } else {
                Self::kfunc_pointer_arg_fixed_size(kfunc, ptr_arg_idx)
            };
            let access_size =
                access_size.or_else(|| Self::kfunc_pointer_arg_min_access_size(kfunc, ptr_arg_idx));
            let Some(access_size) = access_size else {
                continue;
            };

            match self.mir_type_for_vreg(*ptr_vreg, types) {
                MirType::Ptr {
                    address_space,
                    pointee,
                } => match address_space {
                    AddressSpace::Stack => {
                        if Self::kfunc_pointer_arg_requires_stack_slot_base(kfunc, ptr_arg_idx) {
                            let is_base = stack_bounds
                                .get(ptr_vreg)
                                .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
                            if !is_base {
                                errors.push(TypeError::new(format!(
                                    "kfunc '{}' arg{} expects stack slot base pointer",
                                    kfunc, ptr_arg_idx
                                )));
                            }
                        }
                        if let Some(bounds) = stack_bounds.get(ptr_vreg) {
                            let end = bounds.max + access_size as i64 - 1;
                            if bounds.min < 0 || end > bounds.limit {
                                errors.push(TypeError::new(format!(
                                    "kfunc '{}' arg{} pointer access requires {} bytes, stack pointer range [{}..{}] exceeds [0..{}]",
                                    kfunc, ptr_arg_idx, access_size, bounds.min, bounds.max, bounds.limit
                                )));
                            }
                        }
                    }
                    AddressSpace::Map => {
                        let pointee_size = pointee.size();
                        if access_size > pointee_size {
                            errors.push(TypeError::new(format!(
                                "kfunc '{}' arg{} pointer access requires {} bytes, map value has {} bytes",
                                kfunc, ptr_arg_idx, access_size, pointee_size
                            )));
                        }
                    }
                    AddressSpace::Kernel | AddressSpace::User | AddressSpace::Packet => {}
                },
                _ => {}
            }
        }

        if kfunc == "bpf_dynptr_clone"
            && let (Some(src), Some(dst)) = (args.first(), args.get(1))
        {
            let src_slot = stack_bounds
                .get(src)
                .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                .map(|bounds| bounds.slot);
            let dst_slot = stack_bounds
                .get(dst)
                .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                .map(|bounds| bounds.slot);
            if src_slot.is_some() && src_slot == dst_slot {
                errors.push(TypeError::new(
                    "kfunc 'bpf_dynptr_clone' arg1 must reference distinct stack slot from arg0",
                ));
            }
        }

        for copy in Self::kfunc_unknown_dynptr_copy(kfunc) {
            if let (Some(src), Some(dst)) = (args.get(copy.src_arg_idx), args.get(copy.dst_arg_idx))
            {
                let src_slot = stack_bounds
                    .get(src)
                    .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                    .map(|bounds| bounds.slot);
                let dst_slot = stack_bounds
                    .get(dst)
                    .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                    .map(|bounds| bounds.slot);
                if src_slot.is_some() && src_slot == dst_slot {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' arg{} must reference distinct stack slot from arg{}",
                        kfunc, copy.dst_arg_idx, copy.src_arg_idx
                    )));
                }
            }
        }

        for copy in Self::kfunc_unknown_stack_object_copy(kfunc) {
            if let (Some(src), Some(dst)) = (args.get(copy.src_arg_idx), args.get(copy.dst_arg_idx))
            {
                let src_slot = stack_bounds
                    .get(src)
                    .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                    .map(|bounds| bounds.slot);
                let dst_slot = stack_bounds
                    .get(dst)
                    .filter(|bounds| bounds.min == 0 && bounds.max == 0)
                    .map(|bounds| bounds.slot);
                if src_slot.is_some() && src_slot == dst_slot {
                    errors.push(TypeError::new(format!(
                        "kfunc '{}' arg{} must reference distinct {} stack object slot from arg{}",
                        kfunc, copy.dst_arg_idx, copy.type_name, copy.src_arg_idx
                    )));
                }
            }
        }

        for (idx, arg) in args.iter().enumerate() {
            if !Self::kfunc_scalar_arg_requires_known_const(kfunc, idx) {
                continue;
            }
            let is_const = matches!(
                self.value_range_for(&MirValue::VReg(*arg), value_ranges),
                ValueRange::Known { min, max } if min == max
            );
            if !is_const {
                errors.push(TypeError::new(format!(
                    "kfunc '{}' arg{} must be known constant",
                    kfunc, idx
                )));
            }
        }

        if kfunc == "scx_bpf_kick_cpu"
            && let Some(flags) = args
                .get(1)
                .and_then(|vreg| self.known_const_vreg(*vreg, value_ranges))
        {
            let (kick_idle, kick_preempt, kick_wait) = Self::sched_ext_kick_flag_bits();
            let uses_idle = flags & kick_idle != 0;
            let uses_preempt = flags & kick_preempt != 0;
            let uses_wait = flags & kick_wait != 0;
            if uses_idle && (uses_preempt || uses_wait) {
                errors.push(TypeError::new(
                    "kfunc 'scx_bpf_kick_cpu' arg1 cannot combine SCX_KICK_IDLE with SCX_KICK_PREEMPT or SCX_KICK_WAIT",
                ));
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
}
