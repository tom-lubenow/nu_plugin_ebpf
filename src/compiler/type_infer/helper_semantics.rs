use super::*;
use crate::compiler::elf::GetSocketCookieArgPolicy;
use crate::compiler::instruction::{
    KfuncRefKind, helper_pointer_arg_ref_kind, scalar_range_contains_only_allowed_values,
    scalar_range_contains_only_bitmask,
};
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

    pub(super) fn helper_pointer_arg_allows_const_zero(
        &self,
        helper_id: u32,
        arg_idx: usize,
    ) -> bool {
        BpfHelper::from_u32(helper_id).is_some_and(|helper| {
            helper.pointer_arg_allows_static_const_zero(arg_idx)
                || self.helper_pointer_arg_allows_contextual_maybe_null(helper, arg_idx)
        })
    }

    fn helper_pointer_arg_allows_contextual_maybe_null(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
    ) -> bool {
        if !matches!(helper, BpfHelper::GetSocketCookie) || arg_idx != 0 {
            return false;
        }
        self.probe_ctx
            .as_ref()
            .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
            .is_some_and(GetSocketCookieArgPolicy::allows_maybe_null)
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
            AddressSpace::Packet | AddressSpace::Context => false,
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

    pub(super) fn helper_nonnegative_size_upper_bound(
        &self,
        helper_id: u32,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) -> Option<usize> {
        match self.value_range_for(value, value_ranges) {
            ValueRange::Known { min, max } => {
                if min < 0 || max < 0 {
                    errors.push(TypeError::new(format!(
                        "helper {} arg{} must be >= 0",
                        helper_id, arg_idx
                    )));
                    return None;
                }
                usize::try_from(max).ok()
            }
            _ => None,
        }
    }

    fn validate_helper_scalar_multiple_of(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some((multiple, message)) = helper.scalar_arg_multiple_of_requirement(arg_idx) else {
            return;
        };
        if let ValueRange::Known { min, max } = self.value_range_for(value, value_ranges)
            && min == max
            && min.rem_euclid(multiple) != 0
        {
            errors.push(TypeError::new(message));
        }
    }

    fn validate_helper_scalar_range(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some((min_required, max_required, message)) =
            helper.scalar_arg_range_requirement(arg_idx)
        else {
            return;
        };
        if let ValueRange::Known { min, max } = self.value_range_for(value, value_ranges)
            && (min < min_required || max > max_required)
        {
            errors.push(TypeError::new(message));
        }
    }

    fn validate_helper_scalar_allowed_values(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some((allowed_values, message)) = helper.scalar_arg_allowed_values_requirement(arg_idx)
        else {
            return;
        };
        if let ValueRange::Known { min, max } = self.value_range_for(value, value_ranges)
            && !scalar_range_contains_only_allowed_values(min, max, allowed_values)
        {
            errors.push(TypeError::new(message));
        }
    }

    fn validate_helper_scalar_bitmask(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        value_ranges: &HashMap<VReg, ValueRange>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some((mask, message)) = helper.scalar_arg_bitmask_requirement(arg_idx) else {
            return;
        };
        if let ValueRange::Known { min, max } = self.value_range_for(value, value_ranges)
            && !scalar_range_contains_only_bitmask(min, max, mask)
        {
            errors.push(TypeError::new(message));
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
        direct_ctx_field_sources: &HashMap<VReg, CtxField>,
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
        for (arg_idx, value) in args.iter().enumerate().take(5) {
            self.validate_helper_scalar_multiple_of(helper, arg_idx, value, value_ranges, errors);
            self.validate_helper_scalar_range(helper, arg_idx, value, value_ranges, errors);
            self.validate_helper_scalar_allowed_values(
                helper,
                arg_idx,
                value,
                value_ranges,
                errors,
            );
            self.validate_helper_scalar_bitmask(helper, arg_idx, value, value_ranges, errors);
        }

        for rule in semantics.ptr_arg_rules {
            let Some(arg) = args.get(rule.arg_idx) else {
                continue;
            };
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => positive_size_bounds[size_arg].or_else(|| {
                    helper
                        .zero_size_pointer_arg_size_arg(rule.arg_idx)
                        .filter(|paired_size_arg| *paired_size_arg == size_arg)
                        .and_then(|_| {
                            args.get(size_arg).and_then(|value| {
                                self.helper_nonnegative_size_upper_bound(
                                    helper_id,
                                    size_arg,
                                    value,
                                    value_ranges,
                                    errors,
                                )
                            })
                        })
                        .or_else(|| {
                            helper
                                .scalar_arg_nonnegative_requirement(size_arg)
                                .and_then(|_| {
                                    args.get(size_arg).and_then(|value| {
                                        self.helper_nonnegative_size_upper_bound(
                                            helper_id,
                                            size_arg,
                                            value,
                                            value_ranges,
                                            errors,
                                        )
                                    })
                                })
                        })
                }),
                (None, None) => None,
            };
            if self.helper_pointer_arg_allows_const_zero(helper_id, rule.arg_idx)
                && matches!(
                    self.value_range_for(arg, value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
            {
                if let Some(size_arg) = helper.zero_size_pointer_arg_size_arg(rule.arg_idx)
                    && !args.get(size_arg).is_some_and(|value| {
                        matches!(
                            self.value_range_for(value, value_ranges),
                            ValueRange::Known { min: 0, max: 0 }
                        )
                    })
                {
                    errors.push(TypeError::new(format!(
                        "helper {} arg{} requires arg{} = 0 when arg{} is null",
                        helper_id, rule.arg_idx, size_arg, rule.arg_idx
                    )));
                }
                continue;
            }
            match arg {
                MirValue::VReg(vreg) => match self.mir_type_for_vreg(*vreg, types) {
                    MirType::MapRef { .. }
                        if BpfHelper::from_u32(helper_id).is_some_and(|helper| {
                            helper.supports_local_helper_map_fd(rule.arg_idx)
                        }) =>
                    {
                        continue;
                    }
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
                                | AddressSpace::Packet
                                | AddressSpace::Context => {}
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

        let arg_is_known_zero = |arg_idx| {
            args.get(arg_idx).is_some_and(|value| {
                matches!(
                    self.value_range_for(value, value_ranges),
                    ValueRange::Known { min: 0, max: 0 }
                )
            })
        };
        let arg_is_known_const = |arg_idx, expected| {
            args.get(arg_idx).is_some_and(|value| {
                matches!(
                    self.value_range_for(value, value_ranges),
                    ValueRange::Known { min, max } if min == expected && max == expected
                )
            })
        };

        if let Some((arg_idx, message)) = self
            .probe_ctx
            .as_ref()
            .and_then(|ctx| ctx.helper_zero_arg_requirement(helper))
            && !arg_is_known_zero(arg_idx)
        {
            errors.push(TypeError::new(message));
        }

        if let Some((arg_idx, message)) = helper.zero_scalar_arg_requirement()
            && !arg_is_known_zero(arg_idx)
        {
            errors.push(TypeError::new(message));
        }

        if let Some((arg_idx, expected, message)) = helper.scalar_arg_const_requirement()
            && !arg_is_known_const(arg_idx, expected)
        {
            errors.push(TypeError::new(message));
        }

        for (arg_idx, arg) in args.iter().enumerate() {
            if let Some(message) = helper.scalar_arg_known_const_requirement(arg_idx) {
                let is_const = matches!(
                    self.value_range_for(arg, value_ranges),
                    ValueRange::Known { min, max } if min == max
                );
                if !is_const {
                    errors.push(TypeError::new(message));
                }
            }
        }

        if let Some((arg_idx, trigger_arg_idx, message)) =
            helper.zero_scalar_arg_requirement_when_arg_zero()
            && arg_is_known_zero(trigger_arg_idx)
            && !arg_is_known_zero(arg_idx)
        {
            errors.push(TypeError::new(message));
        }

        for (arg_idx, arg) in args.iter().enumerate() {
            if helper.dynptr_arg_role(arg_idx).is_none() {
                continue;
            }
            match arg {
                MirValue::VReg(vreg) => {
                    if matches!(
                        self.mir_type_for_vreg(*vreg, types),
                        MirType::Ptr {
                            address_space: AddressSpace::Stack,
                            ..
                        }
                    ) {
                        let is_base = stack_bounds
                            .get(vreg)
                            .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
                        if !is_base {
                            errors.push(TypeError::new(format!(
                                "helper '{}' arg{} expects stack slot base pointer",
                                helper.name(),
                                arg_idx
                            )));
                        }
                    }
                }
                MirValue::StackSlot(_) | MirValue::Const(_) => {}
            }
        }

        if matches!(helper, BpfHelper::GetSocketCookie) {
            self.validate_get_socket_cookie_arg_shape(
                args,
                types,
                value_ranges,
                direct_ctx_field_sources,
                errors,
            );
        }
        for arg_idx in 0..args.len() {
            let Some((predicate, expected)) = helper_expected_named_arg_shape(helper, arg_idx)
            else {
                continue;
            };
            self.validate_named_helper_arg_shape(
                helper, args, arg_idx, types, predicate, expected, errors,
            );
        }
    }

    fn validate_get_socket_cookie_arg_shape(
        &self,
        args: &[MirValue],
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
        direct_ctx_field_sources: &HashMap<VReg, CtxField>,
        errors: &mut Vec<TypeError>,
    ) {
        let Some(program_type) = self.probe_ctx.as_ref().map(|ctx| ctx.program_type()) else {
            return;
        };
        let Some(policy) = self
            .probe_ctx
            .as_ref()
            .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
        else {
            return;
        };
        let Some(arg) = args.first() else {
            return;
        };
        if policy.allows_maybe_null()
            && matches!(
                self.value_range_for(arg, value_ranges),
                ValueRange::Known { min: 0, max: 0 }
            )
        {
            return;
        }
        let matches_policy = match policy {
            GetSocketCookieArgPolicy::Context => {
                self.helper_arg_is_raw_context_pointer(arg, direct_ctx_field_sources)
            }
            GetSocketCookieArgPolicy::ContextOrSocket => {
                self.helper_arg_is_raw_context_pointer(arg, direct_ctx_field_sources)
                    || self.helper_arg_is_socket_cookie_socket_pointer(arg, types)
            }
            GetSocketCookieArgPolicy::Socket => {
                self.helper_arg_is_socket_cookie_socket_pointer(arg, types)
            }
        };
        if !matches_policy {
            errors.push(TypeError::new(
                policy.error_message(BpfHelper::GetSocketCookie, program_type),
            ));
        }
    }

    fn helper_arg_is_raw_context_pointer(
        &self,
        arg: &MirValue,
        direct_ctx_field_sources: &HashMap<VReg, CtxField>,
    ) -> bool {
        match arg {
            MirValue::VReg(vreg) => direct_ctx_field_sources.get(vreg).is_some_and(|field| {
                ProbeContext::resolve_ctx_field_is_raw_context_pointer(
                    self.probe_ctx.as_ref(),
                    field,
                )
            }),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        }
    }

    fn helper_arg_is_socket_cookie_socket_pointer(
        &self,
        arg: &MirValue,
        types: &HashMap<VReg, MirType>,
    ) -> bool {
        match arg {
            MirValue::VReg(vreg) => self
                .mir_type_for_vreg(*vreg, types)
                .is_socket_cookie_socket_ptr(),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        }
    }

    fn validate_named_helper_arg_shape(
        &self,
        helper: BpfHelper,
        args: &[MirValue],
        arg_idx: usize,
        types: &HashMap<VReg, MirType>,
        predicate: fn(&MirType) -> bool,
        expected: &str,
        errors: &mut Vec<TypeError>,
    ) {
        let Some(arg) = args.get(arg_idx) else {
            return;
        };
        if self.helper_pointer_arg_allows_const_zero(helper as u32, arg_idx)
            && Self::is_const_zero(arg)
        {
            return;
        }
        let matches = match arg {
            MirValue::VReg(vreg) => predicate(&self.mir_type_for_vreg(*vreg, types)),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        };
        if !matches {
            errors.push(TypeError::new(format!(
                "helper '{}' arg{} expects {}",
                helper.name(),
                arg_idx,
                expected
            )));
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
                            AddressSpace::Kernel
                            | AddressSpace::User
                            | AddressSpace::Packet
                            | AddressSpace::Context => {}
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
                    AddressSpace::Kernel
                    | AddressSpace::User
                    | AddressSpace::Packet
                    | AddressSpace::Context => {}
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

fn helper_expected_named_arg_shape(
    helper: BpfHelper,
    arg_idx: usize,
) -> Option<(fn(&MirType) -> bool, &'static str)> {
    if matches!(
        (helper, arg_idx),
        (
            BpfHelper::TimerInit
                | BpfHelper::TimerSetCallback
                | BpfHelper::TimerStart
                | BpfHelper::TimerCancel,
            0
        )
    ) {
        return Some((
            MirType::is_bpf_timer_map_ptr,
            "map-backed bpf_timer pointer",
        ));
    }
    if matches!(
        (helper, arg_idx),
        (BpfHelper::SpinLock | BpfHelper::SpinUnlock, 0)
    ) {
        return Some((
            MirType::is_bpf_spin_lock_map_ptr,
            "map-backed bpf_spin_lock pointer",
        ));
    }
    match helper_pointer_arg_ref_kind(helper, arg_idx)? {
        KfuncRefKind::Socket => Some((MirType::is_socket_ptr, "socket pointer")),
        KfuncRefKind::Task => Some((MirType::is_task_struct_ptr, "task pointer")),
        KfuncRefKind::File => Some((MirType::is_file_ptr, "file pointer")),
        KfuncRefKind::Inode => Some((MirType::is_inode_ptr, "inode pointer")),
        KfuncRefKind::Cgroup => Some((MirType::is_cgroup_ptr, "cgroup pointer")),
        _ => None,
    }
}
