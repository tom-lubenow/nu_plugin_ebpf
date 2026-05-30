use super::*;
use crate::compiler::{ProbeContext, ProgramTypeInfo};

fn ctx_field_is_raw_context_pointer(
    field: &CtxField,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
) -> bool {
    probe_ctx.map_or_else(
        || {
            program
                .is_some_and(|program| program.program_type.ctx_field_is_raw_context_pointer(field))
                || (program.is_none() && matches!(field, CtxField::Context))
        },
        |ctx| ctx.ctx_field_is_raw_context_pointer(field),
    )
}

fn kfunc_arg_accepts_raw_skb_context_source(
    kfunc: &str,
    arg_idx: usize,
    arg: VReg,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
) -> bool {
    let Some(field) = state.ctx_field_source(arg) else {
        return false;
    };
    if !ctx_field_is_raw_context_pointer(field, program, probe_ctx) {
        return false;
    }
    probe_ctx
        .map(|ctx| ctx.program_type())
        .or_else(|| program.map(|program| program.program_type))
        .map_or(true, |program_type| {
            program_type.kfunc_arg_accepts_raw_skb_context(kfunc, arg_idx)
        })
}

pub(in crate::compiler::verifier_types) fn check_kfunc_arg(
    kfunc: &str,
    arg_idx: usize,
    arg: VReg,
    expected: KfuncArgKind,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let ty = state.get(arg);
    match expected {
        KfuncArgKind::Scalar => {
            if !matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} expects scalar, got {:?}",
                    kfunc, arg_idx, ty
                )));
            }
        }
        KfuncArgKind::Subprogram => {
            let Some(arg_ty @ MirType::Subprogram { .. }) = types.get(&arg) else {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} expects callback subprogram",
                    kfunc, arg_idx
                )));
                return;
            };
            if let Some(message) =
                KfuncSignature::callback_subprogram_type_error(kfunc, arg_idx, arg_ty)
            {
                errors.push(VerifierTypeError::new(message));
            }
        }
        KfuncArgKind::Pointer => {
            if state.is_released_kfunc_ref(arg) {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} reference already released",
                    kfunc, arg_idx
                )));
                return;
            }
            if kfunc_pointer_arg_allows_const_zero(kfunc, arg_idx)
                && matches!(ty, VerifierType::Scalar | VerifierType::Bool)
                && matches!(
                    value_range(&MirValue::VReg(arg), state),
                    ValueRange::Known { min: 0, max: 0 }
                )
            {
                return;
            }
            if kfunc_local_map_ref_arg(kfunc, arg_idx, arg, types) {
                return;
            }
            match ty {
                VerifierType::Ptr {
                    space,
                    bounds,
                    nullability,
                    kfunc_ref,
                    ..
                } => {
                    let requires_stack = kfunc_pointer_arg_requires_stack(kfunc, arg_idx);
                    if requires_stack {
                        if !bounds.is_some_and(|ptr_bounds| {
                            matches!(ptr_bounds.origin(), PtrOrigin::Stack(_))
                        }) {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects stack slot pointer",
                                kfunc, arg_idx
                            )));
                        }
                        if bounds.is_some_and(|ptr_bounds| {
                            matches!(ptr_bounds.origin(), PtrOrigin::Stack(_))
                                && (ptr_bounds.min() != 0 || ptr_bounds.max() != 0)
                        }) {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects stack slot base pointer",
                                kfunc, arg_idx
                            )));
                        }
                        if let Some(source) = state.ctx_field_source(arg) {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects stack pointer from stack slot, got context field {:?}",
                                kfunc, arg_idx, source
                            )));
                        }
                        if space != AddressSpace::Stack {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects stack pointer, got {:?}",
                                kfunc, arg_idx, space
                            )));
                        }
                    }
                    if !requires_stack
                        && space == AddressSpace::Stack
                        && kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx)
                    {
                        let is_base = bounds.is_some_and(|ptr_bounds| {
                            matches!(ptr_bounds.origin(), PtrOrigin::Stack(_))
                                && ptr_bounds.min() == 0
                                && ptr_bounds.max() == 0
                        });
                        if !is_base {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects stack slot base pointer",
                                kfunc, arg_idx
                            )));
                        }
                    }
                    if kfunc_pointer_arg_requires_kernel(kfunc, arg_idx)
                        && space != AddressSpace::Kernel
                    {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects kernel pointer, got {:?}",
                            kfunc, arg_idx, space
                        )));
                    }
                    if kfunc_pointer_arg_requires_user(kfunc, arg_idx)
                        && space != AddressSpace::User
                    {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects user pointer, got {:?}",
                            kfunc, arg_idx, space
                        )));
                    }
                    if kfunc_pointer_arg_requires_stack_or_map(kfunc, arg_idx)
                        && !matches!(space, AddressSpace::Stack | AddressSpace::Map)
                    {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects stack or map pointer, got {:?}",
                            kfunc, arg_idx, space
                        )));
                    }
                    if let Some(MirType::Ptr {
                        pointee,
                        address_space,
                    }) = types.get(&arg)
                    {
                        if let Some(expected) = kfunc_arg_pointee_mismatch(kfunc, arg_idx, pointee)
                        {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects {} pointer, got {:?}",
                                kfunc, arg_idx, expected, pointee
                            )));
                        } else if kfunc_arg_requires_skb_context_or_pointer(kfunc, arg_idx)
                            && !kfunc_arg_accepts_raw_skb_context_source(
                                kfunc, arg_idx, arg, state, program, probe_ctx,
                            )
                            && !(*address_space == AddressSpace::Kernel
                                && matches!(
                                    pointee.as_ref(),
                                    MirType::Struct { name: Some(name), .. }
                                        if kfunc_arg_accepts_skb_pointee_name(name)
                                ))
                        {
                            errors.push(VerifierTypeError::new(format!(
                                "kfunc '{}' arg{} expects __sk_buff context or sk_buff pointer",
                                kfunc, arg_idx
                            )));
                        }
                    }
                    if let Some(expected_kind) = kfunc_pointer_arg_expected_ref_kind(kfunc, arg_idx)
                    {
                        if let Some(ref_id) = kfunc_ref {
                            if !state.is_live_kfunc_ref(ref_id) {
                                errors.push(VerifierTypeError::new(format!(
                                    "kfunc '{}' arg{} reference already released",
                                    kfunc, arg_idx
                                )));
                                return;
                            }
                            if !matches!(nullability, Nullability::NonNull) {
                                errors.push(VerifierTypeError::new(format!(
                                    "kfunc '{}' arg{} may dereference null pointer v{} (add a null check)",
                                    kfunc, arg_idx, arg.0
                                )));
                            }
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind != Some(expected_kind) {
                                let expected = expected_kind.label();
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                errors.push(VerifierTypeError::new(format!(
                                    "kfunc '{}' arg{} expects {} reference, got {} reference",
                                    kfunc, arg_idx, expected, actual
                                )));
                            }
                        }
                    }
                }
                _ => {
                    if kfunc_pointer_arg_allows_const_zero(kfunc, arg_idx) {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects null (0) or pointer, got {:?}",
                            kfunc, arg_idx, ty
                        )));
                    } else {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects pointer, got {:?}",
                            kfunc, arg_idx, ty
                        )));
                    }
                }
            }
        }
    }
}

pub(in crate::compiler::verifier_types) fn kfunc_positive_size_upper_bound(
    kfunc: &str,
    arg_idx: usize,
    value: VReg,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<usize> {
    match value_range(&MirValue::VReg(value), state) {
        ValueRange::Known { min, max } => {
            if max <= 0 || min <= 0 {
                errors.push(VerifierTypeError::new(format!(
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

pub(in crate::compiler::verifier_types) fn kfunc_allowed_spaces(
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
) -> &'static [AddressSpace] {
    match (allow_stack, allow_map, allow_kernel, allow_user) {
        (true, true, false, false) => &[AddressSpace::Stack, AddressSpace::Map],
        (true, true, true, false) => {
            &[AddressSpace::Stack, AddressSpace::Map, AddressSpace::Kernel]
        }
        (false, true, true, false) => &[AddressSpace::Map, AddressSpace::Kernel],
        (false, false, true, false) => &[AddressSpace::Kernel],
        (false, false, false, true) => &[AddressSpace::User],
        (true, false, false, false) => &[AddressSpace::Stack],
        (false, true, false, false) => &[AddressSpace::Map],
        (false, false, false, false) => &[],
        _ => &[
            AddressSpace::Stack,
            AddressSpace::Map,
            AddressSpace::Kernel,
            AddressSpace::User,
        ],
    }
}

pub(in crate::compiler::verifier_types) fn check_kfunc_ptr_arg_value(
    kfunc: &str,
    arg_idx: usize,
    arg: VReg,
    op: &str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    access_size: Option<usize>,
    require_stack_slot_base: bool,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if kfunc_pointer_arg_allows_const_zero(kfunc, arg_idx)
        && matches!(state.get(arg), VerifierType::Scalar | VerifierType::Bool)
        && matches!(
            value_range(&MirValue::VReg(arg), state),
            ValueRange::Known { min: 0, max: 0 }
        )
    {
        return;
    }
    let allowed = kfunc_allowed_spaces(allow_stack, allow_map, allow_kernel, allow_user);
    if access_size.is_none() {
        match state.get(arg) {
            VerifierType::Ptr {
                nullability: Nullability::Null,
                ..
            } => {
                errors.push(VerifierTypeError::new(format!(
                    "{op} uses null pointer v{}",
                    arg.0
                )));
            }
            VerifierType::Ptr {
                nullability: Nullability::MaybeNull,
                ..
            } => {
                errors.push(VerifierTypeError::new(format!(
                    "{op} may dereference null pointer v{} (add a null check)",
                    arg.0
                )));
            }
            VerifierType::Ptr { space, .. } => {
                if !allowed.contains(&space) {
                    errors.push(VerifierTypeError::new(format!(
                        "{op} expects pointer in {:?}, got {:?}",
                        allowed, space
                    )));
                }
            }
            VerifierType::Uninit => {
                errors.push(VerifierTypeError::new(format!(
                    "{op} uses uninitialized pointer v{}",
                    arg.0
                )));
            }
            other => {
                errors.push(VerifierTypeError::new(format!(
                    "{op} expected pointer, got {:?}",
                    other
                )));
            }
        }
        return;
    }
    let Some(VerifierType::Ptr { space, bounds, .. }) =
        require_ptr_with_space(arg, op, allowed, state, errors)
    else {
        return;
    };
    if require_stack_slot_base && space == AddressSpace::Stack {
        let is_base = bounds.is_some_and(|ptr_bounds| {
            matches!(ptr_bounds.origin(), PtrOrigin::Stack(_))
                && ptr_bounds.min() == 0
                && ptr_bounds.max() == 0
        });
        if !is_base {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} expects stack slot base pointer",
                kfunc, arg_idx
            )));
        }
    }
    if let Some(size) = access_size {
        check_ptr_bounds(op, space, bounds, 0, size, errors);
    }
}

pub(in crate::compiler::verifier_types) fn check_kfunc_semantics(
    kfunc: &str,
    args: &[VReg],
    _types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if let Some(root_arg_idx) = kfunc_bpf_spin_lock_protected_graph_root_arg(kfunc) {
        let protected = args
            .get(root_arg_idx)
            .is_some_and(|arg| state.has_bpf_spin_lock_for_map_root(*arg));
        if !protected {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' requires bpf_spin_lock from the same map value to be held for graph root",
                kfunc
            )));
        }
    }
    validate_kfunc_map_fd_matches_map_value(kfunc, args, state, errors);

    let semantics = kfunc_semantics(kfunc);
    let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
    for (arg_idx, value) in args.iter().enumerate() {
        if kfunc_scalar_arg_requires_positive(kfunc, arg_idx) {
            positive_size_bounds[arg_idx] =
                kfunc_positive_size_upper_bound(kfunc, arg_idx, *value, state, errors);
        }
    }

    for rule in semantics.ptr_arg_rules {
        let Some(arg) = args.get(rule.arg_idx) else {
            continue;
        };
        let size_from_arg = rule.size_from_arg;
        let access_size = match (rule.fixed_size, rule.size_from_arg) {
            (Some(size), _) => Some(size),
            (None, Some(size_arg)) => positive_size_bounds[size_arg],
            (None, None) => None,
        };
        if let Some(size_arg) = size_from_arg
            && access_size.is_none()
            && matches!(
                state.get(*arg),
                VerifierType::Ptr {
                    space: AddressSpace::Stack | AddressSpace::Map,
                    ..
                }
            )
        {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} must have bounded upper range for {}",
                kfunc, size_arg, rule.op
            )));
        }
        check_kfunc_ptr_arg_value(
            kfunc,
            rule.arg_idx,
            *arg,
            rule.op,
            rule.allowed.allow_stack,
            rule.allowed.allow_map,
            rule.allowed.allow_kernel,
            rule.allowed.allow_user,
            access_size,
            kfunc_pointer_arg_requires_stack_slot_base(kfunc, rule.arg_idx),
            state,
            errors,
        );
    }

    for (idx, arg) in args.iter().enumerate() {
        let Some(expected) = kfunc_pointer_arg_requires_raw_context(kfunc, idx) else {
            continue;
        };
        if state.ctx_field_source(*arg) != Some(&CtxField::Context) {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} expects {} pointer",
                kfunc, idx, expected
            )));
        }
    }

    for (ptr_arg_idx, arg) in args.iter().enumerate() {
        if semantics
            .ptr_arg_rules
            .iter()
            .any(|rule| rule.arg_idx == ptr_arg_idx)
        {
            continue;
        }
        let access_size =
            if let Some(size_arg_idx) = kfunc_pointer_arg_size_from_scalar(kfunc, ptr_arg_idx) {
                let access_size = positive_size_bounds.get(size_arg_idx).copied().flatten();
                if access_size.is_none()
                    && matches!(
                        state.get(*arg),
                        VerifierType::Ptr {
                            space: AddressSpace::Stack | AddressSpace::Map,
                            ..
                        }
                    )
                {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} must have bounded upper range for arg{} pointer access",
                        kfunc, size_arg_idx, ptr_arg_idx
                    )));
                }
                access_size
            } else {
                kfunc_pointer_arg_fixed_size(kfunc, ptr_arg_idx)
            };
        let access_size =
            access_size.or_else(|| kfunc_pointer_arg_min_access_size(kfunc, ptr_arg_idx));
        let Some(access_size) = access_size else {
            continue;
        };
        if !matches!(state.get(*arg), VerifierType::Ptr { .. }) {
            continue;
        }
        let op = format!("kfunc '{}' arg{} pointer access", kfunc, ptr_arg_idx);
        check_kfunc_ptr_arg_value(
            kfunc,
            ptr_arg_idx,
            *arg,
            &op,
            true,
            true,
            true,
            true,
            Some(access_size),
            kfunc_pointer_arg_requires_stack_slot_base(kfunc, ptr_arg_idx),
            state,
            errors,
        );
    }

    for (idx, arg) in args.iter().enumerate() {
        if !kfunc_scalar_arg_requires_known_const(kfunc, idx) {
            continue;
        }
        let is_const = matches!(
            value_range(&MirValue::VReg(*arg), state),
            ValueRange::Known { min, max } if min == max
        );
        if !is_const {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} must be known constant",
                kfunc, idx
            )));
        }
    }

    for (idx, arg) in args.iter().enumerate() {
        if !kfunc_scalar_arg_requires_zero(kfunc, idx) {
            continue;
        }
        let is_zero = matches!(
            value_range(&MirValue::VReg(*arg), state),
            ValueRange::Known { min: 0, max: 0 }
        );
        if !is_zero {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} must be known zero",
                kfunc, idx
            )));
        }
    }
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_kernel(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_raw_context(
    kfunc: &str,
    arg_idx: usize,
) -> Option<&'static str> {
    kfunc_pointer_arg_requires_raw_context_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_stack(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_stack_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_user(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_user_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_allows_const_zero(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_allows_const_zero_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_stack_slot_base(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_stack_slot_base_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_stack_or_map(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_stack_or_map_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_size_from_scalar(
    kfunc: &str,
    arg_idx: usize,
) -> Option<usize> {
    kfunc_pointer_arg_size_from_scalar_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_min_access_size(
    kfunc: &str,
    arg_idx: usize,
) -> Option<usize> {
    kfunc_pointer_arg_min_access_size_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_fixed_size(
    kfunc: &str,
    arg_idx: usize,
) -> Option<usize> {
    kfunc_pointer_arg_fixed_size_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_scalar_arg_requires_known_const(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_scalar_arg_requires_known_const_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_scalar_arg_requires_positive(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_scalar_arg_requires_positive_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_scalar_arg_requires_zero(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_scalar_arg_requires_zero_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_supports_local_map_fd(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_supports_local_map_fd_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_expected_ref_kind(
    kfunc: &str,
    arg_idx: usize,
) -> Option<KfuncRefKind> {
    kfunc_pointer_arg_ref_kind(kfunc, arg_idx)
}

fn kfunc_local_map_ref_arg(
    kfunc: &str,
    arg_idx: usize,
    arg: VReg,
    types: &HashMap<VReg, MirType>,
) -> bool {
    matches!(types.get(&arg), Some(MirType::MapRef { .. }))
        && kfunc_supports_local_map_fd(kfunc, arg_idx)
}

fn validate_kfunc_map_fd_matches_map_value(
    kfunc: &str,
    args: &[VReg],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let (map_value_arg_idx, map_fd_arg_idx) = match kfunc {
        "bpf_wq_init" => (0, 1),
        _ => return,
    };
    let (Some(map_value), Some(map_fd)) = (args.get(map_value_arg_idx), args.get(map_fd_arg_idx))
    else {
        return;
    };
    let Some(map_fd_source) = state.map_fd_source(*map_fd) else {
        return;
    };
    if state.map_value_source_is_ambiguous(*map_value) {
        errors.push(VerifierTypeError::new(format!(
            "kfunc '{}' arg{} map value may come from multiple maps and cannot be matched to arg{} map '{}'",
            kfunc, map_value_arg_idx, map_fd_arg_idx, map_fd_source.name
        )));
        return;
    }
    let Some(map_value_source) = state.map_value_source(*map_value) else {
        return;
    };
    if map_value_source.map != *map_fd_source {
        errors.push(VerifierTypeError::new(format!(
            "kfunc '{}' arg{} map '{}' does not match arg{} map value '{}'",
            kfunc, map_fd_arg_idx, map_fd_source.name, map_value_arg_idx, map_value_source.map.name
        )));
    }
}

pub(in crate::compiler::verifier_types) fn kfunc_iter_lifecycle(
    kfunc: &str,
) -> Option<KfuncUnknownIterLifecycle> {
    kfunc_iter_lifecycle_shared(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_unknown_dynptr_args(
    kfunc: &str,
) -> Vec<KfuncUnknownDynptrArg> {
    kfunc_unknown_dynptr_args_shared(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_unknown_dynptr_copy(
    kfunc: &str,
) -> Vec<KfuncUnknownDynptrCopy> {
    kfunc_unknown_dynptr_copy_shared(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_unknown_stack_object_lifecycle(
    kfunc: &str,
) -> Option<KfuncUnknownStackObjectLifecycle> {
    kfunc_unknown_stack_object_lifecycle_shared(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_unknown_stack_object_copy(
    kfunc: &str,
) -> Vec<KfuncUnknownStackObjectCopy> {
    kfunc_unknown_stack_object_copy_shared(kfunc)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IterLifecycleFailure {
    LiveSlot,
    MissingMatchingConstructor,
}

fn iter_lifecycle_result(
    valid: bool,
    failure: IterLifecycleFailure,
) -> Result<(), IterLifecycleFailure> {
    if valid { Ok(()) } else { Err(failure) }
}

fn apply_iter_lifecycle_op(
    state: &mut VerifierState,
    family: KfuncIterFamily,
    op: KfuncIterLifecycleOp,
    slot: StackSlotId,
) -> Result<(), IterLifecycleFailure> {
    match (family, op) {
        (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_task_vma_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_task_vma_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_task_vma_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Task, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_task_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::Task, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_task_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Task, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_task_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_scx_dsq_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_scx_dsq_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_scx_dsq_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Num, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_num_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::Num, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_num_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Num, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_num_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Bits, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_bits_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::Bits, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_bits_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Bits, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_bits_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Css, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_css_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::Css, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_css_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Css, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_css_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_css_task_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_css_task_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_css_task_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_dmabuf_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_dmabuf_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_dmabuf_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
            state.acquire_iter_kmem_cache_slot(slot),
            IterLifecycleFailure::LiveSlot,
        ),
        (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
            state.use_iter_kmem_cache_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
        (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
            state.release_iter_kmem_cache_slot(slot),
            IterLifecycleFailure::MissingMatchingConstructor,
        ),
    }
}

fn iter_lifecycle_error_message(
    kfunc: &str,
    family: KfuncIterFamily,
    failure: IterLifecycleFailure,
) -> String {
    match failure {
        IterLifecycleFailure::LiveSlot => format!(
            "kfunc '{}' requires uninitialized {} stack object slot",
            kfunc,
            family.stack_object_type_name()
        ),
        IterLifecycleFailure::MissingMatchingConstructor => format!(
            "kfunc '{}' requires a matching {}",
            kfunc,
            family.constructor_kfunc()
        ),
    }
}

pub(in crate::compiler::verifier_types) fn apply_kfunc_semantics(
    kfunc: &str,
    args: &[VReg],
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if kfunc == "bpf_rcu_read_lock" {
        state.acquire_rcu_read_lock();
        return;
    }
    if kfunc == "bpf_rcu_read_unlock" {
        if !state.release_rcu_read_lock() {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_rcu_read_unlock' requires a matching bpf_rcu_read_lock",
            ));
        }
        return;
    }
    if kfunc == "bpf_preempt_disable" {
        state.acquire_preempt_disable();
        return;
    }
    if kfunc == "bpf_preempt_enable" {
        if !state.release_preempt_disable() {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_preempt_enable' requires a matching bpf_preempt_disable",
            ));
        }
        return;
    }
    if kfunc == "bpf_local_irq_save" {
        if let Some(flags) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_local_irq_disable_slot(flags);
        }
        return;
    }
    if kfunc == "bpf_local_irq_restore" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|flags| state.release_local_irq_disable_slot(flags));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_local_irq_restore' requires a matching bpf_local_irq_save",
            ));
        }
        return;
    }
    if kfunc == "bpf_res_spin_lock" {
        let Some(lock) = args.first().copied() else {
            return;
        };
        if !res_spin_lock_arg_can_transition(kfunc, lock, types, state) {
            return;
        }
        let identity = state.res_spin_lock_identity(lock);
        if !state.acquire_res_spin_lock(identity) {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_res_spin_lock' cannot acquire an already-held resource spin lock",
            ));
        }
        return;
    }
    if kfunc == "bpf_res_spin_unlock" {
        let Some(lock) = args.first().copied() else {
            return;
        };
        if !res_spin_lock_arg_can_transition(kfunc, lock, types, state) {
            return;
        }
        let identity = state.res_spin_lock_identity(lock);
        let released = state.release_res_spin_lock(identity);
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_res_spin_unlock' requires a matching bpf_res_spin_lock",
            ));
        }
        return;
    }
    if kfunc == "bpf_res_spin_lock_irqsave" {
        if let (Some(lock), Some(flags)) = (
            args.first().copied(),
            args.get(1)
                .copied()
                .and_then(|arg| stack_slot_from_arg(state, arg)),
        ) {
            if !res_spin_lock_arg_can_transition(kfunc, lock, types, state) {
                return;
            }
            let identity = state.res_spin_lock_identity(lock);
            if !state.acquire_res_spin_lock_irqsave(identity, flags) {
                errors.push(VerifierTypeError::new(
                    "kfunc 'bpf_res_spin_lock_irqsave' cannot acquire an already-held resource spin lock",
                ));
            }
        }
        return;
    }
    if kfunc == "bpf_res_spin_unlock_irqrestore" {
        let released = match (
            args.first().copied(),
            args.get(1)
                .copied()
                .and_then(|arg| stack_slot_from_arg(state, arg)),
        ) {
            (Some(lock), Some(flags)) => {
                if !res_spin_lock_arg_can_transition(kfunc, lock, types, state) {
                    return;
                }
                let identity = state.res_spin_lock_identity(lock);
                state.release_res_spin_lock_irqsave(identity, flags)
            }
            _ => false,
        };
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_res_spin_unlock_irqrestore' requires a matching bpf_res_spin_lock_irqsave",
            ));
        }
        return;
    }
    if let Some(lifecycle) = kfunc_iter_lifecycle(kfunc) {
        let iter = args
            .get(lifecycle.arg_idx)
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg));
        if let Some(iter) = iter {
            if let Err(failure) =
                apply_iter_lifecycle_op(state, lifecycle.family, lifecycle.op, iter)
            {
                errors.push(VerifierTypeError::new(iter_lifecycle_error_message(
                    kfunc,
                    lifecycle.family,
                    failure,
                )));
            }
        } else if lifecycle.op != KfuncIterLifecycleOp::New {
            errors.push(VerifierTypeError::new(iter_lifecycle_error_message(
                kfunc,
                lifecycle.family,
                IterLifecycleFailure::MissingMatchingConstructor,
            )));
        }
        return;
    }
    let unknown_dynptr_copies = kfunc_unknown_dynptr_copy(kfunc);
    let unknown_dynptr_args = kfunc_unknown_dynptr_args(kfunc);
    if !unknown_dynptr_args.is_empty() {
        for dynptr_arg in &unknown_dynptr_args {
            let Some(ptr) = args.get(dynptr_arg.arg_idx).copied() else {
                continue;
            };
            let Some(slot) = stack_slot_from_arg(state, ptr) else {
                continue;
            };
            match dynptr_arg.role {
                KfuncUnknownDynptrArgRole::In => {
                    if !state.is_dynptr_slot_initialized(slot) {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} requires initialized dynptr stack object",
                            kfunc, dynptr_arg.arg_idx
                        )));
                    }
                }
                KfuncUnknownDynptrArgRole::Out => {
                    if unknown_dynptr_copies
                        .iter()
                        .any(|copy| copy.dst_arg_idx == dynptr_arg.arg_idx)
                    {
                        continue;
                    }
                    if state.is_dynptr_slot_maybe_initialized(slot) {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} requires uninitialized dynptr stack object slot",
                            kfunc, dynptr_arg.arg_idx
                        )));
                        continue;
                    }
                    state.initialize_dynptr_slot(slot);
                }
            }
        }
        for copy in unknown_dynptr_copies {
            if let (Some(src), Some(dst)) = (
                args.get(copy.src_arg_idx).copied(),
                args.get(copy.dst_arg_idx).copied(),
            ) && let (Some(src_slot), Some(dst_slot)) = (
                stack_slot_from_arg(state, src),
                stack_slot_from_arg(state, dst),
            ) {
                if src_slot == dst_slot {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} must reference distinct stack slot from arg{}",
                        kfunc, copy.dst_arg_idx, copy.src_arg_idx
                    )));
                } else if state.is_dynptr_slot_maybe_initialized(dst_slot) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires uninitialized dynptr stack object slot",
                        kfunc, copy.dst_arg_idx
                    )));
                } else if !state.is_dynptr_slot_initialized(src_slot) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires initialized dynptr stack object",
                        kfunc, copy.src_arg_idx
                    )));
                } else {
                    if copy.move_semantics {
                        state.deinitialize_dynptr_slot(src_slot);
                    }
                    state.initialize_dynptr_slot(dst_slot);
                    state.copy_ringbuf_dynptr_slot(src_slot, dst_slot, copy.move_semantics);
                }
            }
        }
    }
    let unknown_stack_object_copies = kfunc_unknown_stack_object_copy(kfunc);
    if unknown_stack_object_copies.is_empty()
        && let Some(lifecycle) = kfunc_unknown_stack_object_lifecycle(kfunc)
        && let Some(ptr) = args
            .get(lifecycle.arg_idx)
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
    {
        match lifecycle.op {
            KfuncUnknownStackObjectLifecycleOp::Init => {
                if state.has_live_unknown_stack_object_slot(ptr) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires uninitialized {} stack object slot",
                        kfunc, lifecycle.arg_idx, lifecycle.type_name
                    )));
                    return;
                }
                state.initialize_unknown_stack_object_slot(
                    ptr,
                    &lifecycle.type_name,
                    lifecycle.type_id,
                );
            }
            KfuncUnknownStackObjectLifecycleOp::Destroy => {
                if !state.release_unknown_stack_object_slot(
                    ptr,
                    &lifecycle.type_name,
                    lifecycle.type_id,
                ) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires initialized {} stack object",
                        kfunc, lifecycle.arg_idx, lifecycle.type_name
                    )));
                }
            }
        }
    }
    for copy in unknown_stack_object_copies {
        if let (Some(src), Some(dst)) = (
            args.get(copy.src_arg_idx).copied(),
            args.get(copy.dst_arg_idx).copied(),
        ) && let (Some(src_slot), Some(dst_slot)) = (
            stack_slot_from_arg(state, src),
            stack_slot_from_arg(state, dst),
        ) {
            if src_slot == dst_slot {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} must reference distinct stack slot from arg{}",
                    kfunc, copy.dst_arg_idx, copy.src_arg_idx
                )));
            } else {
                if !state.has_unknown_stack_object_slot(src_slot, &copy.type_name, copy.type_id) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires initialized {} stack object",
                        kfunc, copy.src_arg_idx, copy.type_name
                    )));
                    return;
                }
                if state.has_live_unknown_stack_object_slot(dst_slot) {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires uninitialized {} stack object slot",
                        kfunc, copy.dst_arg_idx, copy.type_name
                    )));
                    return;
                }
                if copy.move_semantics
                    && !state.release_unknown_stack_object_slot(
                        src_slot,
                        &copy.type_name,
                        copy.type_id,
                    )
                {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} requires initialized {} stack object",
                        kfunc, copy.src_arg_idx, copy.type_name
                    )));
                    return;
                }
                state.initialize_unknown_stack_object_slot(dst_slot, &copy.type_name, copy.type_id);
            }
        }
    }

    let Some((release_arg_idx, expected_kind)) = kfunc_release_spec(kfunc) else {
        return;
    };
    let Some(ptr) = args.get(release_arg_idx) else {
        return;
    };
    if state.is_released_kfunc_ref(*ptr) {
        return;
    }

    match state.get(*ptr) {
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::NonNull,
            kfunc_ref: Some(ref_id),
            ..
        } => {
            if !state.is_live_kfunc_ref(ref_id) {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} reference already released",
                    kfunc, release_arg_idx
                )));
                return;
            }
            let actual_kind = state.kfunc_ref_kind(ref_id);
            if actual_kind == Some(expected_kind) {
                state.invalidate_kfunc_ref(ref_id);
            } else {
                let expected = expected_kind.label();
                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} expects acquired {} reference, got {} reference",
                    kfunc, release_arg_idx, expected, actual
                )));
            }
        }
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::MaybeNull,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} may dereference null pointer v{} (add a null check)",
                kfunc, release_arg_idx, ptr.0
            )));
        }
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ..
        } => {
            let expected = expected_kind.label();
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} expects acquired {} reference",
                kfunc, release_arg_idx, expected
            )));
        }
        VerifierType::Ptr { space, .. } => {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} expects kernel pointer, got {:?}",
                kfunc, release_arg_idx, space
            )));
        }
        _ => {
            let expected = expected_kind.label();
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg{} expects acquired {} reference pointer",
                kfunc, release_arg_idx, expected
            )));
        }
    }
}

pub(in crate::compiler::verifier_types) fn kfunc_acquire_kind(kfunc: &str) -> Option<KfuncRefKind> {
    kfunc_acquire_ref_kind(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_release_kind(kfunc: &str) -> Option<KfuncRefKind> {
    kfunc_release_ref_kind(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_release_arg_index(kfunc: &str) -> Option<usize> {
    kfunc_release_ref_arg_index(kfunc)
}

pub(in crate::compiler::verifier_types) fn kfunc_release_spec(
    kfunc: &str,
) -> Option<(usize, KfuncRefKind)> {
    Some((kfunc_release_arg_index(kfunc)?, kfunc_release_kind(kfunc)?))
}

fn stack_slot_from_arg(state: &VerifierState, arg: VReg) -> Option<StackSlotId> {
    match state.get(arg) {
        VerifierType::Ptr {
            bounds: Some(bounds),
            ..
        } => match bounds.origin() {
            PtrOrigin::Stack(slot) => Some(slot),
            PtrOrigin::Map(_) => None,
            PtrOrigin::Packet(_) => None,
            PtrOrigin::ContextBuffer(_) => None,
            PtrOrigin::KernelBtf(_) => None,
        },
        _ => None,
    }
}

fn res_spin_lock_arg_can_transition(
    kfunc: &str,
    arg: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
) -> bool {
    if !matches!(
        state.get(arg),
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ..
        }
    ) {
        return false;
    }
    let Some(MirType::Ptr { pointee, .. }) = types.get(&arg) else {
        return true;
    };
    kfunc_arg_pointee_mismatch(kfunc, 0, pointee).is_none()
}
