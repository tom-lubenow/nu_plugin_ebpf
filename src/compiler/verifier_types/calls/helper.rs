use super::*;
use crate::compiler::elf::GetSocketCookieArgPolicy;
use crate::compiler::instruction::{KfuncRefKind, helper_pointer_arg_ref_kind};
use crate::compiler::{ProbeContext, ProgramTypeInfo};

pub(in crate::compiler::verifier_types) fn check_helper_arg(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    expected: HelperArgKind,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let ty = value_type(arg, state, slot_sizes);
    match expected {
        HelperArgKind::Scalar => {
            if !matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
                errors.push(VerifierTypeError::new(format!(
                    "helper {} arg{} expects scalar, got {:?}",
                    helper_id, arg_idx, ty
                )));
            }
        }
        HelperArgKind::Pointer => {
            if helper_pointer_arg_allows_const_zero(
                helper_id, arg_idx, arg, state, program, probe_ctx,
            ) {
                return;
            }
            if helper_local_map_ref_arg(helper_id, arg_idx, arg, types) {
                return;
            }
            if !matches!(ty, VerifierType::Ptr { .. }) {
                errors.push(VerifierTypeError::new(format!(
                    "helper {} arg{} expects pointer, got {:?}",
                    helper_id, arg_idx, ty
                )));
            }
        }
    }
}

pub(in crate::compiler::verifier_types) fn helper_pointer_arg_allows_const_zero(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
) -> bool {
    let Some(helper) = BpfHelper::from_u32(helper_id) else {
        return false;
    };
    (matches!(
        (Some(helper), arg_idx),
        (Some(BpfHelper::KptrXchg), 1)
            | (Some(BpfHelper::RedirectNeigh), 1)
            | (Some(BpfHelper::SkAssign), 1)
            | (Some(BpfHelper::SkStorageGet), 2)
            | (Some(BpfHelper::InodeStorageGet), 2)
            | (Some(BpfHelper::TaskStorageGet), 2)
    ) || helper_allows_maybe_null_arg(helper, arg_idx, program, probe_ctx))
        && matches!(
            value_range(arg, state),
            ValueRange::Known { min: 0, max: 0 }
        )
}

pub(in crate::compiler::verifier_types) fn helper_positive_size_upper_bound(
    helper_id: u32,
    arg_idx: usize,
    value: &MirValue,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<usize> {
    match value_range(value, state) {
        ValueRange::Known { min, max } => {
            if max <= 0 || min <= 0 {
                errors.push(VerifierTypeError::new(format!(
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

fn scalar_value_range_satisfies_only<F>(
    value: &MirValue,
    state: &VerifierState,
    predicate: F,
) -> bool
where
    F: Fn(i64) -> bool,
{
    match value_range(value, state) {
        ValueRange::Known { min, max } if min <= max => {
            let width = max.saturating_sub(min);
            width <= 64 && (min..=max).all(predicate)
        }
        _ => false,
    }
}

pub(in crate::compiler::verifier_types) fn check_helper_ptr_arg_value(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    op: &str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    allow_maybe_null: bool,
    access_size: Option<usize>,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    if helper_pointer_arg_allows_const_zero(helper_id, arg_idx, arg, state, program, probe_ctx) {
        return;
    }
    if helper_local_map_ref_arg(helper_id, arg_idx, arg, types) {
        return;
    }
    let allowed = helper_allowed_spaces(allow_stack, allow_map, allow_kernel, allow_user);
    match arg {
        MirValue::VReg(vreg) => {
            let ptr = if allow_maybe_null {
                match state.get(*vreg) {
                    VerifierType::Ptr {
                        space,
                        bounds,
                        nullability,
                        ..
                    } => {
                        if !allowed.contains(&space) {
                            errors.push(VerifierTypeError::new(format!(
                                "{op} expects pointer in {:?}, got {:?}",
                                allowed, space
                            )));
                            return;
                        }
                        Some((space, bounds, nullability))
                    }
                    VerifierType::Uninit => {
                        errors.push(VerifierTypeError::new(format!(
                            "{op} uses uninitialized pointer v{}",
                            vreg.0
                        )));
                        None
                    }
                    other => {
                        errors.push(VerifierTypeError::new(format!(
                            "{op} requires pointer type, got {:?}",
                            other
                        )));
                        None
                    }
                }
            } else {
                require_ptr_with_space(*vreg, op, allowed, state, errors).map(|ty| match ty {
                    VerifierType::Ptr {
                        space,
                        bounds,
                        nullability,
                        ..
                    } => (space, bounds, nullability),
                    _ => unreachable!("require_ptr_with_space only returns pointer types"),
                })
            };
            let Some((space, bounds, nullability)) = ptr else {
                return;
            };
            if let Some(size) = access_size {
                if allow_maybe_null && !matches!(nullability, Nullability::NonNull) {
                    errors.push(VerifierTypeError::new(format!(
                        "{op} may dereference null pointer v{} (add a null check)",
                        vreg.0
                    )));
                    return;
                }
                check_ptr_bounds(op, space, bounds, 0, size, errors);
            }
        }
        MirValue::StackSlot(slot) => {
            if !allowed.contains(&AddressSpace::Stack) {
                errors.push(VerifierTypeError::new(format!(
                    "{op} expects pointer in {:?}, got stack slot {}",
                    allowed, slot.0
                )));
                return;
            }
            if let Some(size) = access_size {
                check_slot_access(*slot, 0, size, slot_sizes, op, errors);
            }
        }
        MirValue::Const(_) => {
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg{} expects pointer value",
                helper_id, arg_idx
            )));
        }
    }
}

pub(in crate::compiler::verifier_types) fn helper_allowed_spaces(
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

pub(in crate::compiler::verifier_types) fn helper_pointer_arg_expected_ref_kind(
    helper: BpfHelper,
    arg_idx: usize,
) -> Option<KfuncRefKind> {
    helper_pointer_arg_ref_kind(helper, arg_idx)
}

pub(in crate::compiler::verifier_types) fn apply_helper_semantics(
    helper_id: u32,
    args: &[MirValue],
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<KfuncRefKind> {
    let Some(helper) = BpfHelper::from_u32(helper_id) else {
        return None;
    };

    let semantics = helper.semantics();
    let mut acquire_kind = helper_acquire_ref_kind(helper);
    let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
    let allow_maybe_null_for_arg =
        |arg_idx: usize| helper_allows_maybe_null_arg(helper, arg_idx, program, probe_ctx);
    for size_arg in semantics.positive_size_args {
        if let Some(value) = args.get(*size_arg) {
            positive_size_bounds[*size_arg] =
                helper_positive_size_upper_bound(helper_id, *size_arg, value, state, errors);
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
        check_helper_ptr_arg_value(
            helper_id,
            rule.arg_idx,
            arg,
            rule.op,
            rule.allowed.allow_stack,
            rule.allowed.allow_map,
            rule.allowed.allow_kernel,
            rule.allowed.allow_user,
            allow_maybe_null_for_arg(rule.arg_idx),
            access_size,
            types,
            state,
            program,
            probe_ctx,
            slot_sizes,
            errors,
        );
    }

    let arg_is_known_zero = |arg_idx| {
        args.get(arg_idx).is_some_and(|value| {
            matches!(
                value_range(value, state),
                ValueRange::Known { min: 0, max: 0 }
            )
        })
    };

    if let Some((arg_idx, message)) = probe_ctx
        .and_then(|ctx| ctx.helper_zero_arg_requirement(helper))
        .or_else(|| {
            program.and_then(|program| program.program_type.helper_zero_arg_requirement(helper))
        })
        && !arg_is_known_zero(arg_idx)
    {
        errors.push(VerifierTypeError::new(message));
    }

    if let Some((arg_idx, message)) = helper.zero_scalar_arg_requirement()
        && !arg_is_known_zero(arg_idx)
    {
        errors.push(VerifierTypeError::new(message));
    }

    if let Some((arg_idx, trigger_arg_idx, message)) =
        helper.zero_scalar_arg_requirement_when_arg_zero()
        && arg_is_known_zero(trigger_arg_idx)
        && !arg_is_known_zero(arg_idx)
    {
        errors.push(VerifierTypeError::new(message));
    }

    if let Some((arg_idx, allowed_mask, message)) = helper.scalar_arg_allowed_mask_requirement()
        && let Some(value) = args.get(arg_idx)
        && matches!(
            value_type(value, state, slot_sizes),
            VerifierType::Scalar | VerifierType::Bool
        )
        && !scalar_value_range_satisfies_only(value, state, |candidate| {
            candidate >= 0 && (candidate & !allowed_mask) == 0
        })
    {
        errors.push(VerifierTypeError::new(message));
    }

    if matches!(helper, BpfHelper::GetSocketCookie) {
        validate_get_socket_cookie_arg_shape(args, types, state, program, probe_ctx, errors);
    }
    for arg_idx in 0..args.len() {
        let Some((predicate, expected)) = helper_expected_named_arg_shape(helper, arg_idx) else {
            continue;
        };
        validate_named_helper_arg_shape(
            helper, args, arg_idx, types, state, predicate, expected, errors,
        );
    }

    for (arg_idx, arg) in args.iter().enumerate().take(5) {
        let Some(expected_kind) = helper_pointer_arg_expected_ref_kind(helper, arg_idx) else {
            continue;
        };
        if helper_release_ref_kind(helper) == Some(expected_kind) && arg_idx == 0 {
            continue;
        }
        let MirValue::VReg(vreg) = arg else {
            continue;
        };
        let VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability,
            kfunc_ref: Some(ref_id),
            ..
        } = state.get(*vreg)
        else {
            continue;
        };
        if !matches!(nullability, Nullability::NonNull) {
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg{} may dereference null pointer v{} (add a null check)",
                helper_id, arg_idx, vreg.0
            )));
            continue;
        }
        if !state.is_live_kfunc_ref(ref_id) {
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg{} reference already released",
                helper_id, arg_idx
            )));
            continue;
        }
        let actual_kind = state.kfunc_ref_kind(ref_id);
        if actual_kind != Some(expected_kind) {
            let expected = expected_kind.label();
            let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg{} expects {} reference, got {} reference",
                helper_id, arg_idx, expected, actual
            )));
        }
    }

    if semantics.ringbuf_record_arg0 {
        if let Some(record) = args.first() {
            match record {
                MirValue::VReg(vreg) => match state.get(*vreg) {
                    VerifierType::Ptr {
                        space: AddressSpace::Map,
                        nullability: Nullability::NonNull,
                        ringbuf_ref: Some(ref_id),
                        ..
                    } => {
                        state.invalidate_ringbuf_ref(ref_id);
                    }
                    VerifierType::Ptr {
                        nullability: Nullability::MaybeNull,
                        ..
                    } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 may dereference null pointer v{} (add a null check)",
                            helper_id, vreg.0
                        )));
                    }
                    VerifierType::Ptr { .. } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects ringbuf record pointer",
                            helper_id
                        )));
                    }
                    _ => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects ringbuf record pointer",
                            helper_id
                        )));
                    }
                },
                _ => {
                    errors.push(VerifierTypeError::new(format!(
                        "helper {} arg0 expects ringbuf record pointer",
                        helper_id
                    )));
                }
            }
        }
    }

    if let Some(expected_kind) = helper_release_ref_kind(helper) {
        let expected = expected_kind.label();
        if let Some(ptr) = args.first() {
            match ptr {
                MirValue::VReg(vreg) => match state.get(*vreg) {
                    VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::NonNull,
                        kfunc_ref: Some(ref_id),
                        ..
                    } => {
                        if !state.is_live_kfunc_ref(ref_id) {
                            errors.push(VerifierTypeError::new(format!(
                                "helper {} arg0 reference already released",
                                helper_id
                            )));
                        } else {
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind == Some(expected_kind) {
                                state.invalidate_kfunc_ref(ref_id);
                            } else {
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                errors.push(VerifierTypeError::new(format!(
                                    "helper {} arg0 expects acquired {} reference, got {} reference",
                                    helper_id, expected, actual
                                )));
                            }
                        }
                    }
                    VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::MaybeNull | Nullability::Null,
                        ..
                    } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 may dereference null pointer v{} (add a null check)",
                            helper_id, vreg.0
                        )));
                    }
                    VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        ..
                    } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects acquired {} reference",
                            helper_id, expected
                        )));
                    }
                    VerifierType::Ptr { space, .. } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects kernel pointer, got {:?}",
                            helper_id, space
                        )));
                    }
                    _ => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects acquired {} reference pointer",
                            helper_id, expected
                        )));
                    }
                },
                _ => {
                    errors.push(VerifierTypeError::new(format!(
                        "helper {} arg0 expects acquired {} reference pointer",
                        helper_id, expected
                    )));
                }
            }
        }
    }

    if matches!(helper, BpfHelper::KptrXchg)
        && let Some(MirValue::VReg(src)) = args.get(1)
        && let VerifierType::Ptr {
            kfunc_ref: Some(ref_id),
            ..
        } = state.get(*src)
    {
        if state.is_live_kfunc_ref(ref_id) {
            acquire_kind = state.kfunc_ref_kind(ref_id);
            state.invalidate_kfunc_ref(ref_id);
        } else {
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg1 reference already released",
                helper_id
            )));
        }
    }

    if helper.invalidates_packet_pointers() {
        state.invalidate_packet_pointers();
    }

    acquire_kind
}

fn validate_get_socket_cookie_arg_shape(
    args: &[MirValue],
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(program_type) = probe_ctx
        .map(|ctx| ctx.program_type())
        .or_else(|| program.map(|program| program.program_type))
    else {
        return;
    };
    let Some(policy) = probe_ctx
        .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
        .or_else(|| {
            program.and_then(|program| program.program_type.get_socket_cookie_arg_policy())
        })
    else {
        return;
    };
    let Some(arg) = args.first() else {
        return;
    };
    if policy.allows_maybe_null()
        && matches!(
            value_range(arg, state),
            ValueRange::Known { min: 0, max: 0 }
        )
    {
        return;
    }
    let matches_policy = match policy {
        GetSocketCookieArgPolicy::Context => helper_arg_is_raw_context_pointer(arg, state),
        GetSocketCookieArgPolicy::ContextOrSocket => {
            helper_arg_is_raw_context_pointer(arg, state)
                || helper_arg_is_socket_cookie_socket_pointer(arg, types)
        }
        GetSocketCookieArgPolicy::Socket => helper_arg_is_socket_cookie_socket_pointer(arg, types),
    };
    if !matches_policy {
        errors.push(VerifierTypeError::new(
            policy.error_message(BpfHelper::GetSocketCookie, program_type),
        ));
    }
}

fn helper_arg_is_raw_context_pointer(arg: &MirValue, state: &VerifierState) -> bool {
    match arg {
        MirValue::VReg(vreg) => state.ctx_field_source(*vreg) == Some(&CtxField::Context),
        MirValue::Const(_) | MirValue::StackSlot(_) => false,
    }
}

fn helper_allows_maybe_null_arg(
    helper: BpfHelper,
    arg_idx: usize,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
) -> bool {
    if !matches!(helper, BpfHelper::GetSocketCookie) || arg_idx != 0 {
        return false;
    }
    probe_ctx
        .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
        .or_else(|| program.and_then(|program| program.program_type.get_socket_cookie_arg_policy()))
        .is_some_and(GetSocketCookieArgPolicy::allows_maybe_null)
}

fn helper_arg_is_socket_cookie_socket_pointer(
    arg: &MirValue,
    types: &HashMap<VReg, MirType>,
) -> bool {
    match arg {
        MirValue::VReg(vreg) => types
            .get(vreg)
            .is_some_and(MirType::is_socket_cookie_socket_ptr),
        MirValue::Const(_) | MirValue::StackSlot(_) => false,
    }
}

fn validate_named_helper_arg_shape(
    helper: BpfHelper,
    args: &[MirValue],
    arg_idx: usize,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    predicate: fn(&MirType) -> bool,
    expected: &str,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(arg) = args.get(arg_idx) else {
        return;
    };
    if helper_pointer_arg_allows_const_zero(helper as u32, arg_idx, arg, state, None, None) {
        return;
    }
    if helper_arg_has_tracked_kfunc_ref(arg, state) {
        return;
    }
    let matches = match arg {
        MirValue::VReg(vreg) => types.get(vreg).is_some_and(predicate),
        MirValue::Const(_) | MirValue::StackSlot(_) => false,
    };
    if !matches {
        errors.push(VerifierTypeError::new(format!(
            "helper '{}' arg{} expects {}",
            helper.name(),
            arg_idx,
            expected
        )));
    }
}

fn helper_arg_has_tracked_kfunc_ref(arg: &MirValue, state: &VerifierState) -> bool {
    let MirValue::VReg(vreg) = arg else {
        return false;
    };
    matches!(
        state.get(*vreg),
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            kfunc_ref: Some(_),
            ..
        }
    )
}

fn helper_expected_named_arg_shape(
    helper: BpfHelper,
    arg_idx: usize,
) -> Option<(fn(&MirType) -> bool, &'static str)> {
    match helper_pointer_arg_ref_kind(helper, arg_idx)? {
        KfuncRefKind::Socket => Some((MirType::is_socket_ptr, "socket pointer")),
        KfuncRefKind::Task => Some((MirType::is_task_struct_ptr, "task pointer")),
        KfuncRefKind::File => Some((MirType::is_file_ptr, "file pointer")),
        KfuncRefKind::Inode => Some((MirType::is_inode_ptr, "inode pointer")),
        _ => None,
    }
}

fn helper_local_map_ref_arg(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    types: &HashMap<VReg, MirType>,
) -> bool {
    let MirValue::VReg(vreg) = arg else {
        return false;
    };
    matches!(types.get(vreg), Some(MirType::MapRef { .. }))
        && BpfHelper::from_u32(helper_id)
            .is_some_and(|helper| helper.supports_local_helper_map_fd(arg_idx))
}
