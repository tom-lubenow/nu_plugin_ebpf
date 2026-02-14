use super::*;

pub(in crate::compiler::verifier_types) fn check_helper_arg(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    expected: HelperArgKind,
    state: &VerifierState,
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
            if helper_pointer_arg_allows_const_zero(helper_id, arg_idx, arg) {
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
) -> bool {
    matches!(
        (BpfHelper::from_u32(helper_id), arg_idx),
        (Some(BpfHelper::KptrXchg), 1)
            | (Some(BpfHelper::SkStorageGet), 2)
            | (Some(BpfHelper::TaskStorageGet), 2)
    ) && matches!(arg, MirValue::Const(0))
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

pub(in crate::compiler::verifier_types) fn check_helper_ptr_arg_value(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    op: &str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    access_size: Option<usize>,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    if helper_pointer_arg_allows_const_zero(helper_id, arg_idx, arg) {
        return;
    }
    let allowed = helper_allowed_spaces(allow_stack, allow_map, allow_kernel, allow_user);
    match arg {
        MirValue::VReg(vreg) => {
            let Some(VerifierType::Ptr { space, bounds, .. }) =
                require_ptr_with_space(*vreg, op, allowed, state, errors)
            else {
                return;
            };
            if let Some(size) = access_size {
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
    state: &mut VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<KfuncRefKind> {
    let Some(helper) = BpfHelper::from_u32(helper_id) else {
        return None;
    };

    let semantics = helper.semantics();
    let mut acquire_kind = helper_acquire_ref_kind(helper);
    let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
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
            access_size,
            state,
            slot_sizes,
            errors,
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
            kfunc_ref: Some(ref_id),
            ..
        } = state.get(*vreg)
        else {
            continue;
        };
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

    acquire_kind
}
