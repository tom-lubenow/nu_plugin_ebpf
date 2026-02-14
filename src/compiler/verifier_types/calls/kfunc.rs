use super::*;

pub(in crate::compiler::verifier_types) fn check_kfunc_arg(
    kfunc: &str,
    arg_idx: usize,
    arg: VReg,
    expected: KfuncArgKind,
    state: &VerifierState,
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
        KfuncArgKind::Pointer => match ty {
            VerifierType::Ptr {
                space,
                nullability,
                kfunc_ref,
                ..
            } => {
                if kfunc_pointer_arg_requires_kernel(kfunc, arg_idx)
                    && space != AddressSpace::Kernel
                {
                    errors.push(VerifierTypeError::new(format!(
                        "kfunc '{}' arg{} expects kernel pointer, got {:?}",
                        kfunc, arg_idx, space
                    )));
                }
                if let Some(expected_kind) = kfunc_pointer_arg_expected_ref_kind(kfunc, arg_idx) {
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
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg{} expects pointer, got {:?}",
                    kfunc, arg_idx, ty
                )));
            }
        },
    }
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_kernel(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_expected_ref_kind(
    kfunc: &str,
    arg_idx: usize,
) -> Option<KfuncRefKind> {
    kfunc_pointer_arg_ref_kind(kfunc, arg_idx)
}

pub(in crate::compiler::verifier_types) fn apply_kfunc_semantics(
    kfunc: &str,
    args: &[VReg],
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

    let Some(expected_kind) = kfunc_release_kind(kfunc) else {
        return;
    };
    let Some(ptr) = args.first() else {
        return;
    };

    match state.get(*ptr) {
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::NonNull,
            kfunc_ref: Some(ref_id),
            ..
        } => {
            if !state.is_live_kfunc_ref(ref_id) {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' arg0 reference already released",
                    kfunc
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
                    "kfunc '{}' arg0 expects acquired {} reference, got {} reference",
                    kfunc, expected, actual
                )));
            }
        }
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::MaybeNull,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg0 may dereference null pointer v{} (add a null check)",
                kfunc, ptr.0
            )));
        }
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ..
        } => {
            let expected = expected_kind.label();
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg0 expects acquired {} reference",
                kfunc, expected
            )));
        }
        VerifierType::Ptr { space, .. } => {
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg0 expects kernel pointer, got {:?}",
                kfunc, space
            )));
        }
        _ => {
            let expected = expected_kind.label();
            errors.push(VerifierTypeError::new(format!(
                "kfunc '{}' arg0 expects acquired {} reference pointer",
                kfunc, expected
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
