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
                bounds,
                nullability,
                kfunc_ref,
                ..
            } => {
                if kfunc_pointer_arg_requires_stack(kfunc, arg_idx) {
                    if !bounds.is_some_and(|ptr_bounds| {
                        matches!(ptr_bounds.origin(), PtrOrigin::Stack(_))
                    }) {
                        errors.push(VerifierTypeError::new(format!(
                            "kfunc '{}' arg{} expects stack slot pointer",
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

pub(in crate::compiler::verifier_types) fn kfunc_pointer_arg_requires_stack(
    kfunc: &str,
    arg_idx: usize,
) -> bool {
    kfunc_pointer_arg_requires_stack_shared(kfunc, arg_idx)
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
        state.acquire_res_spin_lock();
        return;
    }
    if kfunc == "bpf_res_spin_unlock" {
        if !state.release_res_spin_lock() {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_res_spin_unlock' requires a matching bpf_res_spin_lock",
            ));
        }
        return;
    }
    if kfunc == "bpf_res_spin_lock_irqsave" {
        if let Some(flags) = args
            .get(1)
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_res_spin_lock_irqsave_slot(flags);
        }
        return;
    }
    if kfunc == "bpf_res_spin_unlock_irqrestore" {
        let released = args
            .get(1)
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|flags| state.release_res_spin_lock_irqsave_slot(flags));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_res_spin_unlock_irqrestore' requires a matching bpf_res_spin_lock_irqsave",
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

fn stack_slot_from_arg(state: &VerifierState, arg: VReg) -> Option<StackSlotId> {
    match state.get(arg) {
        VerifierType::Ptr {
            bounds: Some(bounds),
            ..
        } => match bounds.origin() {
            PtrOrigin::Stack(slot) => Some(slot),
            PtrOrigin::Map => None,
        },
        _ => None,
    }
}
