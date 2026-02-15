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
    arg: VReg,
    op: &str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    access_size: Option<usize>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let allowed = kfunc_allowed_spaces(allow_stack, allow_map, allow_kernel, allow_user);
    let Some(VerifierType::Ptr { space, bounds, .. }) =
        require_ptr_with_space(arg, op, allowed, state, errors)
    else {
        return;
    };
    if let Some(size) = access_size {
        check_ptr_bounds(op, space, bounds, 0, size, errors);
    }
}

pub(in crate::compiler::verifier_types) fn check_kfunc_semantics(
    kfunc: &str,
    args: &[VReg],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let semantics = kfunc_semantics(kfunc);
    let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
    for size_arg in semantics.positive_size_args {
        if let Some(value) = args.get(*size_arg) {
            positive_size_bounds[*size_arg] =
                kfunc_positive_size_upper_bound(kfunc, *size_arg, *value, state, errors);
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
        check_kfunc_ptr_arg_value(
            *arg,
            rule.op,
            rule.allowed.allow_stack,
            rule.allowed.allow_map,
            rule.allowed.allow_kernel,
            rule.allowed.allow_user,
            access_size,
            state,
            errors,
        );
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
    if kfunc == "bpf_iter_task_vma_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_task_vma_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_task_vma_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_task_vma_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_task_vma_next' requires a matching bpf_iter_task_vma_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_task_vma_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_task_vma_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_task_vma_destroy' requires a matching bpf_iter_task_vma_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_task_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_task_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_task_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_task_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_task_next' requires a matching bpf_iter_task_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_task_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_task_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_task_destroy' requires a matching bpf_iter_task_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_scx_dsq_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_scx_dsq_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_scx_dsq_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_scx_dsq_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_scx_dsq_next' requires a matching bpf_iter_scx_dsq_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_scx_dsq_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_scx_dsq_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_scx_dsq_destroy' requires a matching bpf_iter_scx_dsq_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_num_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_num_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_num_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_num_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_num_next' requires a matching bpf_iter_num_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_num_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_num_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_bits_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_bits_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_bits_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_bits_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_bits_next' requires a matching bpf_iter_bits_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_bits_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_bits_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_dmabuf_new" {
        if let Some(iter) = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
        {
            state.acquire_iter_dmabuf_slot(iter);
        }
        return;
    }
    if kfunc == "bpf_iter_dmabuf_next" {
        let valid = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.use_iter_dmabuf_slot(iter));
        if !valid {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_dmabuf_next' requires a matching bpf_iter_dmabuf_new",
            ));
        }
        return;
    }
    if kfunc == "bpf_iter_dmabuf_destroy" {
        let released = args
            .first()
            .copied()
            .and_then(|arg| stack_slot_from_arg(state, arg))
            .is_some_and(|iter| state.release_iter_dmabuf_slot(iter));
        if !released {
            errors.push(VerifierTypeError::new(
                "kfunc 'bpf_iter_dmabuf_destroy' requires a matching bpf_iter_dmabuf_new",
            ));
        }
        return;
    }

    let Some((release_arg_idx, expected_kind)) = kfunc_release_spec(kfunc) else {
        return;
    };
    let Some(ptr) = args.get(release_arg_idx) else {
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
            PtrOrigin::Map => None,
        },
        _ => None,
    }
}
