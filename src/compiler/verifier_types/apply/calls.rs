use super::*;
use crate::compiler::instruction::{
    kfunc_allowed_while_lock_held, unknown_kfunc_signature_message,
};
use crate::compiler::mir::{MapRef, SubfunctionId};
use crate::compiler::subfn_summaries::{
    SubfunctionMapSource, SubfunctionSummary, SubfunctionUnknownStackObjectType,
};
use crate::compiler::{ProbeContext, ProgramTypeInfo};

fn scalar_value_range_for_type(types: &HashMap<VReg, MirType>, dst: VReg) -> ValueRange {
    types
        .get(&dst)
        .and_then(MirType::scalar_value_range)
        .map(|(min, max)| ValueRange::Known { min, max })
        .unwrap_or(ValueRange::Unknown)
}

fn helper_return_range_for_type(
    ty: VerifierType,
    types: &HashMap<VReg, MirType>,
    dst: VReg,
) -> ValueRange {
    if matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
        scalar_value_range_for_type(types, dst)
    } else {
        ValueRange::Unknown
    }
}

fn reject_call_if_kernel_lock_held(
    state: &VerifierState,
    call: String,
    errors: &mut Vec<VerifierTypeError>,
) {
    if let Some(lock) = state.live_kernel_lock_description() {
        errors.push(VerifierTypeError::new(format!(
            "{} cannot be called while {} is held",
            call, lock
        )));
    }
}

pub(super) fn apply_call_helper_inst(
    dst: VReg,
    helper: u32,
    args: &[MirValue],
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if helper > i32::MAX as u32 {
        errors.push(VerifierTypeError::new(format!(
            "helper id {} is outside the eBPF call immediate range",
            helper
        )));
    }
    let helper_kind = BpfHelper::from_u32(helper);
    if !matches!(helper_kind, Some(BpfHelper::SpinUnlock)) {
        match helper_kind {
            Some(helper) => {
                reject_call_if_kernel_lock_held(
                    state,
                    format!("helper '{}'", helper.name()),
                    errors,
                );
            }
            None => {
                reject_call_if_kernel_lock_held(state, format!("helper {}", helper), errors);
            }
        }
    }

    if let Some(helper_kind) = BpfHelper::from_u32(helper) {
        if helper_kind.requires_callback_subprogram()
            && !helper_kind.supports_modeled_callback_subprogram()
        {
            errors.push(VerifierTypeError::new(format!(
                "helper '{}' requires callback subprogram pointer support, which is not modeled yet",
                helper_kind.name()
            )));
            let ty = types
                .get(&dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set_with_range(dst, ty, ValueRange::Unknown);
            return;
        }
    }

    if let Some(helper_kind) = BpfHelper::from_u32(helper)
        && let Some(message) = probe_ctx
            .and_then(|ctx| ctx.helper_call_error(helper_kind))
            .or_else(|| {
                program.and_then(|program| program.program_type.helper_call_error(helper_kind))
            })
    {
        errors.push(VerifierTypeError::new(message));
        let ty = types
            .get(&dst)
            .map(verifier_type_from_mir)
            .unwrap_or(VerifierType::Scalar);
        let range = helper_return_range_for_type(ty, types, dst);
        state.set_with_range(dst, ty, range);
        return;
    }

    if let Some(sig) = HelperSignature::for_id(helper) {
        if args.len() < sig.min_args || args.len() > sig.max_args {
            errors.push(VerifierTypeError::new(format!(
                "helper {} expects {}..={} args, got {}",
                helper,
                sig.min_args,
                sig.max_args,
                args.len()
            )));
        }
        for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
            check_helper_arg(
                helper,
                idx,
                arg,
                sig.arg_kind(idx),
                types,
                state,
                program,
                probe_ctx,
                slot_sizes,
                errors,
            );
        }
        let helper_kfunc_acquire_kind = apply_helper_semantics(
            helper, args, types, state, slot_sizes, program, probe_ctx, errors,
        );
        clear_stack_slot_value_ranges_for_helper_args(args, state);

        let ty = match sig.ret_kind {
            HelperRetKind::Void => VerifierType::Uninit,
            HelperRetKind::Scalar => types
                .get(&dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar),
            HelperRetKind::PointerNonNull => match BpfHelper::from_u32(helper) {
                Some(BpfHelper::GetLocalStorage) => VerifierType::Ptr {
                    space: AddressSpace::Map,
                    nullability: Nullability::NonNull,
                    bounds: map_value_limit_from_dst_type(
                        types.get(&dst),
                        "get_local_storage return value type",
                        errors,
                    )
                    .map(|limit| PtrBounds::new(PtrOrigin::Map(dst), 0, 0, limit)),
                    ringbuf_ref: None,
                    kfunc_ref: None,
                },
                _ => match types.get(&dst).map(verifier_type_from_mir) {
                    Some(VerifierType::Ptr {
                        space,
                        bounds,
                        ringbuf_ref,
                        kfunc_ref,
                        ..
                    }) => VerifierType::Ptr {
                        space,
                        nullability: Nullability::NonNull,
                        bounds,
                        ringbuf_ref,
                        kfunc_ref,
                    },
                    _ => VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::NonNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    },
                },
            },
            HelperRetKind::PointerMaybeNull => match BpfHelper::from_u32(helper) {
                Some(BpfHelper::RingbufReserve) => {
                    state.set_live_ringbuf_ref(dst, true);
                    VerifierType::Ptr {
                        space: AddressSpace::Map,
                        nullability: Nullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: Some(dst),
                        kfunc_ref: None,
                    }
                }
                Some(BpfHelper::KptrXchg) => VerifierType::Ptr {
                    space: AddressSpace::Kernel,
                    nullability: Nullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                    kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                        state.set_live_kfunc_ref(dst, true, Some(kind));
                        dst
                    }),
                },
                Some(
                    BpfHelper::SkFullsock
                    | BpfHelper::TcpSock
                    | BpfHelper::SkcToTcp6Sock
                    | BpfHelper::SkcToTcpTimewaitSock
                    | BpfHelper::SkcToTcpRequestSock
                    | BpfHelper::SkcToUdp6Sock
                    | BpfHelper::SockFromFile
                    | BpfHelper::TaskPtRegs
                    | BpfHelper::SkcToTcpSock
                    | BpfHelper::PerCpuPtr
                    | BpfHelper::GetListenerSock,
                ) => VerifierType::Ptr {
                    space: AddressSpace::Kernel,
                    nullability: Nullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                },
                Some(_) if helper_kfunc_acquire_kind.is_some() => VerifierType::Ptr {
                    space: AddressSpace::Kernel,
                    nullability: Nullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                    kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                        state.set_live_kfunc_ref(dst, true, Some(kind));
                        dst
                    }),
                },
                _ => {
                    let bounds = map_value_limit_from_dst_type(
                        types.get(&dst),
                        "helper return map value type",
                        errors,
                    )
                    .map(|limit| PtrBounds::new(PtrOrigin::Map(dst), 0, 0, limit));
                    VerifierType::Ptr {
                        space: AddressSpace::Map,
                        nullability: Nullability::MaybeNull,
                        bounds,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    }
                }
            },
        };
        let range = helper_return_range_for_type(ty, types, dst);
        state.set_with_range(dst, ty, range);
        return;
    }

    if args.len() > 5 {
        errors.push(VerifierTypeError::new(
            "BPF helpers support at most 5 arguments",
        ));
    }
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set_with_range(dst, ty, ValueRange::Unknown);
}

fn clear_stack_slot_value_ranges_for_helper_args(args: &[MirValue], state: &mut VerifierState) {
    for arg in args {
        match arg {
            MirValue::StackSlot(slot) => state.clear_stack_slot_value_range(*slot),
            MirValue::VReg(vreg)
                if matches!(
                    state.get(*vreg),
                    VerifierType::Ptr {
                        space: AddressSpace::Stack,
                        ..
                    }
                ) =>
            {
                state.clear_all_stack_slot_value_ranges();
                return;
            }
            MirValue::VReg(_) | MirValue::Const(_) => {}
        }
    }
}

fn clear_stack_slot_value_ranges_for_vreg_args(args: &[VReg], state: &mut VerifierState) {
    if args.iter().any(|vreg| {
        matches!(
            state.get(*vreg),
            VerifierType::Ptr {
                space: AddressSpace::Stack,
                ..
            }
        )
    }) {
        state.clear_all_stack_slot_value_ranges();
    }
}

pub(super) fn apply_call_kfunc_inst(
    dst: VReg,
    kfunc: &str,
    args: &[VReg],
    types: &HashMap<VReg, MirType>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !kfunc_allowed_while_lock_held(kfunc) {
        reject_call_if_kernel_lock_held(state, format!("kfunc '{}'", kfunc), errors);
    }

    if let Some(message) = probe_ctx.and_then(|ctx| ctx.kfunc_call_error(kfunc)) {
        errors.push(VerifierTypeError::new(message));
        let ty = types
            .get(&dst)
            .map(verifier_type_from_mir)
            .unwrap_or(VerifierType::Scalar);
        state.set_with_range(dst, ty, ValueRange::Unknown);
        return;
    }

    let Some(sig) = KfuncSignature::for_name_or_kernel_btf(kfunc) else {
        errors.push(VerifierTypeError::new(unknown_kfunc_signature_message(
            kfunc,
        )));
        return;
    };
    if args.len() < sig.min_args || args.len() > sig.max_args {
        errors.push(VerifierTypeError::new(format!(
            "kfunc '{}' expects {}..={} args, got {}",
            kfunc,
            sig.min_args,
            sig.max_args,
            args.len()
        )));
    }
    if args.len() > 5 {
        errors.push(VerifierTypeError::new(
            "BPF kfunc calls support at most 5 arguments",
        ));
    }
    for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
        check_kfunc_arg(
            kfunc,
            idx,
            *arg,
            sig.arg_kind(idx),
            types,
            state,
            program,
            probe_ctx,
            errors,
        );
    }
    check_kfunc_semantics(kfunc, args, types, state, errors);
    apply_kfunc_semantics(kfunc, args, types, state, errors);
    clear_stack_slot_value_ranges_for_vreg_args(args, state);

    let ty = match sig.ret_kind {
        KfuncRetKind::Scalar | KfuncRetKind::Void => types
            .get(&dst)
            .map(verifier_type_from_mir)
            .unwrap_or(VerifierType::Scalar),
        KfuncRetKind::PointerMaybeNull => {
            let acquire_kind = kfunc_acquire_kind(kfunc);
            if let Some(kind) = acquire_kind {
                state.set_live_kfunc_ref(dst, true, Some(kind));
            }
            let trusted_btf_return = matches!(
                types.get(&dst),
                Some(MirType::Ptr {
                    pointee,
                    address_space: AddressSpace::Kernel,
                }) if !matches!(pointee.as_ref(), MirType::Unknown)
            );
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability: Nullability::MaybeNull,
                bounds: trusted_btf_return.then(|| {
                    PtrBounds::new(PtrOrigin::KernelBtf(dst), 0, 0, UNKNOWN_KERNEL_BTF_LIMIT)
                }),
                ringbuf_ref: None,
                kfunc_ref: if acquire_kind.is_some() {
                    Some(dst)
                } else {
                    None
                },
            }
        }
    };
    state.set_with_range(dst, ty, ValueRange::Unknown);
}

pub(super) fn apply_call_subfn_inst(
    dst: VReg,
    subfn: SubfunctionId,
    args: &[VReg],
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionSummary>,
    probe_ctx: Option<&ProbeContext>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    reject_call_if_kernel_lock_held(state, format!("subfunction '{}'", subfn), errors);

    if args.len() > 5 {
        errors.push(VerifierTypeError::new(format!(
            "BPF subfunctions support at most 5 arguments, got {}",
            args.len()
        )));
    }
    let summary = subfn_summaries
        .get(&subfn)
        .cloned()
        .unwrap_or_else(SubfunctionSummary::unknown);

    if summary.changes_packet_data() {
        state.invalidate_packet_pointers();
    }

    apply_subfunction_critical_delta(&summary, args, state, errors);
    apply_subfunction_release_summary(&summary, args, state, errors);
    apply_subfunction_map_value_map_fd_requirements(&summary, args, state, errors);
    clear_stack_slot_value_ranges_for_vreg_args(args, state);

    if let Some(idx) = summary.return_arg()
        && let Some(arg) = args.get(idx)
    {
        apply_copy_inst(dst, &MirValue::VReg(*arg), types, slot_sizes, state);
        return;
    }

    if summary.returns_ringbuf_record() {
        state.set_live_ringbuf_ref(dst, true);
        state.set_with_range(
            dst,
            VerifierType::Ptr {
                space: AddressSpace::Map,
                nullability: Nullability::MaybeNull,
                bounds: None,
                ringbuf_ref: Some(dst),
                kfunc_ref: None,
            },
            ValueRange::Unknown,
        );
        return;
    }

    if let Some(kind) = summary.kfunc_ref_return_kind() {
        state.set_live_kfunc_ref(dst, true, Some(kind));
        let trusted_btf_return = matches!(
            types.get(&dst),
            Some(MirType::Ptr {
                pointee,
                address_space: AddressSpace::Kernel,
            }) if !matches!(pointee.as_ref(), MirType::Unknown)
        );
        state.set_with_range(
            dst,
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability: Nullability::MaybeNull,
                bounds: trusted_btf_return.then(|| {
                    PtrBounds::new(PtrOrigin::KernelBtf(dst), 0, 0, UNKNOWN_KERNEL_BTF_LIMIT)
                }),
                ringbuf_ref: None,
                kfunc_ref: Some(dst),
            },
            ValueRange::Unknown,
        );
        return;
    }

    if let Some(field) = summary.return_context_field() {
        let mut ty = types
            .get(&dst)
            .map(verifier_type_from_mir)
            .unwrap_or(VerifierType::Scalar);
        match field {
            CtxField::Data | CtxField::DataMeta => {
                if let VerifierType::Ptr {
                    space: AddressSpace::Packet,
                    nullability,
                    bounds: None,
                    ..
                } = ty
                {
                    ty = VerifierType::Ptr {
                        space: AddressSpace::Packet,
                        nullability,
                        bounds: Some(PtrBounds::new(
                            PtrOrigin::Packet(dst),
                            0,
                            0,
                            UNKNOWN_PACKET_LIMIT,
                        )),
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    };
                }
            }
            CtxField::SockoptOptval => {
                if let VerifierType::Ptr {
                    space: AddressSpace::Kernel,
                    nullability,
                    bounds: None,
                    ..
                } = ty
                {
                    ty = VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability,
                        bounds: Some(PtrBounds::new(
                            PtrOrigin::ContextBuffer(dst),
                            0,
                            0,
                            UNKNOWN_CONTEXT_BUFFER_LIMIT,
                        )),
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    };
                }
            }
            _ => {}
        }
        if ProbeContext::resolve_ctx_field_pointer_is_non_null(probe_ctx, field)
            && let VerifierType::Ptr {
                space,
                bounds,
                ringbuf_ref,
                kfunc_ref,
                ..
            } = ty
        {
            ty = VerifierType::Ptr {
                space,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref,
                kfunc_ref,
            };
        }
        if ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(probe_ctx, field)
            && let VerifierType::Ptr {
                space: AddressSpace::Kernel,
                ringbuf_ref,
                kfunc_ref,
                ..
            } = ty
        {
            ty = VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability: Nullability::NonNull,
                bounds: Some(PtrBounds::new(
                    PtrOrigin::KernelBtf(dst),
                    0,
                    0,
                    UNKNOWN_KERNEL_BTF_LIMIT,
                )),
                ringbuf_ref,
                kfunc_ref,
            };
        }
        if ProbeContext::resolve_ctx_field_is_raw_context_pointer(probe_ctx, field)
            && let VerifierType::Ptr {
                space,
                bounds,
                ringbuf_ref,
                kfunc_ref,
                ..
            } = ty
        {
            ty = VerifierType::Ptr {
                space,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref,
                kfunc_ref,
            };
        }
        state.set_with_range(dst, ty, ValueRange::Unknown);
        state.set_ctx_field_source(dst, Some(field.clone()));
        if matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
            state.set_scalar_expr_fact(dst, Some(ScalarExprFact::CtxField(field.clone())));
        }
        return;
    }

    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set_with_range(dst, ty, ValueRange::Unknown);
}

fn apply_subfunction_critical_delta(
    summary: &SubfunctionSummary,
    args: &[VReg],
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for _ in 0..summary.rcu_read_lock_delta().max(0) {
        state.acquire_rcu_read_lock();
    }
    for _ in 0..summary.rcu_read_lock_delta().saturating_neg() {
        if !state.release_rcu_read_lock() {
            errors.push(VerifierTypeError::new(
                "subfunction requires a matching bpf_rcu_read_lock",
            ));
        }
    }
    for _ in 0..summary.preempt_disable_delta().max(0) {
        state.acquire_preempt_disable();
    }
    for _ in 0..summary.preempt_disable_delta().saturating_neg() {
        if !state.release_preempt_disable() {
            errors.push(VerifierTypeError::new(
                "subfunction requires a matching bpf_preempt_disable",
            ));
        }
    }
    for idx in 0..5 {
        let delta = summary.local_irq_delta_arg(idx);
        if delta == 0 {
            continue;
        }
        let Some(arg) = args.get(idx).copied() else {
            errors.push(VerifierTypeError::new(format!(
                "subfunction arg{} local irq flags argument is missing",
                idx
            )));
            continue;
        };
        let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
            errors.push(VerifierTypeError::new(format!(
                "subfunction arg{} expects local irq flags stack slot pointer",
                idx
            )));
            continue;
        };
        for _ in 0..delta.max(0) {
            state.acquire_local_irq_disable_slot(slot);
        }
        for _ in 0..delta.saturating_neg() {
            if !state.release_local_irq_disable_slot(slot) {
                errors.push(VerifierTypeError::new(
                    "subfunction requires a matching bpf_local_irq_save",
                ));
            }
        }
    }
    for idx in 0..5 {
        let Some(delta) = summary.iter_delta_arg(idx) else {
            continue;
        };
        let Some(arg) = args.get(idx).copied() else {
            errors.push(VerifierTypeError::new(format!(
                "subfunction arg{} iterator argument is missing",
                idx
            )));
            continue;
        };
        let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
            errors.push(VerifierTypeError::new(format!(
                "subfunction arg{} expects {} stack slot pointer",
                idx,
                delta.family.stack_object_type_name()
            )));
            continue;
        };
        let op = if delta.delta > 0 {
            KfuncIterLifecycleOp::New
        } else {
            KfuncIterLifecycleOp::Destroy
        };
        let kfunc = if delta.delta > 0 {
            "subfunction"
        } else {
            "subfunction destroy"
        };
        for _ in 0..delta.delta.unsigned_abs() {
            if let Err(failure) = apply_iter_lifecycle_op(state, delta.family, op, slot) {
                errors.push(VerifierTypeError::new(iter_lifecycle_error_message(
                    kfunc,
                    delta.family,
                    failure,
                )));
            }
        }
    }
}

fn apply_subfunction_release_summary(
    summary: &SubfunctionSummary,
    args: &[VReg],
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for idx in 0..5 {
        let Some(arg) = args.get(idx).copied() else {
            continue;
        };
        if summary.releases_ringbuf_record_arg(idx) {
            release_subfunction_ringbuf_record_arg(idx, arg, state, errors);
        }
        if summary.requires_initialized_dynptr_arg(idx) {
            require_subfunction_dynptr_arg(idx, arg, state, errors);
        }
        let dynptr_delta = summary.dynptr_delta_arg(idx);
        for _ in 0..dynptr_delta.max(0) {
            initialize_subfunction_dynptr_arg(idx, arg, state, errors);
        }
        for _ in 0..dynptr_delta.saturating_neg() {
            deinitialize_subfunction_dynptr_arg(idx, arg, state, errors);
        }
        if summary.maybe_initializes_dynptr_arg(idx) {
            mark_subfunction_dynptr_arg_maybe_initialized(idx, arg, state, errors);
        }
        if let Some(object_type) = summary.unknown_stack_object_required_arg(idx) {
            require_subfunction_unknown_stack_object_arg(idx, arg, object_type, state, errors);
        }
        if let Some(delta) = summary.unknown_stack_object_delta_arg(idx) {
            for _ in 0..delta.delta.max(0) {
                initialize_subfunction_unknown_stack_object_arg(
                    idx,
                    arg,
                    &delta.object_type,
                    state,
                    errors,
                );
            }
            for _ in 0..delta.delta.saturating_neg() {
                destroy_subfunction_unknown_stack_object_arg(
                    idx,
                    arg,
                    &delta.object_type,
                    state,
                    errors,
                );
            }
        }
        if let Some(object_type) = summary.unknown_stack_object_maybe_initialized_arg(idx) {
            mark_subfunction_unknown_stack_object_arg_maybe_initialized(
                idx,
                arg,
                object_type,
                state,
                errors,
            );
        }
        let dynptr_delta = summary.ringbuf_dynptr_delta_arg(idx);
        for _ in 0..dynptr_delta.max(0) {
            acquire_subfunction_ringbuf_dynptr_arg(idx, arg, state, errors);
        }
        for _ in 0..dynptr_delta.saturating_neg() {
            release_subfunction_ringbuf_dynptr_arg(idx, arg, state, errors);
        }
        if let Some(kind) = summary.kfunc_ref_release_arg_kind(idx) {
            release_subfunction_kfunc_ref_arg(idx, arg, kind, state, errors);
        }
    }
}

fn apply_subfunction_map_value_map_fd_requirements(
    summary: &SubfunctionSummary,
    args: &[VReg],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for requirement in summary.map_value_map_fd_requirements() {
        let Some(map_fd_source) =
            subfunction_map_fd_requirement_source(&requirement.map_fd, args, state, errors)
        else {
            continue;
        };
        if subfunction_map_value_requirement_is_ambiguous(&requirement.map_value, args, state) {
            errors.push(VerifierTypeError::new(format!(
                "{} {} may come from multiple maps and cannot be matched to {} '{}'",
                requirement.call,
                subfunction_map_source_label(
                    &requirement.map_value,
                    SubfunctionMapSourceRole::MapValue
                ),
                subfunction_map_source_label(&requirement.map_fd, SubfunctionMapSourceRole::MapFd),
                map_fd_source.name
            )));
            continue;
        }
        let Some(map_value_source) =
            subfunction_map_value_requirement_source(&requirement.map_value, args, state, errors)
        else {
            continue;
        };
        if map_value_source != map_fd_source {
            errors.push(VerifierTypeError::new(format!(
                "{} {} '{}' does not match {} '{}'",
                requirement.call,
                subfunction_map_source_label(&requirement.map_fd, SubfunctionMapSourceRole::MapFd),
                map_fd_source.name,
                subfunction_map_source_label(
                    &requirement.map_value,
                    SubfunctionMapSourceRole::MapValue
                ),
                map_value_source.name
            )));
        }
    }
}

#[derive(Clone, Copy)]
enum SubfunctionMapSourceRole {
    MapValue,
    MapFd,
}

fn subfunction_map_fd_requirement_source(
    source: &SubfunctionMapSource,
    args: &[VReg],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<MapRef> {
    match source {
        SubfunctionMapSource::Arg(idx) => {
            let Some(arg) = args.get(*idx).copied() else {
                errors.push(VerifierTypeError::new(format!(
                    "subfunction arg{} map fd argument is missing",
                    idx
                )));
                return None;
            };
            state.map_fd_source(arg).cloned()
        }
        SubfunctionMapSource::Map(map) => Some(map.clone()),
    }
}

fn subfunction_map_value_requirement_source(
    source: &SubfunctionMapSource,
    args: &[VReg],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<MapRef> {
    match source {
        SubfunctionMapSource::Arg(idx) => {
            let Some(arg) = args.get(*idx).copied() else {
                errors.push(VerifierTypeError::new(format!(
                    "subfunction arg{} map value argument is missing",
                    idx
                )));
                return None;
            };
            state.map_value_source(arg).map(|source| source.map.clone())
        }
        SubfunctionMapSource::Map(map) => Some(map.clone()),
    }
}

fn subfunction_map_value_requirement_is_ambiguous(
    source: &SubfunctionMapSource,
    args: &[VReg],
    state: &VerifierState,
) -> bool {
    let SubfunctionMapSource::Arg(idx) = source else {
        return false;
    };
    args.get(*idx)
        .copied()
        .is_some_and(|arg| state.map_value_source_is_ambiguous(arg))
}

fn subfunction_map_source_label(
    source: &SubfunctionMapSource,
    role: SubfunctionMapSourceRole,
) -> String {
    match (source, role) {
        (SubfunctionMapSource::Arg(idx), SubfunctionMapSourceRole::MapValue) => {
            format!("arg{} map value", idx)
        }
        (SubfunctionMapSource::Arg(idx), SubfunctionMapSourceRole::MapFd) => {
            format!("arg{} map", idx)
        }
        (SubfunctionMapSource::Map(_), SubfunctionMapSourceRole::MapValue) => {
            "map value".to_string()
        }
        (SubfunctionMapSource::Map(_), SubfunctionMapSourceRole::MapFd) => "map".to_string(),
    }
}

fn release_subfunction_ringbuf_record_arg(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if state.is_released_ringbuf_record(arg) {
        return;
    }
    match state.get(arg) {
        VerifierType::Ptr {
            space: AddressSpace::Map,
            nullability: Nullability::NonNull,
            ringbuf_ref: Some(ref_id),
            ..
        } => {
            if state.is_live_ringbuf_ref(ref_id) {
                state.invalidate_ringbuf_ref(ref_id);
            } else {
                errors.push(VerifierTypeError::new(format!(
                    "subfunction arg{} ringbuf record already released",
                    idx
                )));
            }
        }
        VerifierType::Ptr {
            nullability: Nullability::MaybeNull,
            ..
        } => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} may dereference null ringbuf record pointer v{} (add a null check)",
            idx, arg.0
        ))),
        VerifierType::Ptr { .. } => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects ringbuf record pointer",
            idx
        ))),
        _ => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects ringbuf record pointer",
            idx
        ))),
    }
}

fn require_subfunction_dynptr_arg(
    idx: usize,
    arg: VReg,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if !state.is_dynptr_slot_initialized(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires initialized dynptr stack object",
            idx
        )));
    }
}

fn initialize_subfunction_dynptr_arg(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if state.is_dynptr_slot_maybe_initialized(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires uninitialized dynptr stack object slot",
            idx
        )));
        return;
    }
    state.initialize_dynptr_slot(slot);
}

fn deinitialize_subfunction_dynptr_arg(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if !state.is_dynptr_slot_initialized(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires initialized dynptr stack object",
            idx
        )));
        return;
    }
    state.deinitialize_dynptr_slot(slot);
}

fn mark_subfunction_dynptr_arg_maybe_initialized(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    state.mark_dynptr_slot_maybe_initialized(slot);
}

fn require_subfunction_unknown_stack_object_arg(
    idx: usize,
    arg: VReg,
    object_type: &SubfunctionUnknownStackObjectType,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if !state.has_unknown_stack_object_slot(slot, &object_type.type_name, object_type.type_id) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires initialized {} stack object",
            idx, object_type.type_name
        )));
    }
}

fn initialize_subfunction_unknown_stack_object_arg(
    idx: usize,
    arg: VReg,
    object_type: &SubfunctionUnknownStackObjectType,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if state.has_live_unknown_stack_object_slot(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires uninitialized {} stack object slot",
            idx, object_type.type_name
        )));
        return;
    }
    state.initialize_unknown_stack_object_slot(slot, &object_type.type_name, object_type.type_id);
}

fn destroy_subfunction_unknown_stack_object_arg(
    idx: usize,
    arg: VReg,
    object_type: &SubfunctionUnknownStackObjectType,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if !state.release_unknown_stack_object_slot(slot, &object_type.type_name, object_type.type_id) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires initialized {} stack object",
            idx, object_type.type_name
        )));
    }
}

fn mark_subfunction_unknown_stack_object_arg_maybe_initialized(
    idx: usize,
    arg: VReg,
    object_type: &SubfunctionUnknownStackObjectType,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    state.mark_unknown_stack_object_slot_maybe_initialized(
        slot,
        &object_type.type_name,
        object_type.type_id,
    );
}

fn acquire_subfunction_ringbuf_dynptr_arg(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if state.is_dynptr_slot_maybe_initialized(slot) || state.has_live_ringbuf_dynptr_slot(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires uninitialized dynptr stack object slot",
            idx
        )));
        return;
    }
    state.initialize_dynptr_slot(slot);
    state.acquire_ringbuf_dynptr_slot(slot);
}

fn release_subfunction_ringbuf_dynptr_arg(
    idx: usize,
    arg: VReg,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(slot) = stack_slot_base_from_vreg(arg, state) else {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects stack slot base pointer",
            idx
        )));
        return;
    };
    if state.is_released_ringbuf_dynptr_slot(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} ringbuf dynptr reservation already released",
            idx
        )));
        return;
    }
    if !state.is_dynptr_slot_initialized(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires initialized dynptr stack object",
            idx
        )));
        return;
    }
    if !state.has_ringbuf_dynptr_slot(slot) {
        errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} requires live ringbuf dynptr reservation",
            idx
        )));
        return;
    }
    state.release_ringbuf_dynptr_slot(slot);
    state.deinitialize_dynptr_slot(slot);
}

fn stack_slot_base_from_vreg(arg: VReg, state: &VerifierState) -> Option<StackSlotId> {
    match state.get(arg) {
        VerifierType::Ptr {
            space: AddressSpace::Stack,
            bounds: Some(bounds),
            ..
        } => match bounds.origin() {
            PtrOrigin::Stack(slot) if bounds.min() == 0 && bounds.max() == 0 => Some(slot),
            _ => None,
        },
        _ => None,
    }
}

fn release_subfunction_kfunc_ref_arg(
    idx: usize,
    arg: VReg,
    expected_kind: KfuncRefKind,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if state.is_released_kfunc_ref(arg) {
        return;
    }
    match state.get(arg) {
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::NonNull,
            kfunc_ref: Some(ref_id),
            ..
        } => {
            if !state.is_live_kfunc_ref(ref_id) {
                errors.push(VerifierTypeError::new(format!(
                    "subfunction arg{} reference already released",
                    idx
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
                    "subfunction arg{} expects acquired {} reference, got {} reference",
                    idx, expected, actual
                )));
            }
        }
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::MaybeNull,
            ..
        } => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} may dereference null pointer v{} (add a null check)",
            idx, arg.0
        ))),
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ..
        } => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects acquired {} reference",
            idx,
            expected_kind.label()
        ))),
        VerifierType::Ptr { space, .. } => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects kernel pointer, got {:?}",
            idx, space
        ))),
        _ => errors.push(VerifierTypeError::new(format!(
            "subfunction arg{} expects acquired {} reference pointer",
            idx,
            expected_kind.label()
        ))),
    }
}
