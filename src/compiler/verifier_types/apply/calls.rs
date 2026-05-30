use super::*;
use crate::compiler::instruction::{
    kfunc_allowed_while_lock_held, unknown_kfunc_signature_message,
};
use crate::compiler::mir::SubfunctionId;
use crate::compiler::subfn_summaries::SubfunctionSummary;
use crate::compiler::{ProbeContext, ProgramTypeInfo};

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
        state.set_with_range(dst, ty, ValueRange::Unknown);
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
                    bounds: map_value_limit_from_dst_type(types.get(&dst))
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
                    let bounds = map_value_limit_from_dst_type(types.get(&dst))
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
        state.set_with_range(dst, ty, ValueRange::Unknown);
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
        .copied()
        .unwrap_or_else(SubfunctionSummary::unknown);

    if summary.changes_packet_data() {
        state.invalidate_packet_pointers();
    }

    apply_subfunction_release_summary(&summary, args, state, errors);

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

    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set_with_range(dst, ty, ValueRange::Unknown);
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
        if summary.releases_ringbuf_dynptr_arg(idx) {
            release_subfunction_ringbuf_dynptr_arg(idx, arg, state, errors);
        }
        if let Some(kind) = summary.kfunc_ref_release_arg_kind(idx) {
            release_subfunction_kfunc_ref_arg(idx, arg, kind, state, errors);
        }
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
