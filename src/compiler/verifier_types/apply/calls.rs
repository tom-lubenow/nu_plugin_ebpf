use super::*;
use crate::compiler::instruction::unknown_kfunc_signature_message;

pub(super) fn apply_call_helper_inst(
    dst: VReg,
    helper: u32,
    args: &[MirValue],
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
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
                state,
                slot_sizes,
                errors,
            );
        }
        let helper_kfunc_acquire_kind =
            apply_helper_semantics(helper, args, state, slot_sizes, errors);

        let ty = match sig.ret_kind {
            HelperRetKind::Scalar => types
                .get(&dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar),
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
                        .map(|limit| PtrBounds::new(PtrOrigin::Map, 0, 0, limit));
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
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(sig) = KfuncSignature::for_name(kfunc) else {
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
        check_kfunc_arg(kfunc, idx, *arg, sig.arg_kind(idx), state, errors);
    }
    apply_kfunc_semantics(kfunc, args, state, errors);

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
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability: Nullability::MaybeNull,
                bounds: None,
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
    args: &[VReg],
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if args.len() > 5 {
        errors.push(VerifierTypeError::new(format!(
            "BPF subfunctions support at most 5 arguments, got {}",
            args.len()
        )));
    }
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set_with_range(dst, ty, ValueRange::Unknown);
}
