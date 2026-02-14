fn apply_inst(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            let ty = value_type(src, state, slot_sizes);
            let range = value_range(src, state);
            let src_ctx_field = match src {
                MirValue::VReg(vreg) => state.ctx_field_source(*vreg).cloned(),
                _ => None,
            };
            let src_guard = match src {
                MirValue::VReg(vreg) => state.guards.get(vreg).copied(),
                _ => None,
            };
            let src_non_zero = match src {
                MirValue::VReg(vreg) => state.is_non_zero(*vreg),
                MirValue::Const(value) => *value != 0,
                _ => false,
            };
            let src_not_equal = match src {
                MirValue::VReg(vreg) => state.not_equal_consts(*vreg).to_vec(),
                MirValue::Const(value) if *value != 0 => vec![0],
                _ => Vec::new(),
            };
            state.set_with_range(*dst, ty, range);
            state.set_ctx_field_source(*dst, src_ctx_field);
            if src_non_zero {
                if let Some(slot) = state.non_zero.get_mut(dst.0 as usize) {
                    *slot = true;
                }
            }
            for excluded in src_not_equal {
                state.set_not_equal_const(*dst, excluded);
            }
            if let Some(guard) = src_guard {
                state.guards.insert(*dst, guard);
            }
        }
        MirInst::Load {
            dst, ptr, offset, ..
        } => {
            let access_size = types.get(dst).map(|ty| ty.size()).unwrap_or(8);
            check_ptr_access(
                *ptr,
                "load",
                &[AddressSpace::Stack, AddressSpace::Map],
                *offset,
                access_size,
                state,
                errors,
            );
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::Store {
            ptr, offset, ty, ..
        } => {
            let access_size = ty.size();
            check_ptr_access(
                *ptr,
                "store",
                &[AddressSpace::Stack, AddressSpace::Map],
                *offset,
                access_size,
                state,
                errors,
            );
        }
        MirInst::LoadSlot { dst, .. } => {
            if let MirInst::LoadSlot {
                slot, offset, ty, ..
            } = inst
            {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "load slot", errors);
            }
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::StoreSlot { .. } => {
            if let MirInst::StoreSlot {
                slot, offset, ty, ..
            } = inst
            {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "store slot", errors);
            }
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
            if matches!(
                op,
                BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge
            ) {
                state.set_with_range(
                    *dst,
                    VerifierType::Bool,
                    ValueRange::Known { min: 0, max: 1 },
                );
                if let Some(guard) = guard_from_compare(*op, lhs, rhs, state) {
                    state.guards.insert(*dst, guard);
                }
            } else {
                if let Some(ty) = pointer_arith_result(*op, lhs, rhs, state, slot_sizes) {
                    state.set(*dst, ty);
                } else {
                    let range = range_for_binop(*op, lhs, rhs, state);
                    state.set_with_range(*dst, VerifierType::Scalar, range);
                }
            }
        }
        MirInst::UnaryOp { op, .. } => {
            let ty = match op {
                super::mir::UnaryOpKind::Not => VerifierType::Bool,
                _ => VerifierType::Scalar,
            };
            if let Some(dst) = inst.def() {
                let guard = if matches!(op, super::mir::UnaryOpKind::Not) {
                    if let MirInst::UnaryOp { src, .. } = inst {
                        if let MirValue::VReg(src_reg) = src {
                            state.guards.get(src_reg).copied().and_then(invert_guard)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                let range = if matches!(op, super::mir::UnaryOpKind::Not) {
                    ValueRange::Known { min: 0, max: 1 }
                } else {
                    ValueRange::Unknown
                };
                state.set_with_range(dst, ty, range);
                if let Some(guard) = guard {
                    state.guards.insert(dst, guard);
                }
            }
        }
        MirInst::CallHelper { dst, helper, args } => {
            if let Some(sig) = HelperSignature::for_id(*helper) {
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
                        *helper,
                        idx,
                        arg,
                        sig.arg_kind(idx),
                        state,
                        slot_sizes,
                        errors,
                    );
                }
                let helper_kfunc_acquire_kind =
                    apply_helper_semantics(*helper, args, state, slot_sizes, errors);

                let ty = match sig.ret_kind {
                    HelperRetKind::Scalar => types
                        .get(dst)
                        .map(verifier_type_from_mir)
                        .unwrap_or(VerifierType::Scalar),
                    HelperRetKind::PointerMaybeNull => match BpfHelper::from_u32(*helper) {
                        Some(BpfHelper::RingbufReserve) => {
                            state.set_live_ringbuf_ref(*dst, true);
                            VerifierType::Ptr {
                                space: AddressSpace::Map,
                                nullability: Nullability::MaybeNull,
                                bounds: None,
                                ringbuf_ref: Some(*dst),
                                kfunc_ref: None,
                            }
                        }
                        Some(BpfHelper::KptrXchg) => VerifierType::Ptr {
                            space: AddressSpace::Kernel,
                            nullability: Nullability::MaybeNull,
                            bounds: None,
                            ringbuf_ref: None,
                            kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                                state.set_live_kfunc_ref(*dst, true, Some(kind));
                                *dst
                            }),
                        },
                        Some(BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp) => {
                            VerifierType::Ptr {
                                space: AddressSpace::Kernel,
                                nullability: Nullability::MaybeNull,
                                bounds: None,
                                ringbuf_ref: None,
                                kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                                    state.set_live_kfunc_ref(*dst, true, Some(kind));
                                    *dst
                                }),
                            }
                        }
                        _ => {
                            let bounds =
                                map_value_limit_from_dst_type(types.get(dst)).map(|limit| {
                                    PtrBounds {
                                        origin: PtrOrigin::Map,
                                        min: 0,
                                        max: 0,
                                        limit,
                                    }
                                });
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
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            } else {
                if args.len() > 5 {
                    errors.push(VerifierTypeError::new(
                        "BPF helpers support at most 5 arguments",
                    ));
                }
                let ty = types
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar);
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            }
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            let Some(sig) = KfuncSignature::for_name(kfunc) else {
                errors.push(VerifierTypeError::new(format!(
                    "unknown kfunc '{}' (typed signature required)",
                    kfunc
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
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar),
                KfuncRetKind::PointerMaybeNull => {
                    let acquire_kind = kfunc_acquire_kind(kfunc);
                    if let Some(kind) = acquire_kind {
                        state.set_live_kfunc_ref(*dst, true, Some(kind));
                    }
                    VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: if acquire_kind.is_some() {
                            Some(*dst)
                        } else {
                            None
                        },
                    }
                }
            };
            state.set_with_range(*dst, ty, ValueRange::Unknown);
        }
        MirInst::CallSubfn { dst, args, .. } => {
            if args.len() > 5 {
                errors.push(VerifierTypeError::new(format!(
                    "BPF subfunctions support at most 5 arguments, got {}",
                    args.len()
                )));
            }
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set_with_range(*dst, ty, ValueRange::Unknown);
        }
        MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::Phi { dst, .. } => {
            let phi_guard = if let MirInst::Phi { args, .. } = inst {
                let mut merged: Option<Option<Guard>> = None;
                for (_, reg) in args {
                    let next = state.guards.get(reg).copied();
                    merged = Some(match merged {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged, Some(None)) {
                        break;
                    }
                }
                merged.flatten()
            } else {
                None
            };
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            let range = if let MirInst::Phi { args, .. } = inst {
                range_for_phi(args, state)
            } else {
                ValueRange::Unknown
            };
            let ty = if let MirInst::Phi { args, .. } = inst {
                ptr_type_for_phi(args, state).unwrap_or(ty)
            } else {
                ty
            };
            state.set_with_range(*dst, ty, range);
            if let Some(guard) = phi_guard {
                state.guards.insert(*dst, guard);
            }
        }
        MirInst::MapLookup { dst, map, key } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            check_map_operand_scalar_size(*key, "map key", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
            let bounds = map_value_limit(map)
                .or_else(|| map_value_limit_from_dst_type(types.get(dst)))
                .map(|limit| PtrBounds {
                    origin: PtrOrigin::Map,
                    min: 0,
                    max: 0,
                    limit,
                });
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Map,
                    nullability: Nullability::MaybeNull,
                    bounds,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                },
            );
        }
        MirInst::ListNew { dst, buffer, .. } => {
            let bounds = slot_sizes.get(buffer).copied().map(|limit| PtrBounds {
                origin: PtrOrigin::Stack(*buffer),
                min: 0,
                max: 0,
                limit,
            });
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability: Nullability::NonNull,
                    bounds,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                },
            );
        }
        MirInst::ListLen { dst, list } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::ListGet { dst, list, .. } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::LoadCtxField { dst, field, slot } => {
            let mut ty = state.find_ctx_field_type(field).unwrap_or_else(|| {
                types
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar)
            });
            if let (
                VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability,
                    ..
                },
                Some(slot),
            ) = (ty, slot)
            {
                let bounds = slot_sizes.get(slot).copied().map(|limit| PtrBounds {
                    origin: PtrOrigin::Stack(*slot),
                    min: 0,
                    max: 0,
                    limit,
                });
                ty = VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability,
                    bounds,
                    ringbuf_ref: None,
                    kfunc_ref: None,
                };
            }
            state.set(*dst, ty);
            state.set_ctx_field_source(*dst, Some(field.clone()));
        }
        MirInst::ReadStr {
            ptr, user_space, ..
        } => {
            let allowed = if *user_space {
                &[AddressSpace::User][..]
            } else {
                &[AddressSpace::Kernel, AddressSpace::Map, AddressSpace::Stack][..]
            };
            require_ptr_with_space(*ptr, "read_str", allowed, state, errors);
        }
        MirInst::EmitEvent { data, size } => {
            if *size > 8 {
                require_ptr_with_space(
                    *data,
                    "emit",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::EmitRecord { fields } => {
            for field in fields {
                if let Some(MirType::Array { .. }) | Some(MirType::Ptr { .. }) =
                    types.get(&field.value)
                {
                    require_ptr_with_space(
                        field.value,
                        "emit record",
                        &[AddressSpace::Stack, AddressSpace::Map],
                        state,
                        errors,
                    );
                }
            }
        }
        MirInst::MapUpdate {
            map,
            key,
            val,
            flags,
        } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            if *flags > i32::MAX as u64 {
                errors.push(VerifierTypeError::new(format!(
                    "map update flags {} exceed supported 32-bit immediate range",
                    flags
                )));
            }
            check_map_operand_scalar_size(*key, "map key", types, errors);
            check_map_operand_scalar_size(*val, "map value", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::MapDelete { map, key } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            } else if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
                errors.push(VerifierTypeError::new(format!(
                    "map delete is not supported for array map kind {:?} ('{}')",
                    map.kind, map.name
                )));
            }
            check_map_operand_scalar_size(*key, "map key", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { list, .. } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
        }
        MirInst::StringAppend { dst_len, .. } | MirInst::IntToString { dst_len, .. } => {
            let ty = state.get(*dst_len);
            if matches!(ty, VerifierType::Uninit) {
                errors.push(VerifierTypeError::new(format!(
                    "string length uses uninitialized v{}",
                    dst_len.0
                )));
            }
        }
        MirInst::RecordStore { val, ty, .. } => {
            if matches!(ty, MirType::Array { .. } | MirType::Ptr { .. }) {
                if let MirValue::VReg(vreg) = val {
                    require_ptr_with_space(
                        *vreg,
                        "record store",
                        &[AddressSpace::Stack, AddressSpace::Map],
                        state,
                        errors,
                    );
                }
            }
        }
    }
}

fn check_uses_initialized(
    inst: &MirInst,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for used in inst.uses() {
        if matches!(state.get(used), VerifierType::Uninit) {
            errors.push(VerifierTypeError::new(format!(
                "instruction uses uninitialized v{}",
                used.0
            )));
        }
    }
}

fn pointer_arith_result(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> Option<VerifierType> {
    if !matches!(op, BinOpKind::Add | BinOpKind::Sub) {
        return None;
    }

    let lhs_ty = value_type(lhs, state, slot_sizes);
    let rhs_ty = value_type(rhs, state, slot_sizes);

    let (ptr_ty, offset, is_add) = match op {
        BinOpKind::Add => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, true)
            }
            (VerifierType::Scalar | VerifierType::Bool, VerifierType::Ptr { .. }) => {
                (rhs_ty, lhs, true)
            }
            _ => return None,
        },
        BinOpKind::Sub => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, false)
            }
            _ => return None,
        },
        _ => return None,
    };

    let offset_range = value_range(offset, state);

    if let VerifierType::Ptr {
        space,
        nullability,
        bounds,
        ringbuf_ref,
        kfunc_ref,
    } = ptr_ty
    {
        let bounds = match (bounds, offset_range) {
            (Some(bounds), ValueRange::Known { min, max }) => {
                let (min_delta, max_delta) = if is_add { (min, max) } else { (-max, -min) };
                Some(PtrBounds {
                    origin: bounds.origin,
                    min: bounds.min.saturating_add(min_delta),
                    max: bounds.max.saturating_add(max_delta),
                    limit: bounds.limit,
                })
            }
            _ => None,
        };
        return Some(VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        });
    }

    None
}
