use super::*;

pub(super) fn require_ptr_with_space(
    ptr: VReg,
    op: &str,
    allowed: &[AddressSpace],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<VerifierType> {
    match state.get(ptr) {
        VerifierType::Ptr {
            nullability: Nullability::NonNull,
            space,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        } => {
            if !allowed.contains(&space) {
                errors.push(VerifierTypeError::new(format!(
                    "{op} expects pointer in {:?}, got {:?}",
                    allowed, space
                )));
            }
            Some(VerifierType::Ptr {
                space,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref,
                kfunc_ref,
            })
        }
        VerifierType::Ptr {
            nullability: Nullability::Null,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "{op} uses null pointer v{}",
                ptr.0
            )));
            None
        }
        VerifierType::Ptr {
            nullability: Nullability::MaybeNull,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "{op} may dereference null pointer v{} (add a null check)",
                ptr.0
            )));
            None
        }
        VerifierType::Uninit => {
            errors.push(VerifierTypeError::new(format!(
                "{op} uses uninitialized pointer v{}",
                ptr.0
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
}

pub(super) fn check_ptr_bounds(
    op: &str,
    space: AddressSpace,
    bounds: Option<PtrBounds>,
    offset: i32,
    size: usize,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(bounds) = bounds else {
        return;
    };

    match (space, bounds.origin) {
        (AddressSpace::Stack, PtrOrigin::Stack(_)) | (AddressSpace::Map, PtrOrigin::Map) => {}
        _ => return,
    }

    let size = size as i64;
    let offset = offset as i64;
    let start = bounds.min.saturating_add(offset);
    let end = bounds
        .max
        .saturating_add(offset)
        .saturating_add(size.saturating_sub(1));

    if start < 0 || end > bounds.limit {
        let origin = match bounds.origin {
            PtrOrigin::Stack(slot) => format!("stack slot {}", slot.0),
            PtrOrigin::Map => "map value".to_string(),
        };
        errors.push(VerifierTypeError::new(format!(
            "{op} out of bounds for {origin}: access [{start}..{end}] exceeds 0..{}",
            bounds.limit
        )));
    }
}

pub(super) fn check_ptr_access(
    ptr: VReg,
    op: &str,
    allowed: &[AddressSpace],
    offset: i32,
    size: usize,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(VerifierType::Ptr { space, bounds, .. }) =
        require_ptr_with_space(ptr, op, allowed, state, errors)
    else {
        return;
    };
    check_ptr_bounds(op, space, bounds, offset, size, errors);
}

pub(super) fn check_slot_access(
    slot: StackSlotId,
    offset: i32,
    size: usize,
    slot_sizes: &HashMap<StackSlotId, i64>,
    op: &str,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(limit) = slot_sizes.get(&slot).copied() else {
        return;
    };
    let size = size as i64;
    let offset = offset as i64;
    let start = offset;
    let end = offset.saturating_add(size.saturating_sub(1));
    if start < 0 || end > limit {
        errors.push(VerifierTypeError::new(format!(
            "{op} out of bounds for stack slot {}: access [{start}..{end}] exceeds 0..{}",
            slot.0, limit
        )));
    }
}

pub(super) fn value_type(
    value: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> VerifierType {
    match value {
        MirValue::Const(_) => VerifierType::Scalar,
        MirValue::VReg(v) => state.get(*v),
        MirValue::StackSlot(slot) => {
            let bounds = slot_sizes.get(slot).copied().map(|limit| PtrBounds {
                origin: PtrOrigin::Stack(*slot),
                min: 0,
                max: 0,
                limit,
            });
            VerifierType::Ptr {
                space: AddressSpace::Stack,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref: None,
                kfunc_ref: None,
            }
        }
    }
}

pub(super) fn verifier_type_from_mir(ty: &MirType) -> VerifierType {
    match ty {
        MirType::Bool => VerifierType::Bool,
        MirType::Array { .. } => VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability: Nullability::NonNull,
            bounds: None,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
        MirType::Ptr { address_space, .. } => VerifierType::Ptr {
            space: *address_space,
            nullability: match address_space {
                AddressSpace::Stack => Nullability::NonNull,
                AddressSpace::Map => Nullability::MaybeNull,
                AddressSpace::Kernel | AddressSpace::User => Nullability::MaybeNull,
            },
            bounds: None,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
        MirType::Unknown => VerifierType::Unknown,
        _ => VerifierType::Scalar,
    }
}

pub(super) fn join_type(a: VerifierType, b: VerifierType) -> VerifierType {
    use VerifierType::*;
    match (a, b) {
        (Uninit, other) | (other, Uninit) => other,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Scalar, Scalar) => Scalar,
        (Bool, Bool) => Bool,
        (
            Ptr {
                space: sa,
                nullability: na,
                bounds: ba,
                ringbuf_ref: ra,
                kfunc_ref: ka,
            },
            Ptr {
                space: sb,
                nullability: nb,
                bounds: bb,
                ringbuf_ref: rb,
                kfunc_ref: kb,
            },
        ) => {
            if sa != sb {
                return Unknown;
            }
            let nullability = join_nullability(na, nb);
            let bounds = join_bounds(ba, bb);
            let ringbuf_ref = join_ringbuf_ref(ra, rb);
            let kfunc_ref = join_kfunc_ref(ka, kb);
            Ptr {
                space: sa,
                nullability,
                bounds,
                ringbuf_ref,
                kfunc_ref,
            }
        }
        (Scalar, Bool) | (Bool, Scalar) => Scalar,
        _ => Unknown,
    }
}

fn join_nullability(a: Nullability, b: Nullability) -> Nullability {
    match (a, b) {
        (Nullability::Null, Nullability::Null) => Nullability::Null,
        (Nullability::NonNull, Nullability::NonNull) => Nullability::NonNull,
        _ => Nullability::MaybeNull,
    }
}

fn join_bounds(a: Option<PtrBounds>, b: Option<PtrBounds>) -> Option<PtrBounds> {
    match (a, b) {
        (Some(a), Some(b)) if a.origin == b.origin && a.limit == b.limit => Some(PtrBounds {
            origin: a.origin,
            min: a.min.min(b.min),
            max: a.max.max(b.max),
            limit: a.limit,
        }),
        _ => None,
    }
}

fn join_ringbuf_ref(a: Option<VReg>, b: Option<VReg>) -> Option<VReg> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (None, None) => None,
        _ => None,
    }
}

fn join_kfunc_ref(a: Option<VReg>, b: Option<VReg>) -> Option<VReg> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (None, None) => None,
        _ => None,
    }
}
