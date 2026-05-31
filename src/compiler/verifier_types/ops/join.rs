use super::*;

pub(in crate::compiler::verifier_types) fn join_type(
    a: VerifierType,
    b: VerifierType,
) -> VerifierType {
    use VerifierType::*;
    match (a, b) {
        (Uninit, other) | (other, Uninit) => clear_resource_refs_after_partial_join(other),
        (StalePacketPtr, _) | (_, StalePacketPtr) => StalePacketPtr,
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
            let ringbuf_ref = join_resource_ref_through_null(ra, na, rb, nb);
            let kfunc_ref = join_resource_ref_through_null(ka, na, kb, nb);
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

fn clear_resource_refs_after_partial_join(ty: VerifierType) -> VerifierType {
    match ty {
        // A resource pointer that exists on only one predecessor may keep its
        // pointer type, but ownership identity is no longer valid on all paths.
        VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ..
        } => VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
        other => other,
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
        (Some(a), Some(b)) if a.origin() == b.origin() && a.limit() == b.limit() => {
            Some(PtrBounds::new(
                a.origin(),
                a.min().min(b.min()),
                a.max().max(b.max()),
                a.limit(),
            ))
        }
        (Some(a), Some(b))
            if matches!(
                a.origin(),
                PtrOrigin::Packet(_) | PtrOrigin::ContextBuffer(_) | PtrOrigin::KernelBtf(_)
            ) && a.origin() == b.origin() =>
        {
            Some(PtrBounds::new(
                a.origin(),
                a.min().min(b.min()),
                a.max().max(b.max()),
                a.limit().max(b.limit()),
            ))
        }
        _ => None,
    }
}

fn join_resource_ref_through_null(
    a: Option<VReg>,
    a_nullability: Nullability,
    b: Option<VReg>,
    b_nullability: Nullability,
) -> Option<VReg> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(a), None) if b_nullability == Nullability::Null => Some(a),
        (None, Some(b)) if a_nullability == Nullability::Null => Some(b),
        _ => None,
    }
}
