use super::*;

pub(in crate::compiler::verifier_types) fn join_type(
    a: VerifierType,
    b: VerifierType,
) -> VerifierType {
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
        (Some(a), Some(b)) if a.origin() == b.origin() && a.limit() == b.limit() => {
            Some(PtrBounds::new(
                a.origin(),
                a.min().min(b.min()),
                a.max().max(b.max()),
                a.limit(),
            ))
        }
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
