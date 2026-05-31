use super::*;

pub(super) fn check_uses_initialized(
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

pub(super) fn pointer_arith_result(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
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
                let (min_delta, max_delta) = if is_add {
                    (min, max)
                } else {
                    (max.saturating_neg(), min.saturating_neg())
                };
                let new_min = bounds.min().saturating_add(min_delta);
                let new_max = bounds.max().saturating_add(max_delta);
                if new_min < 0 || new_max > bounds.limit() {
                    errors.push(VerifierTypeError::new("pointer arithmetic out of bounds"));
                    return Some(VerifierType::Unknown);
                }
                Some(PtrBounds::new(
                    bounds.origin(),
                    new_min,
                    new_max,
                    bounds.limit(),
                ))
            }
            (Some(_), ValueRange::Unknown) => {
                errors.push(VerifierTypeError::new(
                    "pointer arithmetic requires bounded scalar offset",
                ));
                return Some(VerifierType::Unknown);
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
