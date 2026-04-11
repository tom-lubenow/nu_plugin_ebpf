use super::*;

impl<'a> TypeInference<'a> {
    pub(in crate::compiler::type_infer) fn range_for_binop(
        &self,
        op: BinOpKind,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match op {
            BinOpKind::Add => self.range_add(lhs, rhs),
            BinOpKind::Sub => self.range_sub(lhs, rhs),
            BinOpKind::Mul => self.range_mul(lhs, rhs),
            BinOpKind::Div => self.range_div(lhs, rhs),
            BinOpKind::Mod => self.range_mod(lhs, rhs),
            BinOpKind::Shl => self.range_shift(lhs, rhs, true),
            BinOpKind::Shr => self.range_shift(lhs, rhs, false),
            BinOpKind::And => self.range_and(lhs, rhs),
            BinOpKind::Or => self.range_or(lhs, rhs),
            BinOpKind::Xor => self.range_xor(lhs, rhs),
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_for_unary(
        &self,
        op: UnaryOpKind,
        src: ValueRange,
    ) -> ValueRange {
        match op {
            UnaryOpKind::Neg => match src {
                ValueRange::Known { min, max } => ValueRange::known(-max, -min),
                ValueRange::Unknown | ValueRange::Unset => ValueRange::Unknown,
            },
            UnaryOpKind::Not => ValueRange::known(0, 1),
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_add(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(
                self.clamp_i128_to_i64((lmin as i128) + (rmin as i128)),
                self.clamp_i128_to_i64((lmax as i128) + (rmax as i128)),
            ),
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_sub(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(
                self.clamp_i128_to_i64((lmin as i128) - (rmax as i128)),
                self.clamp_i128_to_i64((lmax as i128) - (rmin as i128)),
            ),
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_mul(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        let (lmin, lmax, rmin, rmax) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => (lmin, lmax, rmin, rmax),
            _ => return ValueRange::Unknown,
        };
        let candidates = [
            (lmin as i128) * (rmin as i128),
            (lmin as i128) * (rmax as i128),
            (lmax as i128) * (rmin as i128),
            (lmax as i128) * (rmax as i128),
        ];
        let min = candidates.iter().copied().min().unwrap_or(0);
        let max = candidates.iter().copied().max().unwrap_or(0);
        ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
    }

    pub(in crate::compiler::type_infer) fn range_div(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => {
                if rhs_min <= 0 && rhs_max >= 0 {
                    return ValueRange::Unknown;
                }
                let candidates = [
                    (lhs_min as i128) / (rhs_min as i128),
                    (lhs_min as i128) / (rhs_max as i128),
                    (lhs_max as i128) / (rhs_min as i128),
                    (lhs_max as i128) / (rhs_max as i128),
                ];
                let min = candidates.iter().copied().min().unwrap_or(0);
                let max = candidates.iter().copied().max().unwrap_or(0);
                ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
            }
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_mod(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known { min: lhs_min, .. },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => {
                if rhs_min <= 0 || rhs_max <= 0 || lhs_min < 0 {
                    return ValueRange::Unknown;
                }
                ValueRange::known(0, rhs_max.saturating_sub(1))
            }
            _ => ValueRange::Unknown,
        }
    }

    pub(in crate::compiler::type_infer) fn range_and(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min & rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) & self.mask_for_max(rhs_max);
        let max = lhs_max.min(rhs_max).min(mask as i64);
        ValueRange::known(0, max)
    }

    pub(in crate::compiler::type_infer) fn range_or(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min | rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) | self.mask_for_max(rhs_max);
        let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
        ValueRange::known(0, max)
    }

    pub(in crate::compiler::type_infer) fn range_xor(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min ^ rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) | self.mask_for_max(rhs_max);
        let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
        ValueRange::known(0, max)
    }

    pub(in crate::compiler::type_infer) fn range_shift(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
        is_left: bool,
    ) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if rhs_min < 0 || rhs_max > 63 {
            return ValueRange::Unknown;
        }

        let mut min = i128::MAX;
        let mut max = i128::MIN;
        for lhs_val in [lhs_min, lhs_max] {
            for rhs_val in [rhs_min, rhs_max] {
                let shifted = if is_left {
                    (lhs_val as i128) << rhs_val
                } else {
                    (lhs_val as i128) >> rhs_val
                };
                min = min.min(shifted);
                max = max.max(shifted);
            }
        }

        ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
    }

    fn clamp_i128_to_i64(&self, value: i128) -> i64 {
        if value > i64::MAX as i128 {
            i64::MAX
        } else if value < i64::MIN as i128 {
            i64::MIN
        } else {
            value as i64
        }
    }

    fn mask_for_max(&self, max: i64) -> u64 {
        if max <= 0 {
            return 0;
        }
        let max = max as u64;
        if max == u64::MAX {
            return u64::MAX;
        }
        let bit = 64 - max.leading_zeros();
        if bit >= 64 {
            u64::MAX
        } else {
            (1u64 << bit) - 1
        }
    }
}
