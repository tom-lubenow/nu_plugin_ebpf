use super::*;

impl<'a> VccLowerer<'a> {
    pub(super) fn lower_value(&mut self, value: &MirValue, out: &mut Vec<VccInst>) -> VccValue {
        match value {
            MirValue::Const(v) => VccValue::Imm(*v),
            MirValue::VReg(v) => VccValue::Reg(VccReg(v.0)),
            MirValue::StackSlot(slot) => VccValue::Reg(self.stack_addr_temp(*slot, out)),
        }
    }

    pub(super) fn base_ptr_reg(&mut self, value: &MirValue, out: &mut Vec<VccInst>) -> VccReg {
        match value {
            MirValue::VReg(v) => VccReg(v.0),
            MirValue::StackSlot(slot) => self.stack_addr_temp(*slot, out),
            MirValue::Const(_) => self.temp_reg(),
        }
    }

    pub(super) fn stack_addr_temp(&mut self, slot: StackSlotId, out: &mut Vec<VccInst>) -> VccReg {
        let reg = self.temp_reg();
        let size = self.slot_sizes.get(&slot).copied().unwrap_or(0) as i64;
        out.push(VccInst::StackAddr {
            dst: reg,
            slot,
            size,
        });
        self.ptr_regs.insert(
            reg,
            VccPointerInfo {
                space: VccAddrSpace::Stack(slot),
                nullability: VccNullability::NonNull,
                bounds: stack_bounds(size),
                ringbuf_ref: None,
                kfunc_ref: None,
            },
        );
        reg
    }

    pub(super) fn temp_reg(&mut self) -> VccReg {
        let reg = VccReg(self.next_temp);
        self.next_temp += 1;
        reg
    }

    pub(super) fn value_ptr_info(&self, value: &MirValue) -> Option<VccPointerInfo> {
        match value {
            MirValue::StackSlot(slot) => {
                let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                Some(VccPointerInfo {
                    space: VccAddrSpace::Stack(*slot),
                    nullability: VccNullability::NonNull,
                    bounds: stack_bounds(size),
                    ringbuf_ref: None,
                    kfunc_ref: None,
                })
            }
            MirValue::VReg(v) => self
                .ptr_regs
                .get(&VccReg(v.0))
                .copied()
                .or_else(|| self.types.get(v).and_then(ptr_info_from_mir)),
            MirValue::Const(_) => None,
        }
    }

    pub(super) fn maybe_assume_type(&mut self, dst: VReg, ty: &MirType, out: &mut Vec<VccInst>) {
        let vcc_ty = vcc_type_from_mir(ty);
        if matches!(vcc_ty, VccValueType::Ptr(_) | VccValueType::Bool) {
            out.push(VccInst::Assume {
                dst: VccReg(dst.0),
                ty: vcc_ty,
            });
            if let VccValueType::Ptr(info) = vcc_ty {
                self.ptr_regs.insert(VccReg(dst.0), info);
            }
        }
    }

    pub(super) fn helper_return_type(&self, helper_id: u32, dst: VReg) -> VccValueType {
        let inferred = self.types.get(&dst).map(vcc_type_from_mir);
        let helper = BpfHelper::from_u32(helper_id);
        let Some(sig) = HelperSignature::for_id(helper_id) else {
            return inferred.unwrap_or(VccValueType::Unknown);
        };

        match sig.ret_kind {
            HelperRetKind::Scalar => inferred.unwrap_or(VccValueType::Scalar { range: None }),
            HelperRetKind::PointerMaybeNull => {
                if matches!(helper, Some(BpfHelper::RingbufReserve)) {
                    return VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::RingBuf,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: Some(VccReg(dst.0)),
                        kfunc_ref: None,
                    });
                }
                if matches!(helper, Some(BpfHelper::KptrXchg)) {
                    return VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::Kernel,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    });
                }
                if Self::helper_acquire_kind(helper_id).is_some() {
                    return VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::Kernel,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: Some(VccReg(dst.0)),
                    });
                }
                match inferred {
                    Some(VccValueType::Ptr(mut info)) => {
                        info.nullability = VccNullability::MaybeNull;
                        VccValueType::Ptr(info)
                    }
                    _ => VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::MapValue,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    }),
                }
            }
        }
    }

    pub(super) fn helper_acquire_kind(helper_id: u32) -> Option<KfuncRefKind> {
        BpfHelper::from_u32(helper_id).and_then(helper_acquire_ref_kind)
    }

    pub(super) fn helper_release_kind(helper_id: u32) -> Option<KfuncRefKind> {
        BpfHelper::from_u32(helper_id).and_then(helper_release_ref_kind)
    }

    pub(super) fn kfunc_return_type(&self, kfunc: &str, dst: VReg) -> VccValueType {
        let inferred = self.types.get(&dst).map(vcc_type_from_mir);
        let Some(sig) = KfuncSignature::for_name(kfunc) else {
            return inferred.unwrap_or(VccValueType::Unknown);
        };

        match sig.ret_kind {
            KfuncRetKind::Scalar | KfuncRetKind::Void => {
                inferred.unwrap_or(VccValueType::Scalar { range: None })
            }
            KfuncRetKind::PointerMaybeNull => match inferred {
                Some(VccValueType::Ptr(mut info)) => {
                    info.nullability = VccNullability::MaybeNull;
                    if Self::kfunc_acquire_kind(kfunc).is_some() {
                        info.kfunc_ref = Some(VccReg(dst.0));
                    }
                    VccValueType::Ptr(info)
                }
                _ => VccValueType::Ptr(VccPointerInfo {
                    space: VccAddrSpace::Kernel,
                    nullability: VccNullability::MaybeNull,
                    bounds: None,
                    ringbuf_ref: None,
                    kfunc_ref: if Self::kfunc_acquire_kind(kfunc).is_some() {
                        Some(VccReg(dst.0))
                    } else {
                        None
                    },
                }),
            },
        }
    }

    pub(super) fn kfunc_acquire_kind(kfunc: &str) -> Option<KfuncRefKind> {
        kfunc_acquire_ref_kind(kfunc)
    }

    pub(super) fn kfunc_release_kind(kfunc: &str) -> Option<KfuncRefKind> {
        kfunc_release_ref_kind(kfunc)
    }

    pub(super) fn maybe_assume_list_len(&mut self, dst: VReg, ptr: VReg, offset: i32, out: &mut Vec<VccInst>) {
        if offset != 0 {
            return;
        }
        let slot = match self.ptr_regs.get(&VccReg(ptr.0)) {
            Some(info) => match info.space {
                VccAddrSpace::Stack(slot) => Some(slot),
                _ => None,
            },
            None => None,
        };
        if let Some(slot) = slot {
            self.maybe_assume_list_len_slot(dst, slot, offset, out);
        }
    }

    pub(super) fn maybe_assume_list_len_slot(
        &self,
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        out: &mut Vec<VccInst>,
    ) {
        if offset != 0 {
            return;
        }
        let kind = self.slot_kinds.get(&slot).copied();
        if kind != Some(StackSlotKind::ListBuffer) {
            return;
        }
        let size = self.slot_sizes.get(&slot).copied().unwrap_or(0);
        let slot_cap = size / 8;
        if slot_cap == 0 {
            return;
        }
        let max_len = self
            .list_max
            .get(&slot)
            .copied()
            .unwrap_or(slot_cap.saturating_sub(1));
        let max_len = max_len.min(slot_cap.saturating_sub(1));
        let max = max_len.saturating_sub(1);
        out.push(VccInst::Assume {
            dst: VccReg(dst.0),
            ty: VccValueType::Scalar {
                range: Some(VccRange {
                    min: 0,
                    max: max as i64,
                }),
            },
        });
    }

    pub(super) fn assert_scalar_reg(&self, reg: VReg, out: &mut Vec<VccInst>) {
        out.push(VccInst::AssertScalar {
            value: VccValue::Reg(VccReg(reg.0)),
        });
    }

    pub(super) fn require_pointer_reg(&self, reg: VReg) -> Result<(), VccError> {
        let ty = self
            .types
            .get(&reg)
            .map(vcc_type_from_mir)
            .unwrap_or(VccValueType::Unknown);
        if ty.class() == VccTypeClass::Ptr || self.ptr_regs.contains_key(&VccReg(reg.0)) {
            return Ok(());
        }
        Err(VccError::new(
            VccErrorKind::TypeMismatch {
                expected: VccTypeClass::Ptr,
                actual: ty.class(),
            },
            "expected pointer value",
        ))
    }

    pub(super) fn check_ptr_range(
        &mut self,
        reg: VReg,
        size: usize,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if size == 0 {
            return Ok(());
        }
        self.require_pointer_reg(reg)?;
        out.push(VccInst::AssertPtrAccess {
            ptr: VccReg(reg.0),
            size: VccValue::Imm(size as i64),
            op: "pointer access",
        });
        Ok(())
    }

}
