use super::*;
use crate::compiler::instruction::unknown_kfunc_signature_message;

impl<'a> VccLowerer<'a> {
    pub(super) fn verify_helper_call(
        &mut self,
        helper_id: u32,
        args: &[MirValue],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if let Some(sig) = HelperSignature::for_id(helper_id) {
            if args.len() < sig.min_args || args.len() > sig.max_args {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "helper {} expects {}..={} args, got {}",
                        helper_id,
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    ),
                ));
            }

            for (idx, arg) in args.iter().enumerate() {
                let arg_kind = sig.arg_kind(idx);
                self.verify_helper_arg_value(helper_id, idx, arg, arg_kind, out)?;
                if matches!(arg_kind, HelperArgKind::Pointer)
                    && let Some(expected_kind) =
                        Self::helper_pointer_arg_expected_ref_kind(helper_id, idx)
                    && !(Self::helper_release_kind(helper_id) == Some(expected_kind) && idx == 0)
                {
                    let ptr = self.lower_value(arg, out);
                    out.push(VccInst::HelperExpectRefKind {
                        ptr,
                        arg_idx: idx,
                        kind: expected_kind,
                        helper_id,
                    });
                }
            }
            self.verify_helper_semantics(helper_id, args, out)?;
        } else if args.len() > 5 {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "BPF helpers support at most 5 arguments",
            ));
        }

        Ok(())
    }

    pub(super) fn verify_kfunc_call(
        &mut self,
        kfunc: &str,
        args: &[VReg],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let sig = KfuncSignature::for_name_or_kernel_btf(kfunc).ok_or_else(|| {
            VccError::new(
                VccErrorKind::UnsupportedInstruction,
                unknown_kfunc_signature_message(kfunc),
            )
        })?;
        if args.len() < sig.min_args || args.len() > sig.max_args {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                format!(
                    "kfunc '{}' expects {}..={} args, got {}",
                    kfunc,
                    sig.min_args,
                    sig.max_args,
                    args.len()
                ),
            ));
        }
        if args.len() > 5 {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "BPF kfunc calls support at most 5 arguments",
            ));
        }

        for (idx, arg) in args.iter().enumerate() {
            match sig.arg_kind(idx) {
                KfuncArgKind::Scalar => self.assert_scalar_reg(*arg, out),
                KfuncArgKind::Pointer => {
                    if !self.is_pointer_reg(*arg)
                        && Self::kfunc_pointer_arg_allows_const_zero(kfunc, idx)
                    {
                        out.push(VccInst::AssertConstEq {
                            value: VccValue::Reg(VccReg(arg.0)),
                            expected: 0,
                            message: format!(
                                "kfunc '{}' arg{} expects null (0) or pointer value",
                                kfunc, idx
                            ),
                        });
                        continue;
                    }
                    self.require_pointer_reg(*arg)?;
                    self.verify_kfunc_ptr_arg_space(kfunc, idx, *arg)?;
                    if Self::kfunc_pointer_arg_requires_stack(kfunc, idx) {
                        out.push(VccInst::AssertStackSlotBase {
                            ptr: VccReg(arg.0),
                            op: format!("kfunc '{}' arg{}", kfunc, idx),
                        });
                    }
                    if let Some(kind) = Self::kfunc_pointer_arg_expected_ref_kind(kfunc, idx) {
                        out.push(VccInst::KfuncExpectRefKind {
                            ptr: VccValue::Reg(VccReg(arg.0)),
                            arg_idx: idx,
                            kind,
                            kfunc: kfunc.to_string(),
                        });
                    }
                    if Self::kfunc_release_arg_index(kfunc) == Some(idx) {
                        self.check_ptr_range(*arg, 1, out)?;
                    }
                }
            }
        }
        self.verify_kfunc_semantics(kfunc, args, out)?;

        Ok(())
    }

    pub(super) fn verify_kfunc_ptr_arg_space(
        &self,
        kfunc: &str,
        arg_idx: usize,
        arg: VReg,
    ) -> Result<(), VccError> {
        if Self::kfunc_pointer_arg_requires_stack(kfunc, arg_idx) {
            let space = self
                .value_ptr_info(&MirValue::VReg(arg))
                .map(|ptr| ptr.space)
                .unwrap_or(VccAddrSpace::Unknown);
            if !matches!(space, VccAddrSpace::Stack(_)) {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!(
                        "kfunc '{}' arg{} expects pointer in [Stack], got {}",
                        kfunc,
                        arg_idx,
                        self.helper_space_name(space)
                    ),
                ));
            }
            if matches!(space, VccAddrSpace::Stack(StackSlotId(slot)) if slot == u32::MAX) {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!("kfunc '{}' arg{} expects stack slot pointer", kfunc, arg_idx),
                ));
            }
            let is_stack_base = self
                .value_ptr_info(&MirValue::VReg(arg))
                .and_then(|ptr| ptr.bounds)
                .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
            if !is_stack_base {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!("kfunc '{}' arg{} expects stack slot base pointer", kfunc, arg_idx),
                ));
            }
            return Ok(());
        }
        let space = self.effective_ptr_space(arg).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Unknown,
                },
                "expected pointer value",
            )
        })?;
        if Self::kfunc_pointer_arg_requires_user(kfunc, arg_idx) {
            if space != VccAddrSpace::User {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!(
                        "kfunc '{}' arg{} expects pointer in [User], got {}",
                        kfunc,
                        arg_idx,
                        self.helper_space_name(space)
                    ),
                ));
            }
            return Ok(());
        }
        if Self::kfunc_pointer_arg_requires_stack_or_map(kfunc, arg_idx) {
            if !matches!(space, VccAddrSpace::Stack(_) | VccAddrSpace::MapValue) {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!(
                        "kfunc '{}' arg{} expects pointer in [Stack, Map], got {}",
                        kfunc,
                        arg_idx,
                        self.helper_space_name(space)
                    ),
                ));
            }
            return Ok(());
        }
        if !Self::kfunc_pointer_arg_requires_kernel(kfunc, arg_idx) {
            return Ok(());
        }
        if space != VccAddrSpace::Kernel {
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "kfunc '{}' arg{} expects pointer in [Kernel], got {}",
                    kfunc,
                    arg_idx,
                    self.helper_space_name(space)
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn effective_ptr_space(&self, reg: VReg) -> Option<VccAddrSpace> {
        let ptr_info = self.value_ptr_info(&MirValue::VReg(reg))?;
        if ptr_info.space != VccAddrSpace::Unknown {
            return Some(ptr_info.space);
        }
        match self.types.get(&reg) {
            Some(MirType::Ptr { address_space, .. }) => Some(match address_space {
                AddressSpace::Stack => VccAddrSpace::Stack(StackSlotId(u32::MAX)),
                AddressSpace::Map => VccAddrSpace::MapValue,
                AddressSpace::Kernel => VccAddrSpace::Kernel,
                AddressSpace::User => VccAddrSpace::User,
            }),
            _ => Some(VccAddrSpace::Unknown),
        }
    }

    pub(super) fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_user(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_user_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack_slot_base(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_slot_base_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_requires_stack_or_map(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_stack_or_map_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_allows_const_zero(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_allows_const_zero_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_size_from_scalar(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_size_from_scalar_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_fixed_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_fixed_size_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_pointer_arg_min_access_size(kfunc: &str, arg_idx: usize) -> Option<usize> {
        kfunc_pointer_arg_min_access_size_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_scalar_arg_requires_known_const(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_scalar_arg_requires_known_const_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_scalar_arg_requires_positive(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_scalar_arg_requires_positive_shared(kfunc, arg_idx)
    }

    pub(super) fn kfunc_unknown_iter_lifecycle(
        kfunc: &str,
    ) -> Option<KfuncUnknownIterLifecycle> {
        kfunc_unknown_iter_lifecycle_shared(kfunc)
    }

    pub(super) fn kfunc_unknown_dynptr_args(
        kfunc: &str,
    ) -> Vec<KfuncUnknownDynptrArg> {
        kfunc_unknown_dynptr_args_shared(kfunc)
    }

    pub(super) fn kfunc_unknown_dynptr_copy(
        kfunc: &str,
    ) -> Option<KfuncUnknownDynptrCopy> {
        kfunc_unknown_dynptr_copy_shared(kfunc)
    }

    pub(super) fn kfunc_pointer_arg_expected_ref_kind(
        kfunc: &str,
        arg_idx: usize,
    ) -> Option<KfuncRefKind> {
        kfunc_pointer_arg_ref_kind(kfunc, arg_idx)
    }

    pub(super) fn is_pointer_reg(&self, reg: VReg) -> bool {
        let ty = self
            .types
            .get(&reg)
            .map(vcc_type_from_mir)
            .unwrap_or(VccValueType::Unknown);
        ty.class() == VccTypeClass::Ptr || self.ptr_regs.contains_key(&VccReg(reg.0))
    }

    pub(super) fn helper_pointer_arg_expected_ref_kind(
        helper_id: u32,
        arg_idx: usize,
    ) -> Option<KfuncRefKind> {
        BpfHelper::from_u32(helper_id).and_then(|helper| helper_pointer_arg_ref_kind(helper, arg_idx))
    }

    pub(super) fn helper_pointer_arg_allows_const_zero(
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
    ) -> bool {
        matches!(
            (BpfHelper::from_u32(helper_id), arg_idx),
            (Some(BpfHelper::KptrXchg), 1)
                | (Some(BpfHelper::SkAssign), 1)
                | (Some(BpfHelper::SkStorageGet), 2)
                | (Some(BpfHelper::InodeStorageGet), 2)
                | (Some(BpfHelper::TaskStorageGet), 2)
        )
            && matches!(arg, MirValue::Const(0))
    }

    pub(super) fn verify_helper_arg_value(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        expected: HelperArgKind,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        match expected {
            HelperArgKind::Scalar => match arg {
                MirValue::Const(_) => Ok(()),
                MirValue::VReg(vreg) => {
                    self.assert_scalar_reg(*vreg, out);
                    Ok(())
                }
                MirValue::StackSlot(_) => Err(VccError::new(
                    VccErrorKind::TypeMismatch {
                        expected: VccTypeClass::Scalar,
                        actual: VccTypeClass::Ptr,
                    },
                    format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
                )),
            },
            HelperArgKind::Pointer => match arg {
                MirValue::Const(_) => {
                    if Self::helper_pointer_arg_allows_const_zero(helper_id, arg_idx, arg) {
                        Ok(())
                    } else {
                        Err(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: VccTypeClass::Scalar,
                            },
                            format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
                        ))
                    }
                }
                MirValue::VReg(vreg) => self.check_ptr_range(*vreg, 1, out),
                MirValue::StackSlot(_) => Ok(()),
            },
        }
    }

    pub(super) fn helper_space_allowed(
        &self,
        space: VccAddrSpace,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> bool {
        match space {
            VccAddrSpace::Stack(_) => allow_stack,
            VccAddrSpace::MapValue | VccAddrSpace::RingBuf => allow_map,
            VccAddrSpace::Context | VccAddrSpace::Kernel => allow_kernel,
            VccAddrSpace::User => allow_user,
            VccAddrSpace::Unknown => true,
        }
    }

    pub(super) fn helper_space_name(&self, space: VccAddrSpace) -> &'static str {
        match space {
            VccAddrSpace::Stack(_) => "Stack",
            VccAddrSpace::MapValue => "Map",
            VccAddrSpace::RingBuf => "RingBuf",
            VccAddrSpace::Context => "Context",
            VccAddrSpace::Kernel => "Kernel",
            VccAddrSpace::User => "User",
            VccAddrSpace::Unknown => "Unknown",
        }
    }

    pub(super) fn helper_allowed_spaces_label(
        &self,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> String {
        let mut labels = Vec::new();
        if allow_stack {
            labels.push("Stack");
        }
        if allow_map {
            labels.push("Map");
        }
        if allow_kernel {
            labels.push("Kernel");
        }
        if allow_user {
            labels.push("User");
        }
        format!("[{}]", labels.join(", "))
    }

    pub(super) fn check_ptr_range_reg(
        &mut self,
        ptr: VccReg,
        size: usize,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if size == 0 {
            return Ok(());
        }
        if !self.ptr_regs.contains_key(&ptr) {
            return Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Unknown,
                },
                "expected pointer value",
            ));
        }
        out.push(VccInst::AssertPtrAccess {
            ptr,
            size: VccValue::Imm(size as i64),
            op: "pointer access",
        });
        Ok(())
    }

    pub(super) fn check_helper_ptr_arg_value(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        op: &'static str,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
        access_size: Option<usize>,
        dynamic_size: Option<&MirValue>,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if Self::helper_pointer_arg_allows_const_zero(helper_id, arg_idx, arg) {
            return Ok(());
        }
        let ptr = self.value_ptr_info(arg).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
            )
        })?;
        let effective_space = if ptr.space == VccAddrSpace::Unknown {
            match arg {
                MirValue::VReg(vreg) => self
                    .effective_ptr_space(*vreg)
                    .unwrap_or(VccAddrSpace::Unknown),
                _ => ptr.space,
            }
        } else {
            ptr.space
        };

        if !self.helper_space_allowed(
            effective_space,
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        ) {
            let allowed =
                self.helper_allowed_spaces_label(allow_stack, allow_map, allow_kernel, allow_user);
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "{op} expects pointer in {allowed}, got {}",
                    self.helper_space_name(effective_space)
                ),
            ));
        }

        if let Some(size) = access_size {
            match arg {
                MirValue::VReg(vreg) => self.check_ptr_range(*vreg, size, out)?,
                MirValue::StackSlot(slot) => {
                    let ptr = self.stack_addr_temp(*slot, out);
                    self.check_ptr_range_reg(ptr, size, out)?;
                }
                MirValue::Const(_) => {
                    return Err(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Ptr,
                            actual: VccTypeClass::Scalar,
                        },
                        format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
                    ));
                }
            }
        } else if let Some(size_arg) = dynamic_size {
            let size_value = self.lower_value(size_arg, out);
            match arg {
                MirValue::VReg(vreg) => {
                    out.push(VccInst::AssertPtrAccess {
                        ptr: VccReg(vreg.0),
                        size: size_value,
                        op,
                    });
                }
                MirValue::StackSlot(slot) => {
                    let ptr = self.stack_addr_temp(*slot, out);
                    out.push(VccInst::AssertPtrAccess {
                        ptr,
                        size: size_value,
                        op,
                    });
                }
                MirValue::Const(_) => {
                    return Err(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Ptr,
                            actual: VccTypeClass::Scalar,
                        },
                        format!("helper {} arg{} expects pointer value", helper_id, arg_idx),
                    ));
                }
            }
        }

        Ok(())
    }

    pub(super) fn check_helper_ringbuf_record_arg(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        op: &str,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let ptr = self.value_ptr_info(arg).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!(
                    "helper {} arg{} expects ringbuf record pointer",
                    helper_id, arg_idx
                ),
            )
        })?;

        if ptr.space != VccAddrSpace::RingBuf {
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "{op} expects ringbuf record pointer, got {}",
                    self.helper_space_name(ptr.space)
                ),
            ));
        }

        match arg {
            MirValue::VReg(vreg) => self.check_ptr_range(*vreg, 1, out),
            MirValue::StackSlot(slot) => {
                let ptr = self.stack_addr_temp(*slot, out);
                self.check_ptr_range_reg(ptr, 1, out)
            }
            MirValue::Const(_) => Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!(
                    "helper {} arg{} expects ringbuf record pointer",
                    helper_id, arg_idx
                ),
            )),
        }
    }

    pub(super) fn helper_positive_size_upper_bound(
        &self,
        helper_id: u32,
        arg_idx: usize,
        value: &MirValue,
        out: &mut Vec<VccInst>,
    ) -> Result<Option<usize>, VccError> {
        match value {
            MirValue::Const(v) => {
                if *v <= 0 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("helper {} arg{} must be > 0", helper_id, arg_idx),
                    ));
                }
                let size = usize::try_from(*v).map_err(|_| {
                    VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("helper {} arg{} is out of range", helper_id, arg_idx),
                    )
                })?;
                Ok(Some(size))
            }
            MirValue::VReg(vreg) => {
                out.push(VccInst::AssertPositive {
                    value: VccValue::Reg(VccReg(vreg.0)),
                    message: format!("helper {} arg{} must be > 0", helper_id, arg_idx),
                });
                Ok(None)
            }
            MirValue::StackSlot(_) => Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Scalar,
                    actual: VccTypeClass::Ptr,
                },
                format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
            )),
        }
    }

    pub(super) fn verify_helper_semantics(
        &mut self,
        helper_id: u32,
        args: &[MirValue],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let Some(helper) = BpfHelper::from_u32(helper_id) else {
            return Ok(());
        };

        let semantics = helper.semantics();
        let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
        for size_arg in semantics.positive_size_args {
            if let Some(arg) = args.get(*size_arg) {
                positive_size_bounds[*size_arg] =
                    self.helper_positive_size_upper_bound(helper_id, *size_arg, arg, out)?;
            }
        }

        for rule in semantics.ptr_arg_rules {
            let Some(arg) = args.get(rule.arg_idx) else {
                continue;
            };
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => positive_size_bounds[size_arg],
                (None, None) => None,
            };
            let dynamic_size = rule.size_from_arg.and_then(|size_arg| args.get(size_arg));
            self.check_helper_ptr_arg_value(
                helper_id,
                rule.arg_idx,
                arg,
                rule.op,
                rule.allowed.allow_stack,
                rule.allowed.allow_map,
                rule.allowed.allow_kernel,
                rule.allowed.allow_user,
                access_size,
                dynamic_size,
                out,
            )?;
        }

        if semantics.ringbuf_record_arg0 {
            if let Some(record) = args.first() {
                self.check_helper_ringbuf_record_arg(
                    helper_id,
                    0,
                    record,
                    "helper ringbuf submit/discard record",
                    out,
                )?;
            }
        }

        Ok(())
    }

    pub(super) fn verify_map_key(
        &mut self,
        map_name: &str,
        key: VReg,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if map_name == STRING_COUNTER_MAP_NAME {
            self.check_ptr_range(key, 16, out)
        } else {
            self.verify_map_operand(key, "map key", out)
        }
    }

    pub(super) fn verify_map_value(&mut self, value: VReg, out: &mut Vec<VccInst>) -> Result<(), VccError> {
        self.verify_map_operand(value, "map value", out)
    }

    pub(super) fn verify_map_operand(
        &mut self,
        reg: VReg,
        what: &str,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if let Some(ty) = self.types.get(&reg) {
            if !matches!(ty, MirType::Ptr { .. }) {
                let size = match ty.size() {
                    0 => 8,
                    n => n,
                };
                if size > 8 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "{what} v{} has size {} bytes and must be passed as a pointer",
                            reg.0, size
                        ),
                    ));
                }
            }
        }
        let is_ptr = self
            .types
            .get(&reg)
            .map(vcc_type_from_mir)
            .map(|ty| ty.class() == VccTypeClass::Ptr)
            .unwrap_or(false)
            || self.ptr_regs.contains_key(&VccReg(reg.0));

        if is_ptr {
            let size = match self.types.get(&reg) {
                Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
                _ => 1,
            };
            self.check_ptr_range(reg, size, out)
        } else {
            self.assert_scalar_reg(reg, out);
            Ok(())
        }
    }

    pub(super) fn kfunc_positive_size_upper_bound(
        &self,
        kfunc: &str,
        arg_idx: usize,
        value: VReg,
        out: &mut Vec<VccInst>,
    ) -> Result<Option<usize>, VccError> {
        out.push(VccInst::AssertPositive {
            value: VccValue::Reg(VccReg(value.0)),
            message: format!("kfunc '{}' arg{} must be > 0", kfunc, arg_idx),
        });
        Ok(None)
    }

    pub(super) fn check_kfunc_ptr_arg_value(
        &mut self,
        kfunc: &str,
        arg_idx: usize,
        arg: VReg,
        op: &'static str,
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
        access_size: Option<usize>,
        dynamic_size: Option<VReg>,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if !self.is_pointer_reg(arg) && Self::kfunc_pointer_arg_allows_const_zero(kfunc, arg_idx) {
            return Ok(());
        }
        let arg_value = MirValue::VReg(arg);
        let ptr = self.value_ptr_info(&arg_value).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Scalar,
                },
                format!("kfunc '{}' arg{} expects pointer value", kfunc, arg_idx),
            )
        })?;
        let effective_space = if ptr.space == VccAddrSpace::Unknown {
            self.effective_ptr_space(arg).unwrap_or(VccAddrSpace::Unknown)
        } else {
            ptr.space
        };

        if !self.helper_space_allowed(
            effective_space,
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        ) {
            let allowed =
                self.helper_allowed_spaces_label(allow_stack, allow_map, allow_kernel, allow_user);
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "{op} expects pointer in {allowed}, got {}",
                    self.helper_space_name(effective_space)
                ),
            ));
        }
        if Self::kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx)
            && matches!(effective_space, VccAddrSpace::Stack(_))
        {
            out.push(VccInst::AssertStackSlotBase {
                ptr: VccReg(arg.0),
                op: format!("kfunc '{}' arg{}", kfunc, arg_idx),
            });
        }

        if let Some(size) = access_size {
            self.check_ptr_range(arg, size, out)?;
        } else if let Some(size_reg) = dynamic_size {
            out.push(VccInst::AssertPtrAccess {
                ptr: VccReg(arg.0),
                size: VccValue::Reg(VccReg(size_reg.0)),
                op,
            });
        }

        Ok(())
    }

    pub(super) fn verify_kfunc_semantics(
        &mut self,
        kfunc: &str,
        args: &[VReg],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let semantics = kfunc_semantics(kfunc);
        let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
        for (arg_idx, arg) in args.iter().enumerate() {
            if Self::kfunc_scalar_arg_requires_positive(kfunc, arg_idx) {
                positive_size_bounds[arg_idx] =
                    self.kfunc_positive_size_upper_bound(kfunc, arg_idx, *arg, out)?;
            }
        }

        for rule in semantics.ptr_arg_rules {
            let Some(arg) = args.get(rule.arg_idx).copied() else {
                continue;
            };
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => positive_size_bounds[size_arg],
                (None, None) => None,
            };
            let dynamic_size = rule
                .size_from_arg
                .and_then(|size_arg| args.get(size_arg))
                .copied();
            self.check_kfunc_ptr_arg_value(
                kfunc,
                rule.arg_idx,
                arg,
                rule.op,
                rule.allowed.allow_stack,
                rule.allowed.allow_map,
                rule.allowed.allow_kernel,
                rule.allowed.allow_user,
                access_size,
                dynamic_size,
                out,
            )?;
        }

        for (ptr_arg_idx, arg) in args.iter().enumerate() {
            if semantics
                .ptr_arg_rules
                .iter()
                .any(|rule| rule.arg_idx == ptr_arg_idx)
            {
                continue;
            }
            let (access_size, dynamic_size) = if let Some(size_arg_idx) =
                Self::kfunc_pointer_arg_size_from_scalar(kfunc, ptr_arg_idx)
            {
                let access_size = positive_size_bounds.get(size_arg_idx).copied().flatten();
                let dynamic_size = if access_size.is_none() {
                    args.get(size_arg_idx).copied()
                } else {
                    None
                };
                (access_size, dynamic_size)
            } else {
                (
                    Self::kfunc_pointer_arg_fixed_size(kfunc, ptr_arg_idx),
                    None,
                )
            };
            let access_size =
                access_size.or_else(|| Self::kfunc_pointer_arg_min_access_size(kfunc, ptr_arg_idx));
            if access_size.is_none() && dynamic_size.is_none() {
                continue;
            }
            self.check_kfunc_ptr_arg_value(
                kfunc,
                ptr_arg_idx,
                *arg,
                "kfunc pointer-size argument",
                true,
                true,
                true,
                true,
                access_size,
                dynamic_size,
                out,
            )?;
        }

        for (ptr_arg_idx, arg) in args.iter().enumerate() {
            let handled_in_rule = semantics
                .ptr_arg_rules
                .iter()
                .any(|rule| rule.arg_idx == ptr_arg_idx);
            let handled_in_pointer_size = Self::kfunc_pointer_arg_size_from_scalar(kfunc, ptr_arg_idx)
                .is_some()
                || Self::kfunc_pointer_arg_fixed_size(kfunc, ptr_arg_idx).is_some();
            if handled_in_rule || handled_in_pointer_size {
                continue;
            }
            if !Self::kfunc_pointer_arg_requires_stack_slot_base(kfunc, ptr_arg_idx) {
                continue;
            }
            self.check_kfunc_ptr_arg_value(
                kfunc,
                ptr_arg_idx,
                *arg,
                "kfunc stack-slot-base argument",
                true,
                true,
                true,
                true,
                None,
                None,
                out,
            )?;
        }

        for (idx, arg) in args.iter().enumerate() {
            if !Self::kfunc_scalar_arg_requires_known_const(kfunc, idx) {
                continue;
            }
            out.push(VccInst::AssertKnownConst {
                value: VccValue::Reg(VccReg(arg.0)),
                message: format!("kfunc '{}' arg{} must be known constant", kfunc, idx),
            });
        }

        if kfunc == "bpf_dynptr_clone"
            && let (Some(src), Some(dst)) = (args.first(), args.get(1))
        {
            out.push(VccInst::AssertDistinctStackSlots {
                lhs: VccReg(src.0),
                rhs: VccReg(dst.0),
                message:
                    "kfunc 'bpf_dynptr_clone' arg1 must reference distinct stack slot from arg0"
                        .to_string(),
            });
        }

        Ok(())
    }

    pub(super) fn verify_read_str_ptr(
        &mut self,
        ptr: VReg,
        user_space: bool,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let ptr_info = self.value_ptr_info(&MirValue::VReg(ptr)).ok_or_else(|| {
            VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Ptr,
                    actual: VccTypeClass::Unknown,
                },
                "read_str expects pointer value",
            )
        })?;
        let effective_space = if ptr_info.space == VccAddrSpace::Unknown {
            match self.types.get(&ptr) {
                Some(MirType::Ptr { address_space, .. }) => match address_space {
                    AddressSpace::Stack => VccAddrSpace::Stack(StackSlotId(u32::MAX)),
                    AddressSpace::Map => VccAddrSpace::MapValue,
                    AddressSpace::Kernel => VccAddrSpace::Kernel,
                    AddressSpace::User => VccAddrSpace::User,
                },
                _ => VccAddrSpace::Unknown,
            }
        } else {
            ptr_info.space
        };

        let (allow_stack, allow_map, allow_kernel, allow_user) = if user_space {
            (false, false, false, true)
        } else {
            (true, true, true, false)
        };
        if !self.helper_space_allowed(
            effective_space,
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        ) {
            let allowed =
                self.helper_allowed_spaces_label(allow_stack, allow_map, allow_kernel, allow_user);
            return Err(VccError::new(
                VccErrorKind::PointerBounds,
                format!(
                    "read_str expects pointer in {allowed}, got {}",
                    self.helper_space_name(effective_space)
                ),
            ));
        }

        self.check_ptr_range(ptr, 1, out)
    }
}
