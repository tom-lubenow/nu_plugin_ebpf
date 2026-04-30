use super::*;
use crate::compiler::elf::GetSocketCookieArgPolicy;
use crate::compiler::instruction::{
    KfuncRefKind, scalar_range_contains_only_bitmask, unknown_kfunc_signature_message,
};

impl<'a> VccLowerer<'a> {
    pub(super) fn verify_helper_call(
        &mut self,
        helper_id: u32,
        args: &[MirValue],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if let Some(helper) = BpfHelper::from_u32(helper_id) {
            if helper.requires_callback_subprogram() && !helper.supports_modeled_callback_subprogram()
            {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "helper '{}' requires callback subprogram pointer support, which is not modeled yet",
                        helper.name()
                    ),
                ));
            }
            if let Some(message) = self
                .probe_ctx
                .and_then(|ctx| ctx.helper_call_error(helper))
                .or_else(|| {
                    self.program
                        .and_then(|program| program.program_type.helper_call_error(helper))
                })
            {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    message,
                ));
            }
        }

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
                self.verify_helper_arg_value(
                    helper_id,
                    idx,
                    arg,
                    arg_kind,
                    self.helper_pointer_arg_allows_maybe_null(helper_id, idx),
                    out,
                )?;
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
        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.kfunc_call_error(kfunc)) {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                message,
            ));
        }

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
        if !matches!(space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf)
            && !(space == VccAddrSpace::Context
                && Self::kfunc_pointer_arg_allows_context_as_kernel(kfunc, arg_idx))
        {
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

    pub(super) fn kfunc_pointer_arg_allows_context_as_kernel(
        kfunc: &str,
        arg_idx: usize,
    ) -> bool {
        matches!((kfunc, arg_idx), ("bpf_sock_ops_enable_tx_tstamp", 0))
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
                AddressSpace::Packet => VccAddrSpace::Packet,
                AddressSpace::Context => VccAddrSpace::Context,
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
    ) -> Vec<KfuncUnknownDynptrCopy> {
        kfunc_unknown_dynptr_copy_shared(kfunc)
    }

    pub(super) fn kfunc_unknown_stack_object_lifecycle(
        kfunc: &str,
    ) -> Option<KfuncUnknownStackObjectLifecycle> {
        kfunc_unknown_stack_object_lifecycle_shared(kfunc)
    }

    pub(super) fn kfunc_unknown_stack_object_copy(
        kfunc: &str,
    ) -> Vec<KfuncUnknownStackObjectCopy> {
        kfunc_unknown_stack_object_copy_shared(kfunc)
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
        &self,
        helper_id: u32,
        arg_idx: usize,
    ) -> bool {
        BpfHelper::from_u32(helper_id).is_some_and(|helper| {
            helper.pointer_arg_allows_static_const_zero(arg_idx)
                || self.helper_pointer_arg_allows_contextual_maybe_null(helper, arg_idx)
        })
    }

    fn verify_helper_scalar_const_eq(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        expected: i64,
        message: &str,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        match arg {
            MirValue::Const(actual) => {
                if *actual == expected {
                    Ok(())
                } else {
                    Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.to_string(),
                    ))
                }
            }
            MirValue::VReg(vreg) => {
                self.assert_scalar_reg(*vreg, out);
                out.push(VccInst::AssertConstEq {
                    value: VccValue::Reg(VccReg(vreg.0)),
                    expected,
                    message: message.to_string(),
                });
                Ok(())
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

    fn verify_helper_scalar_const_eq_if_scalar_const_eq(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        trigger: &MirValue,
        trigger_expected: i64,
        message: &str,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        match trigger {
            MirValue::Const(actual) => {
                if *actual == trigger_expected {
                    self.verify_helper_scalar_const_eq(
                        helper_id, arg_idx, arg, 0, message, out,
                    )?;
                }
                Ok(())
            }
            MirValue::VReg(vreg) if !self.is_pointer_reg(*vreg) => {
                self.assert_scalar_reg(*vreg, out);
                let value = match arg {
                    MirValue::Const(actual) => VccValue::Imm(*actual),
                    MirValue::VReg(value) => {
                        self.assert_scalar_reg(*value, out);
                        VccValue::Reg(VccReg(value.0))
                    }
                    MirValue::StackSlot(_) => {
                        return Err(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: VccTypeClass::Ptr,
                            },
                            format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
                        ));
                    }
                };
                out.push(VccInst::AssertConstEqIfConstEq {
                    value,
                    expected: 0,
                    when_value: VccValue::Reg(VccReg(vreg.0)),
                    when_expected: trigger_expected,
                    message: message.to_string(),
                });
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(super) fn verify_helper_arg_value(
        &mut self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
        expected: HelperArgKind,
        allow_maybe_null: bool,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if self.is_local_helper_map_ref_arg(helper_id, arg_idx, arg) {
            return Ok(());
        }
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
                    if matches!(
                        (BpfHelper::from_u32(helper_id), arg_idx, arg),
                        (Some(BpfHelper::GetSocketCookie), 0, MirValue::Const(0))
                    ) {
                        return Ok(());
                    }
                    if matches!(arg, MirValue::Const(0))
                        && self.helper_pointer_arg_allows_const_zero(helper_id, arg_idx)
                    {
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
                MirValue::VReg(vreg) => {
                    if matches!(BpfHelper::from_u32(helper_id), Some(BpfHelper::GetSocketCookie))
                        && arg_idx == 0
                        && !self.is_pointer_reg(*vreg)
                    {
                        return Ok(());
                    }
                    if !self.is_pointer_reg(*vreg)
                        && self.helper_pointer_arg_allows_const_zero(helper_id, arg_idx)
                    {
                        out.push(VccInst::AssertConstEq {
                            value: VccValue::Reg(VccReg(vreg.0)),
                            expected: 0,
                            message: format!(
                                "helper {} arg{} expects null (0) or pointer value",
                                helper_id, arg_idx
                            ),
                        });
                        Ok(())
                    } else if allow_maybe_null {
                        self.require_pointer_reg(*vreg)
                    } else {
                        self.check_ptr_range(*vreg, 1, out)
                    }
                }
                MirValue::StackSlot(_) => Ok(()),
            },
            HelperArgKind::Subprogram => match arg {
                MirValue::VReg(vreg) => {
                    let Some(arg_ty) = self.types.get(vreg) else {
                        return Err(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Unknown,
                                actual: VccTypeClass::Unknown,
                            },
                            format!(
                                "helper {} arg{} expects callback subprogram",
                                helper_id, arg_idx
                            ),
                        ));
                    };
                    if !matches!(arg_ty, MirType::Subprogram { .. }) {
                        return Err(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Unknown,
                                actual: vcc_type_from_mir(arg_ty).class(),
                            },
                            format!(
                                "helper {} arg{} expects callback subprogram",
                                helper_id, arg_idx
                            ),
                        ));
                    }
                    if let Some(helper) = BpfHelper::from_u32(helper_id)
                        && let Some(message) = helper.callback_subprogram_type_error(arg_idx, arg_ty)
                    {
                        return Err(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            message,
                        ));
                    }
                    Ok(())
                }
                MirValue::Const(_) | MirValue::StackSlot(_) => Err(VccError::new(
                    VccErrorKind::TypeMismatch {
                        expected: VccTypeClass::Unknown,
                        actual: if matches!(arg, MirValue::Const(_)) {
                            VccTypeClass::Scalar
                        } else {
                            VccTypeClass::Ptr
                        },
                    },
                    format!("helper {} arg{} expects callback subprogram", helper_id, arg_idx),
                )),
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
            VccAddrSpace::Context | VccAddrSpace::Kernel | VccAddrSpace::KernelBtf => allow_kernel,
            VccAddrSpace::Packet => false,
            VccAddrSpace::User => allow_user,
            VccAddrSpace::Unknown => true,
        }
    }

    pub(super) fn helper_space_name(&self, space: VccAddrSpace) -> &'static str {
        match space {
            VccAddrSpace::Stack(_) => "Stack",
            VccAddrSpace::MapValue => "Map",
            VccAddrSpace::Packet => "Packet",
            VccAddrSpace::RingBuf => "RingBuf",
            VccAddrSpace::Context => "Context",
            VccAddrSpace::Kernel => "Kernel",
            VccAddrSpace::KernelBtf => "KernelBtf",
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
        dynamic_size_allows_zero: bool,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if self.helper_pointer_arg_allows_const_zero(helper_id, arg_idx) {
            match arg {
                MirValue::Const(0) => return Ok(()),
                MirValue::VReg(vreg) if self.value_ptr_info(arg).is_none() => {
                    out.push(VccInst::AssertConstEq {
                        value: VccValue::Reg(VccReg(vreg.0)),
                        expected: 0,
                        message: format!(
                            "helper {} arg{} expects null (0) or pointer value",
                            helper_id, arg_idx
                        ),
                    });
                    return Ok(());
                }
                _ => {}
            }
        }
        if self.is_local_helper_map_ref_arg(helper_id, arg_idx, arg) {
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

        if effective_space == VccAddrSpace::Context
            && allow_kernel
            && self.helper_arg_is_non_raw_context_pointer(arg)
        {
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
                    if dynamic_size_allows_zero {
                        out.push(VccInst::AssertPtrAccessOrZero {
                            ptr: VccReg(vreg.0),
                            size: size_value,
                            op,
                        });
                    } else {
                        out.push(VccInst::AssertPtrAccess {
                            ptr: VccReg(vreg.0),
                            size: size_value,
                            op,
                        });
                    }
                }
                MirValue::StackSlot(slot) => {
                    let ptr = self.stack_addr_temp(*slot, out);
                    if dynamic_size_allows_zero {
                        out.push(VccInst::AssertPtrAccessOrZero {
                            ptr,
                            size: size_value,
                            op,
                        });
                    } else {
                        out.push(VccInst::AssertPtrAccess {
                            ptr,
                            size: size_value,
                            op,
                        });
                    }
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

    fn is_local_helper_map_ref_arg(
        &self,
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
    ) -> bool {
        let MirValue::VReg(vreg) = arg else {
            return false;
        };
        matches!(self.types.get(vreg), Some(MirType::MapRef { .. }))
            && BpfHelper::from_u32(helper_id)
                .is_some_and(|helper| helper.supports_local_helper_map_fd(arg_idx))
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

    pub(super) fn helper_nonnegative_size_upper_bound(
        &self,
        helper_id: u32,
        arg_idx: usize,
        value: &MirValue,
    ) -> Result<Option<usize>, VccError> {
        match value {
            MirValue::Const(v) => {
                if *v < 0 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("helper {} arg{} must be >= 0", helper_id, arg_idx),
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
            MirValue::VReg(_) => Ok(None),
            MirValue::StackSlot(_) => Err(VccError::new(
                VccErrorKind::TypeMismatch {
                    expected: VccTypeClass::Scalar,
                    actual: VccTypeClass::Ptr,
                },
                format!("helper {} arg{} expects scalar value", helper_id, arg_idx),
            )),
        }
    }

    fn verify_helper_scalar_multiple_of(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
    ) -> Result<(), VccError> {
        let Some((multiple, message)) = helper.scalar_arg_multiple_of_requirement(arg_idx) else {
            return Ok(());
        };
        if let MirValue::Const(v) = value
            && v.rem_euclid(multiple) != 0
        {
            return Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                message,
            ));
        }
        Ok(())
    }

    fn verify_helper_scalar_range(
        &mut self,
        helper_id: u32,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let Some((min_required, max_required, message)) =
            helper.scalar_arg_range_requirement(arg_idx)
        else {
            return Ok(());
        };
        match value {
            MirValue::Const(actual) => {
                if *actual >= min_required && *actual <= max_required {
                    Ok(())
                } else {
                    Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message,
                    ))
                }
            }
            MirValue::VReg(vreg) => {
                self.assert_scalar_reg(*vreg, out);
                out.push(VccInst::AssertRange {
                    value: VccValue::Reg(VccReg(vreg.0)),
                    min: min_required,
                    max: max_required,
                    message: message.to_string(),
                });
                Ok(())
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

    fn verify_helper_scalar_allowed_values(
        &mut self,
        helper_id: u32,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let Some((allowed_values, message)) =
            helper.scalar_arg_allowed_values_requirement(arg_idx)
        else {
            return Ok(());
        };
        match value {
            MirValue::Const(actual) => {
                if allowed_values.contains(actual) {
                    Ok(())
                } else {
                    Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message,
                    ))
                }
            }
            MirValue::VReg(vreg) => {
                self.assert_scalar_reg(*vreg, out);
                out.push(VccInst::AssertAllowedValues {
                    value: VccValue::Reg(VccReg(vreg.0)),
                    allowed: allowed_values.to_vec(),
                    message: message.to_string(),
                });
                Ok(())
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

    fn verify_helper_scalar_bitmask(
        &mut self,
        helper_id: u32,
        helper: BpfHelper,
        arg_idx: usize,
        value: &MirValue,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let Some((mask, message)) = helper.scalar_arg_bitmask_requirement(arg_idx) else {
            return Ok(());
        };
        match value {
            MirValue::Const(actual) => {
                if scalar_range_contains_only_bitmask(*actual, *actual, mask) {
                    Ok(())
                } else {
                    Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message,
                    ))
                }
            }
            MirValue::VReg(vreg) => {
                self.assert_scalar_reg(*vreg, out);
                out.push(VccInst::AssertBitmask {
                    value: VccValue::Reg(VccReg(vreg.0)),
                    mask,
                    message: message.to_string(),
                });
                Ok(())
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
        for (arg_idx, value) in args.iter().enumerate().take(5) {
            self.verify_helper_scalar_multiple_of(helper, arg_idx, value)?;
            self.verify_helper_scalar_range(helper_id, helper, arg_idx, value, out)?;
            self.verify_helper_scalar_allowed_values(helper_id, helper, arg_idx, value, out)?;
            self.verify_helper_scalar_bitmask(helper_id, helper, arg_idx, value, out)?;
        }

        if matches!(helper, BpfHelper::GetSocketCookie) {
            self.verify_get_socket_cookie_arg_shape(args)?;
        }

        for rule in semantics.ptr_arg_rules {
            let Some(arg) = args.get(rule.arg_idx) else {
                continue;
            };
            let access_size = match (rule.fixed_size, rule.size_from_arg) {
                (Some(size), _) => Some(size),
                (None, Some(size_arg)) => {
                    if let Some(size) = positive_size_bounds[size_arg] {
                        Some(size)
                    } else if helper.zero_size_pointer_arg_size_arg(rule.arg_idx)
                        == Some(size_arg)
                    {
                        args.get(size_arg)
                            .map(|value| {
                                self.helper_nonnegative_size_upper_bound(
                                    helper_id, size_arg, value,
                                )
                            })
                            .transpose()?
                            .flatten()
                    } else if helper
                        .scalar_arg_nonnegative_requirement(size_arg)
                        .is_some()
                    {
                        args.get(size_arg)
                            .map(|value| {
                                self.helper_nonnegative_size_upper_bound(
                                    helper_id, size_arg, value,
                                )
                            })
                            .transpose()?
                            .flatten()
                    } else {
                        None
                    }
                }
                (None, None) => None,
            };
            if self.helper_pointer_arg_allows_const_zero(helper_id, rule.arg_idx) {
                match arg {
                    MirValue::Const(0) => {
                        if let Some(size_arg) = helper.zero_size_pointer_arg_size_arg(rule.arg_idx)
                            && let Some(size) = args.get(size_arg)
                        {
                            self.verify_helper_scalar_const_eq(
                                helper_id,
                                size_arg,
                                size,
                                0,
                                &format!(
                                    "helper {} arg{} requires arg{} = 0 when arg{} is null",
                                    helper_id, rule.arg_idx, size_arg, rule.arg_idx
                                ),
                                out,
                            )?;
                        }
                        continue;
                    }
                    MirValue::VReg(vreg) if !self.is_pointer_reg(*vreg) => {
                        if let Some(size_arg) = helper.zero_size_pointer_arg_size_arg(rule.arg_idx)
                            && let Some(size) = args.get(size_arg)
                        {
                            self.verify_helper_scalar_const_eq(
                                helper_id,
                                size_arg,
                                size,
                                0,
                                &format!(
                                    "helper {} arg{} requires arg{} = 0 when arg{} is null",
                                    helper_id, rule.arg_idx, size_arg, rule.arg_idx
                                ),
                                out,
                            )?;
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            let dynamic_size = rule.size_from_arg.and_then(|size_arg| args.get(size_arg));
            let dynamic_size_allows_zero =
                access_size.is_none() && rule.size_from_arg.is_some_and(|size_arg| {
                    helper.scalar_arg_nonnegative_requirement(size_arg).is_some()
                });
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
                dynamic_size_allows_zero,
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

        if let Some((arg_idx, message)) = self
            .probe_ctx
            .and_then(|ctx| ctx.helper_zero_arg_requirement(helper))
            .or_else(|| self.program.and_then(|program| program.program_type.helper_zero_arg_requirement(helper)))
            && let Some(arg) = args.get(arg_idx)
        {
            self.verify_helper_scalar_const_eq(helper_id, arg_idx, arg, 0, message, out)?;
        }

        if let Some((arg_idx, message)) = helper.zero_scalar_arg_requirement()
            && let Some(arg) = args.get(arg_idx)
        {
            self.verify_helper_scalar_const_eq(helper_id, arg_idx, arg, 0, message, out)?;
        }

        if let Some((arg_idx, expected, message)) = helper.scalar_arg_const_requirement()
            && let Some(arg) = args.get(arg_idx)
        {
            self.verify_helper_scalar_const_eq(
                helper_id, arg_idx, arg, expected, message, out,
            )?;
        }

        for (arg_idx, arg) in args.iter().enumerate() {
            if let Some(message) = helper.scalar_arg_known_const_requirement(arg_idx) {
                let value = self.lower_value(arg, out);
                out.push(VccInst::AssertKnownConst {
                    value,
                    message: message.to_string(),
                });
            }
        }

        if let Some((arg_idx, trigger_arg_idx, message)) =
            helper.zero_scalar_arg_requirement_when_arg_zero()
            && let (Some(arg), Some(trigger)) = (args.get(arg_idx), args.get(trigger_arg_idx))
        {
            self.verify_helper_scalar_const_eq_if_scalar_const_eq(
                helper_id,
                arg_idx,
                arg,
                trigger,
                0,
                message,
                out,
            )?;
        }

        if matches!(helper, BpfHelper::GetSocketCookie) {
            self.verify_get_socket_cookie_arg_shape(args)?;
        }
        for arg_idx in 0..args.len() {
            let Some((predicate, expected)) =
                Self::helper_expected_named_arg_shape(helper, arg_idx)
            else {
                continue;
            };
            self.verify_named_helper_arg_shape(helper, args, arg_idx, predicate, expected)?;
        }

        Ok(())
    }

    fn verify_get_socket_cookie_arg_shape(
        &self,
        args: &[MirValue],
    ) -> Result<(), VccError> {
        let Some(program_type) = self
            .probe_ctx
            .map(|ctx| ctx.program_type())
            .or_else(|| self.program.map(|program| program.program_type))
        else {
            return Ok(());
        };
        let Some(policy) = self
            .probe_ctx
            .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
            .or_else(|| self.program.and_then(|program| program.program_type.get_socket_cookie_arg_policy()))
        else {
            return Ok(());
        };
        let Some(arg) = args.first() else {
            return Ok(());
        };
        if policy.allows_maybe_null()
            && matches!(arg, MirValue::Const(0))
        {
            return Ok(());
        }
        if policy.allows_maybe_null()
            && matches!(arg, MirValue::VReg(vreg) if !self.is_pointer_reg(*vreg))
        {
            return Ok(());
        }
        let matches_policy = match policy {
            GetSocketCookieArgPolicy::Context => self.helper_arg_is_raw_context_pointer(arg),
            GetSocketCookieArgPolicy::ContextOrSocket => {
                self.helper_arg_is_raw_context_pointer(arg)
                    || self.helper_arg_is_socket_cookie_socket_pointer(arg)
            }
            GetSocketCookieArgPolicy::Socket => {
                self.helper_arg_is_socket_cookie_socket_pointer(arg)
            }
        };
        if matches_policy {
            Ok(())
        } else {
            Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                policy.error_message(BpfHelper::GetSocketCookie, program_type),
            ))
        }
    }

    fn helper_arg_is_raw_context_pointer(&self, arg: &MirValue) -> bool {
        match arg {
            MirValue::VReg(vreg) => self
                .direct_ctx_field_regs
                .get(&VccReg(vreg.0))
                .is_some_and(|field| self.ctx_field_is_raw_context_pointer(field)),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        }
    }

    fn helper_arg_is_non_raw_context_pointer(&self, arg: &MirValue) -> bool {
        match arg {
            MirValue::VReg(vreg) => self
                .direct_ctx_field_regs
                .get(&VccReg(vreg.0))
                .is_some_and(|field| !self.ctx_field_is_raw_context_pointer(field)),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        }
    }

    fn vreg_is_non_raw_context_pointer(&self, vreg: VReg) -> bool {
        self.direct_ctx_field_regs
            .get(&VccReg(vreg.0))
            .is_some_and(|field| !self.ctx_field_is_raw_context_pointer(field))
    }

    fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        if let Some(ctx) = self.probe_ctx {
            return ctx.ctx_field_is_raw_context_pointer(field);
        }
        if let Some(program) = self.program {
            return program.program_type.ctx_field_is_raw_context_pointer(field);
        }
        matches!(field, CtxField::Context)
    }

    fn helper_arg_is_socket_cookie_socket_pointer(&self, arg: &MirValue) -> bool {
        match arg {
            MirValue::VReg(vreg) => self
                .types
                .get(vreg)
                .is_some_and(MirType::is_socket_cookie_socket_ptr),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        }
    }

    fn verify_named_helper_arg_shape(
        &self,
        helper: BpfHelper,
        args: &[MirValue],
        arg_idx: usize,
        predicate: fn(&MirType) -> bool,
        expected: &str,
    ) -> Result<(), VccError> {
        let Some(arg) = args.get(arg_idx) else {
            return Ok(());
        };
        if self.helper_pointer_arg_allows_const_zero(helper as u32, arg_idx)
            && matches!(arg, MirValue::Const(0))
        {
            return Ok(());
        }
        if self.helper_arg_has_tracked_kfunc_ref(arg) {
            return Ok(());
        }
        let matches = match arg {
            MirValue::VReg(vreg) => self.types.get(vreg).is_some_and(predicate),
            MirValue::Const(_) | MirValue::StackSlot(_) => false,
        };
        if matches {
            Ok(())
        } else {
            Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                format!("helper '{}' arg{} expects {}", helper.name(), arg_idx, expected),
            ))
        }
    }

    fn helper_arg_has_tracked_kfunc_ref(&self, arg: &MirValue) -> bool {
        self.value_ptr_info(arg)
            .is_some_and(|info| {
                matches!(info.space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf)
                    && info.kfunc_ref.is_some()
            })
    }

    fn helper_expected_named_arg_shape(
        helper: BpfHelper,
        arg_idx: usize,
    ) -> Option<(fn(&MirType) -> bool, &'static str)> {
        if matches!(
            (helper, arg_idx),
            (
                BpfHelper::TimerInit
                    | BpfHelper::TimerSetCallback
                    | BpfHelper::TimerStart
                    | BpfHelper::TimerCancel,
                0
            )
        ) {
            return Some((MirType::is_bpf_timer_map_ptr, "map-backed bpf_timer pointer"));
        }
        if matches!(
            (helper, arg_idx),
            (BpfHelper::SpinLock | BpfHelper::SpinUnlock, 0)
        ) {
            return Some((
                MirType::is_bpf_spin_lock_map_ptr,
                "map-backed bpf_spin_lock pointer",
            ));
        }
        match Self::helper_pointer_arg_expected_ref_kind(helper as u32, arg_idx)? {
            KfuncRefKind::Socket => Some((MirType::is_socket_ptr, "socket pointer")),
            KfuncRefKind::Task => Some((MirType::is_task_struct_ptr, "task pointer")),
            KfuncRefKind::File => Some((MirType::is_file_ptr, "file pointer")),
            KfuncRefKind::Inode => Some((MirType::is_inode_ptr, "inode pointer")),
            KfuncRefKind::Cgroup => Some((MirType::is_cgroup_ptr, "cgroup pointer")),
            _ => None,
        }
    }

    fn helper_pointer_arg_allows_maybe_null(&self, helper_id: u32, arg_idx: usize) -> bool {
        BpfHelper::from_u32(helper_id).is_some_and(|helper| {
            helper.pointer_arg_allows_static_maybe_null(arg_idx)
                || self.helper_pointer_arg_allows_contextual_maybe_null(helper, arg_idx)
        })
    }

    fn helper_pointer_arg_allows_contextual_maybe_null(
        &self,
        helper: BpfHelper,
        arg_idx: usize,
    ) -> bool {
        if !matches!(helper, BpfHelper::GetSocketCookie) || arg_idx != 0 {
            return false;
        }
        self.probe_ctx
            .and_then(|ctx| ctx.get_socket_cookie_arg_policy())
            .or_else(|| {
                self.program
                    .and_then(|program| program.program_type.get_socket_cookie_arg_policy())
            })
            .is_some_and(GetSocketCookieArgPolicy::allows_maybe_null)
    }

    pub(super) fn verify_map_key(
        &mut self,
        map_name: &str,
        key: VReg,
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        if map_name == STRING_COUNTER_MAP_NAME {
            self.check_ptr_range(key, 16, out)
        } else if map_name == BYTES_COUNTER_MAP_NAME {
            let size = match self.types.get(&key) {
                Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
                Some(ty) => ty.size().max(1),
                None => 1,
            };
            self.check_ptr_range(key, size, out)
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
            let ptr_info = self
                .value_ptr_info(&MirValue::VReg(reg))
                .ok_or_else(|| VccError::new(VccErrorKind::PointerBounds, "expected pointer value"))?;
            if !matches!(
                ptr_info.space,
                VccAddrSpace::Stack(_) | VccAddrSpace::MapValue | VccAddrSpace::Unknown
            ) {
                return Err(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!(
                        "{what} expects pointer in [Stack, Map], got {}",
                        self.helper_space_name(ptr_info.space)
                    ),
                ));
            }
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
            out.push(VccInst::AssertConstEq {
                value: VccValue::Reg(VccReg(arg.0)),
                expected: 0,
                message: format!(
                    "kfunc '{}' arg{} expects null (0) or pointer value",
                    kfunc, arg_idx
                ),
            });
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

        let context_as_kernel = effective_space == VccAddrSpace::Context
            && allow_kernel
            && Self::kfunc_pointer_arg_allows_context_as_kernel(kfunc, arg_idx);
        if effective_space == VccAddrSpace::Context
            && allow_kernel
            && !context_as_kernel
            && self.vreg_is_non_raw_context_pointer(arg)
        {
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
                    AddressSpace::Packet => VccAddrSpace::Packet,
                    AddressSpace::Context => VccAddrSpace::Context,
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
