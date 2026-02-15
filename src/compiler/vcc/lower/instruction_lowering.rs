use super::*;

impl<'a> VccLowerer<'a> {
    fn ctx_field_key(field: &CtxField) -> String {
        match field {
            CtxField::Pid => "pid".to_string(),
            CtxField::Tid => "tid".to_string(),
            CtxField::Uid => "uid".to_string(),
            CtxField::Gid => "gid".to_string(),
            CtxField::Comm => "comm".to_string(),
            CtxField::Cpu => "cpu".to_string(),
            CtxField::Timestamp => "timestamp".to_string(),
            CtxField::Arg(idx) => format!("arg:{idx}"),
            CtxField::RetVal => "retval".to_string(),
            CtxField::KStack => "kstack".to_string(),
            CtxField::UStack => "ustack".to_string(),
            CtxField::TracepointField(name) => format!("tp:{name}"),
        }
    }

    pub(super) fn lower_inst(
        &mut self,
        inst: &MirInst,
        out: &mut Vec<VccInst>,
        in_entry: bool,
    ) -> Result<(), VccError> {
        match inst {
            MirInst::Copy { dst, src } => {
                let dst_reg = VccReg(dst.0);
                match src {
                    MirValue::StackSlot(slot) => {
                        let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                        out.push(VccInst::StackAddr {
                            dst: dst_reg,
                            slot: *slot,
                            size,
                        });
                        self.ptr_regs.insert(
                            dst_reg,
                            VccPointerInfo {
                                space: VccAddrSpace::Stack(*slot),
                                nullability: VccNullability::NonNull,
                                bounds: stack_bounds(size),
                                ringbuf_ref: None,
                                kfunc_ref: None,
                            },
                        );
                    }
                    _ => {
                        let vcc_src = self.lower_value(src, out);
                        out.push(VccInst::Copy {
                            dst: dst_reg,
                            src: vcc_src,
                        });
                        if let Some(ptr) = self.value_ptr_info(src) {
                            self.ptr_regs.insert(dst_reg, ptr);
                        }
                    }
                }
            }
            MirInst::Load {
                dst,
                ptr,
                offset,
                ty,
            } => {
                out.push(VccInst::Load {
                    dst: VccReg(dst.0),
                    ptr: VccReg(ptr.0),
                    offset: *offset as i64,
                    size: ty.size() as u8,
                });
                self.maybe_assume_list_len(*dst, *ptr, *offset, out);
                self.maybe_assume_type(*dst, ty, out);
            }
            MirInst::Store {
                ptr,
                offset,
                val,
                ty,
            } => {
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: VccReg(ptr.0),
                    offset: *offset as i64,
                    src: vcc_val,
                    size: ty.size() as u8,
                });
            }
            MirInst::LoadSlot {
                dst,
                slot,
                offset,
                ty,
            } => {
                let base = self.stack_addr_temp(*slot, out);
                out.push(VccInst::Load {
                    dst: VccReg(dst.0),
                    ptr: base,
                    offset: *offset as i64,
                    size: ty.size() as u8,
                });
                self.maybe_assume_list_len_slot(*dst, *slot, *offset, out);
                self.maybe_assume_type(*dst, ty, out);
            }
            MirInst::StoreSlot {
                slot,
                offset,
                val,
                ty,
            } => {
                let base = self.stack_addr_temp(*slot, out);
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: *offset as i64,
                    src: vcc_val,
                    size: ty.size() as u8,
                });
            }
            MirInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_ptr = self.value_ptr_info(lhs);
                let rhs_ptr = self.value_ptr_info(rhs);

                let vcc_op = to_vcc_binop(*op);
                let dst_reg = VccReg(dst.0);

                match op {
                    BinOpKind::Add | BinOpKind::Sub if lhs_ptr.is_some() ^ rhs_ptr.is_some() => {
                        let (base, offset_val, base_ptr) = if lhs_ptr.is_some() {
                            (lhs, rhs, lhs_ptr.unwrap())
                        } else {
                            (rhs, lhs, rhs_ptr.unwrap())
                        };

                        if matches!(op, BinOpKind::Sub) && lhs_ptr.is_none() {
                            return Err(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "numeric - pointer is not supported",
                            ));
                        }

                        let base_reg = self.base_ptr_reg(base, out);
                        let mut offset = self.lower_value(offset_val, out);
                        if matches!(op, BinOpKind::Sub) {
                            match offset {
                                VccValue::Imm(value) => {
                                    offset = VccValue::Imm(-value);
                                }
                                VccValue::Reg(reg) => {
                                    let tmp = self.temp_reg();
                                    out.push(VccInst::BinOp {
                                        dst: tmp,
                                        op: VccBinOp::Sub,
                                        lhs: VccValue::Imm(0),
                                        rhs: VccValue::Reg(reg),
                                    });
                                    offset = VccValue::Reg(tmp);
                                }
                            }
                        }
                        out.push(VccInst::PtrAdd {
                            dst: dst_reg,
                            base: base_reg,
                            offset,
                        });
                        self.ptr_regs.insert(dst_reg, base_ptr);
                    }
                    _ => {
                        let vcc_lhs = self.lower_value(lhs, out);
                        let vcc_rhs = self.lower_value(rhs, out);
                        out.push(VccInst::BinOp {
                            dst: dst_reg,
                            op: vcc_op,
                            lhs: vcc_lhs,
                            rhs: vcc_rhs,
                        });
                    }
                }
            }
            MirInst::UnaryOp { dst, op, src } => {
                let vcc_src = self.lower_value(src, out);
                out.push(VccInst::AssertScalar { value: vcc_src });
                let dst_ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                match op {
                    UnaryOpKind::Not => {
                        out.push(VccInst::BinOp {
                            dst: VccReg(dst.0),
                            op: VccBinOp::Eq,
                            lhs: vcc_src,
                            rhs: VccValue::Imm(0),
                        });
                    }
                    _ => {
                        out.push(VccInst::Assume {
                            dst: VccReg(dst.0),
                            ty: dst_ty,
                        });
                    }
                }
            }
            MirInst::Phi { dst, args } => {
                let vcc_args = args
                    .iter()
                    .map(|(block, vreg)| (VccBlockId(block.0), VccReg(vreg.0)))
                    .collect();
                out.push(VccInst::Phi {
                    dst: VccReg(dst.0),
                    args: vcc_args,
                });
            }
            MirInst::LoadCtxField { dst, field, slot } => {
                if slot.is_none() {
                    let key = Self::ctx_field_key(field);
                    if let Some(src) = self.entry_ctx_field_regs.get(&key).copied() {
                        out.push(VccInst::Copy {
                            dst: VccReg(dst.0),
                            src: VccValue::Reg(src),
                        });
                        if let Some(ptr) = self.ptr_regs.get(&src).copied() {
                            self.ptr_regs.insert(VccReg(dst.0), ptr);
                        }
                        return Ok(());
                    }
                }
                if let Some(slot) = slot {
                    let size = self.slot_sizes.get(slot).copied().unwrap_or(0) as i64;
                    out.push(VccInst::StackAddr {
                        dst: VccReg(dst.0),
                        slot: *slot,
                        size,
                    });
                    if size > 0 {
                        out.push(VccInst::Store {
                            ptr: VccReg(dst.0),
                            offset: size.saturating_sub(1),
                            src: VccValue::Imm(0),
                            size: 1,
                        });
                    }
                    self.ptr_regs.insert(
                        VccReg(dst.0),
                        VccPointerInfo {
                            space: VccAddrSpace::Stack(*slot),
                            nullability: VccNullability::NonNull,
                            bounds: stack_bounds(size),
                            ringbuf_ref: None,
                            kfunc_ref: None,
                        },
                    );
                } else {
                    let ty = self
                        .types
                        .get(dst)
                        .map(vcc_type_from_mir)
                        .unwrap_or(VccValueType::Unknown);
                    out.push(VccInst::Assume {
                        dst: VccReg(dst.0),
                        ty,
                    });
                    if let VccValueType::Ptr(info) = ty {
                        self.ptr_regs.insert(VccReg(dst.0), info);
                    }
                }
                if in_entry && slot.is_none() {
                    self.entry_ctx_field_regs
                        .entry(Self::ctx_field_key(field))
                        .or_insert(VccReg(dst.0));
                }
            }
            MirInst::StrCmp { dst, lhs, rhs, len } => {
                if *len > 0 {
                    let lhs_base = self.stack_addr_temp(*lhs, out);
                    let rhs_base = self.stack_addr_temp(*rhs, out);
                    let last = (*len as i64).saturating_sub(1);
                    let lhs_tmp = self.temp_reg();
                    let rhs_tmp = self.temp_reg();
                    out.push(VccInst::Load {
                        dst: lhs_tmp,
                        ptr: lhs_base,
                        offset: last,
                        size: 1,
                    });
                    out.push(VccInst::Load {
                        dst: rhs_tmp,
                        ptr: rhs_base,
                        offset: last,
                        size: 1,
                    });
                }
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty: VccValueType::Bool,
                });
            }
            MirInst::MapLookup { dst, map, key } => {
                if !supports_generic_map_kind(map.kind) {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map operations do not support map kind {:?} for '{}'",
                            map.kind, map.name
                        ),
                    ));
                }
                self.verify_map_key(&map.name, *key, out)?;
                let inferred = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                let bounds = map_value_limit(map.name.as_str())
                    .or_else(|| map_value_limit_from_dst_type(self.types.get(dst)))
                    .map(|limit| VccBounds {
                        min: 0,
                        max: 0,
                        limit,
                    });
                let mut info = match inferred {
                    VccValueType::Ptr(info) => info,
                    _ => VccPointerInfo {
                        space: VccAddrSpace::MapValue,
                        nullability: VccNullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    },
                };
                info.space = VccAddrSpace::MapValue;
                info.nullability = VccNullability::MaybeNull;
                if info.bounds.is_none() {
                    info.bounds = bounds;
                }
                let ty = VccValueType::Ptr(info);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
                if let VccValueType::Ptr(info) = ty {
                    self.ptr_regs.insert(VccReg(dst.0), info);
                }
            }
            MirInst::MapUpdate {
                map,
                key,
                val,
                flags,
            } => {
                if !supports_generic_map_kind(map.kind) {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map operations do not support map kind {:?} for '{}'",
                            map.kind, map.name
                        ),
                    ));
                }
                if *flags > i32::MAX as u64 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map update flags {} exceed supported 32-bit immediate range",
                            flags
                        ),
                    ));
                }
                self.verify_map_key(&map.name, *key, out)?;
                self.verify_map_value(*val, out)?;
            }
            MirInst::MapDelete { map, key } => {
                if !supports_generic_map_kind(map.kind) {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map operations do not support map kind {:?} for '{}'",
                            map.kind, map.name
                        ),
                    ));
                }
                if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map delete is not supported for array map kind {:?} ('{}')",
                            map.kind, map.name
                        ),
                    ));
                }
                self.verify_map_key(&map.name, *key, out)?;
            }
            MirInst::EmitEvent { data, size } => {
                if *size <= 8 {
                    self.assert_scalar_reg(*data, out);
                } else {
                    self.check_ptr_range(*data, *size, out)?;
                }
            }
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    let size = record_field_size(&field.ty);
                    if size <= 8 {
                        self.assert_scalar_reg(field.value, out);
                    } else {
                        self.check_ptr_range(field.value, size, out)?;
                    }
                }
            }
            MirInst::Histogram { value } => {
                self.assert_scalar_reg(*value, out);
            }
            MirInst::StartTimer => {}
            MirInst::StopTimer { dst } => {
                let ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
            }
            MirInst::CallHelper { dst, helper, args } => {
                self.verify_helper_call(*helper, args, out)?;
                let ty = self.helper_return_type(*helper, *dst);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
                if let VccValueType::Ptr(info) = ty {
                    self.ptr_regs.insert(VccReg(dst.0), info);
                }
                if matches!(BpfHelper::from_u32(*helper), Some(BpfHelper::KptrXchg))
                    && let Some(arg1) = args.get(1)
                {
                    let src = self.lower_value(arg1, out);
                    out.push(VccInst::KptrXchgTransfer {
                        dst: VccReg(dst.0),
                        src,
                    });
                }
                if let Some(kind) = Self::helper_acquire_kind(*helper) {
                    out.push(VccInst::KfuncAcquire {
                        id: VccReg(dst.0),
                        kind,
                    });
                }
                if matches!(
                    BpfHelper::from_u32(*helper),
                    Some(BpfHelper::RingbufReserve)
                ) {
                    out.push(VccInst::RingbufAcquire { id: VccReg(dst.0) });
                }
                if matches!(
                    BpfHelper::from_u32(*helper),
                    Some(BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard)
                ) {
                    if let Some(arg0) = args.first() {
                        let release_ptr = self.lower_value(arg0, out);
                        out.push(VccInst::RingbufRelease { ptr: release_ptr });
                    }
                }
                if let Some(kind) = Self::helper_release_kind(*helper)
                    && let Some(arg0) = args.first()
                {
                    let release_ptr = self.lower_value(arg0, out);
                    out.push(VccInst::KfuncRelease {
                        ptr: release_ptr,
                        kind,
                        arg_idx: 0,
                    });
                }
            }
            MirInst::CallKfunc {
                dst, kfunc, args, ..
            } => {
                self.verify_kfunc_call(kfunc, args, out)?;
                let ty = self.kfunc_return_type(kfunc, *dst);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
                if let VccValueType::Ptr(info) = ty {
                    self.ptr_regs.insert(VccReg(dst.0), info);
                }
                if let Some(kind) = Self::kfunc_acquire_kind(kfunc) {
                    out.push(VccInst::KfuncAcquire {
                        id: VccReg(dst.0),
                        kind,
                    });
                }
                if let Some(kind) = Self::kfunc_release_kind(kfunc) {
                    if let Some(release_arg_idx) = Self::kfunc_release_arg_index(kfunc)
                        && let Some(arg) = args.get(release_arg_idx)
                    {
                        out.push(VccInst::KfuncRelease {
                            ptr: VccValue::Reg(VccReg(arg.0)),
                            kind,
                            arg_idx: release_arg_idx,
                        });
                    }
                }
                if kfunc == "bpf_rcu_read_lock" {
                    out.push(VccInst::RcuReadLockAcquire);
                }
                if kfunc == "bpf_rcu_read_unlock" {
                    out.push(VccInst::RcuReadLockRelease);
                }
                if kfunc == "bpf_preempt_disable" {
                    out.push(VccInst::PreemptDisableAcquire);
                }
                if kfunc == "bpf_preempt_enable" {
                    out.push(VccInst::PreemptDisableRelease);
                }
                if kfunc == "bpf_local_irq_save" {
                    if let Some(flags) = args.first() {
                        out.push(VccInst::LocalIrqDisableAcquire {
                            flags: VccReg(flags.0),
                        });
                    }
                }
                if kfunc == "bpf_local_irq_restore" {
                    if let Some(flags) = args.first() {
                        out.push(VccInst::LocalIrqDisableRelease {
                            flags: VccReg(flags.0),
                        });
                    }
                }
                if kfunc == "bpf_res_spin_lock" {
                    out.push(VccInst::ResSpinLockAcquire);
                }
                if kfunc == "bpf_res_spin_unlock" {
                    out.push(VccInst::ResSpinLockRelease);
                }
                if kfunc == "bpf_res_spin_lock_irqsave" {
                    if let Some(flags) = args.get(1) {
                        out.push(VccInst::ResSpinLockIrqsaveAcquire {
                            flags: VccReg(flags.0),
                        });
                    }
                }
                if kfunc == "bpf_res_spin_unlock_irqrestore" {
                    if let Some(flags) = args.get(1) {
                        out.push(VccInst::ResSpinLockIrqsaveRelease {
                            flags: VccReg(flags.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_task_vma_new" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterTaskVmaNew {
                            iter: VccReg(iter.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_task_vma_next" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterTaskVmaNext {
                            iter: VccReg(iter.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_task_vma_destroy" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterTaskVmaDestroy {
                            iter: VccReg(iter.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_scx_dsq_new" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterScxDsqNew {
                            iter: VccReg(iter.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_scx_dsq_next" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterScxDsqNext {
                            iter: VccReg(iter.0),
                        });
                    }
                }
                if kfunc == "bpf_iter_scx_dsq_destroy" {
                    if let Some(iter) = args.first() {
                        out.push(VccInst::IterScxDsqDestroy {
                            iter: VccReg(iter.0),
                        });
                    }
                }
            }
            MirInst::CallSubfn { dst, args, .. } => {
                if args.len() > 5 {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "BPF subfunctions support at most 5 arguments, got {}",
                            args.len()
                        ),
                    ));
                }
                let ty = self
                    .types
                    .get(dst)
                    .map(vcc_type_from_mir)
                    .unwrap_or(VccValueType::Unknown);
                out.push(VccInst::Assume {
                    dst: VccReg(dst.0),
                    ty,
                });
            }
            MirInst::ReadStr {
                dst,
                ptr,
                user_space,
                max_len,
            } => {
                if *max_len == 0 {
                    return Err(VccError::new(
                        VccErrorKind::PointerBounds,
                        "read_str max_len must be positive",
                    ));
                }
                self.verify_read_str_ptr(*ptr, *user_space, out)?;
                let ptr_reg = VccReg(ptr.0);
                let tmp = self.temp_reg();
                out.push(VccInst::PtrAdd {
                    dst: tmp,
                    base: ptr_reg,
                    offset: VccValue::Imm(0),
                });

                let base = self.stack_addr_temp(*dst, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: (*max_len as i64).saturating_sub(1),
                    src: VccValue::Imm(0),
                    size: 1,
                });
            }
            MirInst::StringAppend {
                dst_buffer,
                dst_len,
                val,
                val_type,
            } => {
                let len_reg = VccReg(dst_len.0);
                out.push(VccInst::AssertScalar {
                    value: VccValue::Reg(len_reg),
                });

                let dst_base = self.stack_addr_temp(*dst_buffer, out);
                let dst_ptr = self.temp_reg();
                out.push(VccInst::PtrAdd {
                    dst: dst_ptr,
                    base: dst_base,
                    offset: VccValue::Reg(len_reg),
                });

                match val_type {
                    StringAppendType::Literal { bytes } => {
                        let effective_len = bytes
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|idx| idx + 1)
                            .unwrap_or(0);
                        if !bytes.is_empty() {
                            let last = (bytes.len() as i64).saturating_sub(1);
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: last,
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }
                        if effective_len > 0 {
                            out.push(VccInst::BinOp {
                                dst: len_reg,
                                op: VccBinOp::Add,
                                lhs: VccValue::Reg(len_reg),
                                rhs: VccValue::Imm(effective_len as i64),
                            });
                        }
                    }
                    StringAppendType::StringSlot { slot, max_len } => {
                        let copy_len = (*max_len).min(STRING_APPEND_COPY_CAP);
                        if copy_len > 0 {
                            let last = (copy_len as i64).saturating_sub(1);
                            let src_base = self.stack_addr_temp(*slot, out);
                            let tmp = self.temp_reg();
                            out.push(VccInst::Load {
                                dst: tmp,
                                ptr: src_base,
                                offset: last,
                                size: 1,
                            });
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: last,
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }

                        let delta = self.temp_reg();
                        out.push(VccInst::Assume {
                            dst: delta,
                            ty: VccValueType::Scalar {
                                range: Some(VccRange {
                                    min: 0,
                                    max: copy_len as i64,
                                }),
                            },
                        });
                        out.push(VccInst::BinOp {
                            dst: len_reg,
                            op: VccBinOp::Add,
                            lhs: VccValue::Reg(len_reg),
                            rhs: VccValue::Reg(delta),
                        });
                    }
                    StringAppendType::Integer => {
                        let vcc_val = self.lower_value(val, out);
                        out.push(VccInst::AssertScalar { value: vcc_val });

                        let max_digits = MAX_INT_STRING_LEN;
                        if max_digits > 0 {
                            out.push(VccInst::Store {
                                ptr: dst_ptr,
                                offset: (max_digits as i64).saturating_sub(1),
                                src: VccValue::Imm(0),
                                size: 1,
                            });
                        }

                        let delta = self.temp_reg();
                        out.push(VccInst::Assume {
                            dst: delta,
                            ty: VccValueType::Scalar {
                                range: Some(VccRange {
                                    min: 1,
                                    max: max_digits as i64,
                                }),
                            },
                        });
                        out.push(VccInst::BinOp {
                            dst: len_reg,
                            op: VccBinOp::Add,
                            lhs: VccValue::Reg(len_reg),
                            rhs: VccValue::Reg(delta),
                        });
                    }
                }
            }
            MirInst::IntToString {
                dst_buffer,
                dst_len,
                val,
            } => {
                out.push(VccInst::AssertScalar {
                    value: VccValue::Reg(VccReg(val.0)),
                });

                let base = self.stack_addr_temp(*dst_buffer, out);
                let max_digits = MAX_INT_STRING_LEN;
                if max_digits > 0 {
                    out.push(VccInst::Store {
                        ptr: base,
                        offset: (max_digits as i64).saturating_sub(1),
                        src: VccValue::Imm(0),
                        size: 1,
                    });
                }

                out.push(VccInst::Assume {
                    dst: VccReg(dst_len.0),
                    ty: VccValueType::Scalar {
                        range: Some(VccRange {
                            min: 1,
                            max: max_digits as i64,
                        }),
                    },
                });
            }
            MirInst::RecordStore {
                buffer,
                field_offset,
                val,
                ty,
            } => {
                let size = ty.size();
                if size == 0 || size > u8::MAX as usize {
                    return Err(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        "record store size out of range",
                    ));
                }
                let base = self.stack_addr_temp(*buffer, out);
                let vcc_val = self.lower_value(val, out);
                out.push(VccInst::Store {
                    ptr: base,
                    offset: *field_offset as i64,
                    src: vcc_val,
                    size: size as u8,
                });
            }
            MirInst::ListNew { .. }
            | MirInst::ListPush { .. }
            | MirInst::ListLen { .. }
            | MirInst::ListGet { .. } => {
                return Err(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    "list operations must be lowered before VCC verification",
                ));
            }
            MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopHeader { .. }
            | MirInst::LoopBack { .. }
            | MirInst::Placeholder => {}
        }

        Ok(())
    }

    pub(super) fn lower_terminator(
        &mut self,
        term: &MirInst,
        out: &mut Vec<VccInst>,
    ) -> Result<VccTerminator, VccError> {
        match term {
            MirInst::Jump { target } => Ok(VccTerminator::Jump {
                target: VccBlockId(target.0),
            }),
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => Ok(VccTerminator::Branch {
                cond: VccValue::Reg(VccReg(cond.0)),
                if_true: VccBlockId(if_true.0),
                if_false: VccBlockId(if_false.0),
            }),
            MirInst::Return { val } => {
                let vcc_val = val.as_ref().map(|v| self.lower_value(v, out));
                Ok(VccTerminator::Return { value: vcc_val })
            }
            MirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    return Err(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!("tail_call requires ProgArray map, got {:?}", prog_map.kind),
                    ));
                }
                let vcc_val = self.lower_value(index, out);
                out.push(VccInst::AssertScalar { value: vcc_val });
                Ok(VccTerminator::Return { value: None })
            }
            MirInst::LoopHeader {
                counter,
                limit,
                body,
                exit,
            } => {
                let tmp = self.temp_reg();
                out.push(VccInst::BinOp {
                    dst: tmp,
                    op: VccBinOp::Lt,
                    lhs: VccValue::Reg(VccReg(counter.0)),
                    rhs: VccValue::Imm(*limit),
                });
                Ok(VccTerminator::Branch {
                    cond: VccValue::Reg(tmp),
                    if_true: VccBlockId(body.0),
                    if_false: VccBlockId(exit.0),
                })
            }
            MirInst::LoopBack {
                counter,
                step,
                header,
            } => {
                out.push(VccInst::BinOp {
                    dst: VccReg(counter.0),
                    op: VccBinOp::Add,
                    lhs: VccValue::Reg(VccReg(counter.0)),
                    rhs: VccValue::Imm(*step),
                });
                Ok(VccTerminator::Jump {
                    target: VccBlockId(header.0),
                })
            }
            MirInst::Placeholder => Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "placeholder terminator in VCC lowering",
            )),
            _ => Err(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                "non-terminator in terminator position",
            )),
        }
    }

}
