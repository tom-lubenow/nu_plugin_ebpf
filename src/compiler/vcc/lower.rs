struct VccLowerer<'a> {
    func: &'a MirFunction,
    types: &'a HashMap<VReg, MirType>,
    slot_sizes: HashMap<StackSlotId, usize>,
    slot_kinds: HashMap<StackSlotId, StackSlotKind>,
    list_max: HashMap<StackSlotId, usize>,
    ptr_regs: HashMap<VccReg, VccPointerInfo>,
    entry_ctx_field_regs: HashMap<String, VccReg>,
    next_temp: u32,
}

const STRING_APPEND_COPY_CAP: usize = 64;
const MAX_INT_STRING_LEN: usize = 20;

#[path = "lower/value_utils.rs"]
mod value_utils;

impl<'a> VccLowerer<'a> {
    fn new(
        func: &'a MirFunction,
        types: &'a HashMap<VReg, MirType>,
        list_max: HashMap<StackSlotId, usize>,
    ) -> Self {
        let mut slot_sizes = HashMap::new();
        let mut slot_kinds = HashMap::new();
        for slot in &func.stack_slots {
            slot_sizes.insert(slot.id, slot.size);
            slot_kinds.insert(slot.id, slot.kind);
        }
        let mut ptr_regs = HashMap::new();
        for (vreg, ty) in types {
            if let VccValueType::Ptr(info) = vcc_type_from_mir(ty) {
                ptr_regs.insert(VccReg(vreg.0), info);
            }
        }
        Self {
            func,
            types,
            slot_sizes,
            slot_kinds,
            list_max,
            ptr_regs,
            entry_ctx_field_regs: HashMap::new(),
            next_temp: func.vreg_count.max(func.param_count as u32),
        }
    }

    fn seed_types(&self) -> HashMap<VccReg, VccValueType> {
        let mut seed = HashMap::new();
        for (vreg, ty) in self.types {
            seed.insert(VccReg(vreg.0), vcc_type_from_mir(ty));
        }
        seed
    }

    fn lower(&mut self) -> Result<VccFunction, VccError> {
        let max_block = self.func.blocks.iter().map(|b| b.id.0).max().unwrap_or(0) as usize;
        let mut blocks = Vec::with_capacity(max_block + 1);
        for i in 0..=max_block {
            blocks.push(VccBlock {
                id: VccBlockId(i as u32),
                instructions: Vec::new(),
                terminator: VccTerminator::Return { value: None },
            });
        }

        for block in &self.func.blocks {
            let mut insts = Vec::new();
            let in_entry = block.id == self.func.entry;
            for inst in &block.instructions {
                self.lower_inst(inst, &mut insts, in_entry)?;
            }
            let term = self.lower_terminator(&block.terminator, &mut insts)?;
            let idx = block.id.0 as usize;
            blocks[idx] = VccBlock {
                id: VccBlockId(block.id.0),
                instructions: insts,
                terminator: term,
            };
        }

        Ok(VccFunction {
            entry: VccBlockId(self.func.entry.0),
            blocks,
            reg_count: self.next_temp,
        })
    }

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

    fn lower_inst(
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
                    if let Some(arg0) = args.first() {
                        out.push(VccInst::KfuncRelease {
                            ptr: VccValue::Reg(VccReg(arg0.0)),
                            kind,
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

    fn lower_terminator(
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

    fn verify_helper_call(
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
                self.verify_helper_arg_value(helper_id, idx, arg, sig.arg_kind(idx), out)?;
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

    fn verify_kfunc_call(
        &mut self,
        kfunc: &str,
        args: &[VReg],
        out: &mut Vec<VccInst>,
    ) -> Result<(), VccError> {
        let sig = KfuncSignature::for_name(kfunc).ok_or_else(|| {
            VccError::new(
                VccErrorKind::UnsupportedInstruction,
                format!("unknown kfunc '{}' (typed signature required)", kfunc),
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
                    self.require_pointer_reg(*arg)?;
                    self.verify_kfunc_ptr_arg_space(kfunc, idx, *arg)?;
                    if let Some(kind) = Self::kfunc_pointer_arg_expected_ref_kind(kfunc, idx) {
                        out.push(VccInst::KfuncExpectRefKind {
                            ptr: VccValue::Reg(VccReg(arg.0)),
                            arg_idx: idx,
                            kind,
                            kfunc: kfunc.to_string(),
                        });
                    }
                    if Self::kfunc_release_kind(kfunc).is_some() && idx == 0 {
                        self.check_ptr_range(*arg, 1, out)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_kfunc_ptr_arg_space(
        &self,
        kfunc: &str,
        arg_idx: usize,
        arg: VReg,
    ) -> Result<(), VccError> {
        if !Self::kfunc_pointer_arg_requires_kernel(kfunc, arg_idx) {
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

    fn effective_ptr_space(&self, reg: VReg) -> Option<VccAddrSpace> {
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

    fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
        kfunc_pointer_arg_requires_kernel_shared(kfunc, arg_idx)
    }

    fn kfunc_pointer_arg_expected_ref_kind(kfunc: &str, arg_idx: usize) -> Option<KfuncRefKind> {
        kfunc_pointer_arg_ref_kind(kfunc, arg_idx)
    }

    fn helper_pointer_arg_allows_const_zero(
        helper_id: u32,
        arg_idx: usize,
        arg: &MirValue,
    ) -> bool {
        matches!(BpfHelper::from_u32(helper_id), Some(BpfHelper::KptrXchg))
            && arg_idx == 1
            && matches!(arg, MirValue::Const(0))
    }

    fn verify_helper_arg_value(
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

    fn helper_space_allowed(
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

    fn helper_space_name(&self, space: VccAddrSpace) -> &'static str {
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

    fn helper_allowed_spaces_label(
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

    fn check_ptr_range_reg(
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

    fn check_helper_ptr_arg_value(
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

    fn check_helper_ringbuf_record_arg(
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

    fn helper_positive_size_upper_bound(
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

    fn verify_helper_semantics(
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

    fn verify_map_key(
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

    fn verify_map_value(&mut self, value: VReg, out: &mut Vec<VccInst>) -> Result<(), VccError> {
        self.verify_map_operand(value, "map value", out)
    }

    fn verify_map_operand(
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

    fn verify_read_str_ptr(
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
