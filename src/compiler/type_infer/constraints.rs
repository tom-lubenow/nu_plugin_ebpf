use super::*;
use crate::compiler::instruction::unknown_kfunc_signature_message;

impl<'a> TypeInference<'a> {
    /// Generate constraints for a basic block
    pub(super) fn generate_block_constraints(
        &mut self,
        block: &BasicBlock,
        errors: &mut Vec<TypeError>,
    ) {
        for inst in &block.instructions {
            if let Err(e) = self.generate_inst_constraints(inst) {
                errors.push(e);
            }
        }

        if let Err(e) = self.generate_inst_constraints(&block.terminator) {
            errors.push(e);
        }
    }

    /// Generate constraints for a single instruction
    pub(super) fn generate_inst_constraints(&mut self, inst: &MirInst) -> Result<(), TypeError> {
        match inst {
            MirInst::Copy { dst, src } => {
                let dst_ty = self.vreg_type(*dst);
                if matches!(src, MirValue::Const(0)) {
                    if let Some(hints) = self.type_hints
                        && let Some(dst_hint) = hints.get(dst)
                    {
                        self.constrain(dst_ty, HMType::from_mir_type(dst_hint), "copy_zero");
                    }
                    return Ok(());
                }

                // dst has same type as src
                let src_ty = self.value_type(src);
                self.constrain(dst_ty, src_ty, "copy");
            }

            MirInst::Load { dst, ty, .. } => {
                // dst has the specified type
                let dst_ty = self.vreg_type(*dst);
                let expected = HMType::from_mir_type(ty);
                self.constrain(dst_ty, expected, "load");
            }

            MirInst::LoadSlot { dst, ty, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let expected = HMType::from_mir_type(ty);
                self.constrain(dst_ty, expected, "load_slot");
            }

            MirInst::StoreCtxField { val, ty, .. } => {
                let val_ty = self.value_type(val);
                let expected = HMType::from_mir_type(ty);
                self.constrain(val_ty, expected, "store_ctx_field");
            }

            MirInst::BinOp { dst, op, lhs, rhs } => {
                let dst_ty = self.vreg_type(*dst);
                let lhs_ty = self.value_type(lhs);
                let rhs_ty = self.value_type(rhs);

                if matches!(op, BinOpKind::Add | BinOpKind::Sub)
                    && let Some(hints) = self.type_hints
                {
                    let hinted_ptr_ty = |vreg: VReg| {
                        hints
                            .get(&vreg)
                            .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                            .map(HMType::from_mir_type)
                    };
                    let dst_ptr_ty = hints
                        .get(dst)
                        .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                        .map(HMType::from_mir_type);
                    let ptr_ty = dst_ptr_ty.or_else(|| match op {
                        BinOpKind::Add => match (lhs, rhs) {
                            (MirValue::VReg(lhs_vreg), _) => hinted_ptr_ty(*lhs_vreg),
                            (_, MirValue::VReg(rhs_vreg)) => hinted_ptr_ty(*rhs_vreg),
                            _ => None,
                        },
                        BinOpKind::Sub => match lhs {
                            MirValue::VReg(lhs_vreg) => hinted_ptr_ty(*lhs_vreg),
                            _ => None,
                        },
                        _ => None,
                    });
                    if let Some(ptr_ty) = ptr_ty {
                        self.constrain(dst_ty.clone(), ptr_ty.clone(), format!("binop {:?}", op));
                        match op {
                            BinOpKind::Add => match (lhs, rhs) {
                                (MirValue::VReg(lhs_vreg), _) => {
                                    self.constrain(
                                        self.vreg_type(*lhs_vreg),
                                        hinted_ptr_ty(*lhs_vreg).unwrap_or_else(|| ptr_ty.clone()),
                                        "pointer_binop_lhs",
                                    );
                                    self.constrain(rhs_ty, HMType::I64, "pointer_binop_rhs");
                                }
                                (_, MirValue::VReg(rhs_vreg)) => {
                                    self.constrain(
                                        self.vreg_type(*rhs_vreg),
                                        hinted_ptr_ty(*rhs_vreg).unwrap_or_else(|| ptr_ty.clone()),
                                        "pointer_binop_rhs_ptr",
                                    );
                                    self.constrain(lhs_ty, HMType::I64, "pointer_binop_lhs");
                                }
                                _ => {
                                    self.constrain(lhs_ty, HMType::I64, "pointer_binop_lhs");
                                    self.constrain(rhs_ty, HMType::I64, "pointer_binop_rhs");
                                }
                            },
                            BinOpKind::Sub => {
                                if let MirValue::VReg(lhs_vreg) = lhs {
                                    self.constrain(
                                        self.vreg_type(*lhs_vreg),
                                        hinted_ptr_ty(*lhs_vreg).unwrap_or_else(|| ptr_ty.clone()),
                                        "pointer_binop_lhs",
                                    );
                                } else {
                                    self.constrain(lhs_ty, ptr_ty.clone(), "pointer_binop_lhs");
                                }
                                self.constrain(rhs_ty, HMType::I64, "pointer_binop_rhs");
                            }
                            _ => unreachable!("pointer binop hint only applies to add/sub"),
                        }
                        return Ok(());
                    }
                }

                // Generate constraints based on operator
                let result_ty = self.binop_result_type(*op, &lhs_ty, &rhs_ty)?;
                self.constrain(dst_ty, result_ty, format!("binop {:?}", op));
            }

            MirInst::UnaryOp { dst, op, src } => {
                let dst_ty = self.vreg_type(*dst);
                let src_ty = self.value_type(src);

                let result_ty = self.unaryop_result_type(*op, &src_ty)?;
                self.constrain(dst_ty, result_ty, format!("unaryop {:?}", op));
            }

            MirInst::CallHelper { dst, helper, args } => {
                let dst_ty = self.vreg_type(*dst);
                if let Some(sig) = HelperSignature::for_id(*helper) {
                    if let Some(helper_kind) = BpfHelper::from_u32(*helper) {
                        self.constrain_helper_map_args(helper_kind, args);
                    }
                    match sig.ret_kind {
                        HelperRetKind::Scalar => {
                            self.constrain(dst_ty, HMType::I64, "helper_call");
                        }
                        HelperRetKind::PointerNonNull | HelperRetKind::PointerMaybeNull => {
                            if let Some(helper_kind) = BpfHelper::from_u32(*helper)
                                && let Some(precise_ty) =
                                    TypeInference::precise_helper_return_mir_type(helper_kind)
                            {
                                self.constrain(
                                    dst_ty,
                                    HMType::from_mir_type(&precise_ty),
                                    "helper_call_ptr_ret",
                                );
                            } else {
                                let pointee = HMType::Var(self.tvar_gen.fresh());
                                let address_space = match BpfHelper::from_u32(*helper) {
                                    Some(BpfHelper::KptrXchg) => AddressSpace::Kernel,
                                    Some(helper) if helper_acquire_ref_kind(helper).is_some() => {
                                        AddressSpace::Kernel
                                    }
                                    _ => AddressSpace::Map,
                                };
                                let ptr_ty = HMType::Ptr {
                                    pointee: Box::new(pointee),
                                    address_space,
                                };
                                self.constrain(dst_ty, ptr_ty, "helper_call_ptr_ret");
                            }
                        }
                    }
                } else {
                    // Unknown helpers default to scalar return.
                    self.constrain(dst_ty, HMType::I64, "helper_call");
                }
            }

            MirInst::CallKfunc { dst, kfunc, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let sig = KfuncSignature::for_name_or_kernel_btf(kfunc)
                    .ok_or_else(|| TypeError::new(unknown_kfunc_signature_message(kfunc)))?;
                match sig.ret_kind {
                    KfuncRetKind::Scalar | KfuncRetKind::Void => {
                        self.constrain(dst_ty, HMType::I64, "kfunc_call");
                    }
                    KfuncRetKind::PointerMaybeNull => {
                        let ptr_ty = Self::precise_kfunc_return_mir_type(kfunc)
                            .map(|ty| HMType::from_mir_type(&ty))
                            .unwrap_or_else(|| HMType::Ptr {
                                pointee: Box::new(HMType::Var(self.tvar_gen.fresh())),
                                address_space: AddressSpace::Kernel,
                            });
                        self.constrain(dst_ty, ptr_ty, "kfunc_call_ptr_ret");
                    }
                }
            }

            MirInst::CallSubfn { dst, subfn, args } => {
                let dst_ty = self.vreg_type(*dst);
                let scheme = self
                    .subfn_schemes
                    .and_then(|env| env.get(subfn))
                    .ok_or_else(|| TypeError::new(format!("Unknown subfunction ID {:?}", subfn)))?;
                let inst = scheme.instantiate(&mut self.tvar_gen);
                match inst {
                    HMType::Fn {
                        args: expected_args,
                        ret,
                    } => {
                        if expected_args.len() != args.len() {
                            return Err(TypeError::new(format!(
                                "Subfunction {:?} expects {} args, got {}",
                                subfn,
                                expected_args.len(),
                                args.len()
                            )));
                        }
                        for (arg_vreg, expected) in args.iter().zip(expected_args.iter()) {
                            let arg_ty = self.vreg_type(*arg_vreg);
                            self.constrain(arg_ty, expected.clone(), "subfn_arg");
                        }
                        self.constrain(dst_ty, *ret, "subfn_ret");
                    }
                    _ => {
                        return Err(TypeError::new(format!(
                            "Subfunction scheme is not a function type: {}",
                            inst
                        )));
                    }
                }
            }

            MirInst::MapLookup { dst, .. } => {
                // Map lookup returns pointer to value
                let dst_ty = self.vreg_type(*dst);
                let pointee = HMType::Var(self.tvar_gen.fresh());
                let ptr_ty = HMType::Ptr {
                    pointee: Box::new(pointee),
                    address_space: AddressSpace::Map,
                };
                self.constrain(dst_ty, ptr_ty, "map_lookup");
            }

            MirInst::LoadGlobal { dst, ty, .. } => {
                let dst_ty = self.vreg_type(*dst);
                let ptr_ty = HMType::Ptr {
                    pointee: Box::new(HMType::from_mir_type(ty)),
                    address_space: AddressSpace::Map,
                };
                self.constrain(dst_ty, ptr_ty, "global_load");
            }

            MirInst::LoadMapFd { dst, map } => {
                let dst_ty = self.vreg_type(*dst);
                let (key_ty, val_ty) = match map.kind {
                    MapKind::DevMap | MapKind::DevMapHash | MapKind::CpuMap | MapKind::XskMap => {
                        (HMType::U32, HMType::Unknown)
                    }
                    MapKind::SockMap | MapKind::ProgArray | MapKind::PerfEventArray => {
                        (HMType::U32, HMType::U32)
                    }
                    MapKind::SockHash => (HMType::Var(self.tvar_gen.fresh()), HMType::U32),
                    MapKind::Queue | MapKind::Stack | MapKind::RingBuf => {
                        (HMType::Unknown, HMType::Unknown)
                    }
                    MapKind::StackTrace => (HMType::U32, HMType::Unknown),
                    MapKind::SkStorage | MapKind::InodeStorage | MapKind::TaskStorage => {
                        (HMType::U32, HMType::Unknown)
                    }
                    _ => (HMType::Unknown, HMType::Unknown),
                };
                let map_ty = HMType::MapRef {
                    key_ty: Box::new(key_ty),
                    val_ty: Box::new(val_ty),
                };
                self.constrain(dst_ty, map_ty, "load_map_fd");
            }

            MirInst::LoadCtxField { dst, field, .. } => {
                self.validate_ctx_field_access(field)?;
                let dst_ty = self.vreg_type(*dst);
                let field_ty = self.ctx_field_type(field);
                self.constrain(dst_ty, field_ty, format!("ctx.{:?}", field));
            }

            MirInst::StrCmp { dst, .. } => {
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::Bool, "strcmp");
            }

            MirInst::StopTimer { dst } => {
                let dst_ty = self.vreg_type(*dst);
                self.constrain(dst_ty, HMType::U64, "stop_timer");
            }

            MirInst::LoopHeader { counter, .. } => {
                let counter_ty = self.vreg_type(*counter);
                self.constrain(counter_ty, HMType::I64, "loop_counter");
            }

            MirInst::ListNew { dst, max_len, .. } => {
                // List pointer is essentially a pointer to stack (list buffer)
                let dst_ty = self.vreg_type(*dst);
                let list_ptr_ty = self.list_pointer_type(Some(*dst), Some(*max_len));
                self.constrain(dst_ty, list_ptr_ty, "list_new");
            }

            MirInst::ListLen { dst, list } => {
                // Length is u64
                let dst_ty = self.vreg_type(*dst);
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = self.list_pointer_type(Some(*list), None);
                self.constrain(dst_ty, HMType::U64, "list_len");
                self.constrain(list_ty, list_ptr_ty, "list_len_src");
            }

            MirInst::ListGet { dst, list, .. } => {
                // Element is i64 (all values stored as 64-bit)
                let dst_ty = self.vreg_type(*dst);
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = self.list_pointer_type(Some(*list), None);
                self.constrain(dst_ty, HMType::I64, "list_get");
                self.constrain(list_ty, list_ptr_ty, "list_get_src");
            }

            MirInst::Phi { dst, args } => {
                // Phi destination has same type as all its arguments
                let dst_ty = self.vreg_type(*dst);
                for (_, arg_vreg) in args {
                    let arg_ty = self.vreg_type(*arg_vreg);
                    self.constrain(dst_ty.clone(), arg_ty, "phi");
                }
            }

            MirInst::ReadStr {
                ptr, user_space, ..
            } => {
                let ptr_ty = self.vreg_type(*ptr);
                let expected = HMType::Ptr {
                    pointee: Box::new(HMType::U8),
                    address_space: if *user_space {
                        AddressSpace::User
                    } else {
                        AddressSpace::Kernel
                    },
                };
                self.constrain(ptr_ty, expected, "read_str_ptr");
            }

            MirInst::StringAppend {
                dst_len,
                val,
                val_type,
                ..
            } => {
                let len_ty = self.vreg_type(*dst_len);
                self.constrain(len_ty, HMType::U64, "string_len");
                if matches!(val_type, StringAppendType::Integer) {
                    let val_ty = self.value_type(val);
                    self.constrain(val_ty, HMType::I64, "string_append_int");
                }
            }

            MirInst::IntToString { dst_len, val, .. } => {
                let len_ty = self.vreg_type(*dst_len);
                self.constrain(len_ty, HMType::U64, "int_to_string_len");
                let val_ty = self.vreg_type(*val);
                self.constrain(val_ty, HMType::I64, "int_to_string_val");
            }

            MirInst::ListPush { list, item } => {
                let list_ty = self.vreg_type(*list);
                let list_ptr_ty = self.list_pointer_type(Some(*list), None);
                let item_ty = self.vreg_type(*item);
                self.constrain(list_ty, list_ptr_ty, "list_push_list");
                self.constrain(item_ty, HMType::I64, "list_push_item");
            }

            MirInst::Return { val } => {
                if let (Some(ret_var), Some(value)) = (self.return_var, val.as_ref()) {
                    let value_ty = self.value_type(value);
                    self.constrain(HMType::Var(ret_var), value_ty, "return");
                }
            }

            // Instructions that don't define a vreg - no constraints needed
            MirInst::Store { .. }
            | MirInst::StoreSlot { .. }
            | MirInst::MapUpdate { .. }
            | MirInst::MapDelete { .. }
            | MirInst::MapPush { .. }
            | MirInst::Histogram { .. }
            | MirInst::StartTimer
            | MirInst::EmitEvent { .. }
            | MirInst::EmitRecord { .. }
            | MirInst::RecordStore { .. }
            | MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopBack { .. }
            | MirInst::Placeholder => {}
        }

        Ok(())
    }

    /// Get the type variable for a vreg as an HMType
    pub(super) fn vreg_type(&self, vreg: VReg) -> HMType {
        if let Some(&tvar) = self.vreg_vars.get(&vreg) {
            HMType::Var(tvar)
        } else {
            HMType::Unknown
        }
    }

    /// Get the type of a MirValue
    pub(super) fn value_type(&mut self, value: &MirValue) -> HMType {
        match value {
            MirValue::VReg(vreg) => self.vreg_type(*vreg),
            MirValue::Const(_) => HMType::I64,
            MirValue::StackSlot(slot) => self
                .stack_slot_hints
                .and_then(|hints| hints.get(slot))
                .map(HMType::from_mir_type)
                .map(|pointee| HMType::Ptr {
                    pointee: Box::new(pointee),
                    address_space: AddressSpace::Stack,
                })
                .unwrap_or(HMType::Ptr {
                    pointee: Box::new(HMType::U8),
                    address_space: AddressSpace::Stack,
                }),
        }
    }

    fn list_pointer_type(&mut self, list_vreg: Option<VReg>, max_len: Option<usize>) -> HMType {
        if let Some(vreg) = list_vreg
            && let Some(hint) = self.type_hints.and_then(|hints| hints.get(&vreg))
        {
            return HMType::from_mir_type(hint);
        }

        let pointee = if let Some(max_len) = max_len {
            HMType::Array {
                elem: Box::new(HMType::I64),
                len: max_len.saturating_add(1),
            }
        } else {
            HMType::Var(self.tvar_gen.fresh())
        };

        HMType::Ptr {
            pointee: Box::new(pointee),
            address_space: AddressSpace::Stack,
        }
    }

    fn constrain_helper_map_args(&mut self, helper: BpfHelper, args: &[MirValue]) {
        let Some(map_arg_idx) = helper.local_helper_map_arg_index() else {
            return;
        };
        let Some(MirValue::VReg(map_vreg)) = args.get(map_arg_idx) else {
            return;
        };

        let map_ty = match helper {
            BpfHelper::RedirectMap => HMType::MapRef {
                key_ty: Box::new(HMType::U32),
                val_ty: Box::new(HMType::Unknown),
            },
            BpfHelper::SkRedirectMap | BpfHelper::SockMapUpdate | BpfHelper::MsgRedirectMap => {
                HMType::MapRef {
                    key_ty: Box::new(HMType::U32),
                    val_ty: Box::new(HMType::U32),
                }
            }
            BpfHelper::SockHashUpdate | BpfHelper::MsgRedirectHash | BpfHelper::SkRedirectHash => {
                let key_ty = match args.get(2).map(|value| self.value_type(value)) {
                    Some(HMType::Ptr { pointee, .. }) => *pointee,
                    Some(other) => other,
                    None => return,
                };
                HMType::MapRef {
                    key_ty: Box::new(key_ty),
                    val_ty: Box::new(HMType::U32),
                }
            }
            BpfHelper::MapPushElem | BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                let hinted_map_ref = self
                    .type_hints
                    .and_then(|hints| hints.get(map_vreg))
                    .is_some_and(|ty| matches!(ty, MirType::MapRef { .. }));
                if !hinted_map_ref {
                    return;
                }
                let val_ty = match args.get(1).map(|value| self.value_type(value)) {
                    Some(HMType::Ptr { pointee, .. }) => *pointee,
                    Some(other) => other,
                    None => return,
                };
                HMType::MapRef {
                    key_ty: Box::new(HMType::Unknown),
                    val_ty: Box::new(val_ty),
                }
            }
            _ => return,
        };

        self.constrain(
            self.vreg_type(*map_vreg),
            map_ty,
            format!("helper_map_ref {}", helper.name()),
        );
    }

    pub(super) fn constrain(
        &mut self,
        expected: HMType,
        actual: HMType,
        context: impl Into<String>,
    ) {
        self.constraints
            .push(Constraint::new(expected, actual, context));
    }
}
