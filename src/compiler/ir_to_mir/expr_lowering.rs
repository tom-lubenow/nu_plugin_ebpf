use super::*;
use crate::compiler::ProgramValueAccess;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::compiler::mir::StructField;
use crate::compiler::mir::UnaryOpKind;
use crate::kernel_btf::{
    KernelBtf, TrampolineBitfieldInfo, TrampolineFieldProjection, TrampolineFieldSelector,
    TrampolineValueKind, TrampolineValueSpec, TypeInfo,
};

mod packet;
mod trampoline;

use trampoline::TypedProjectionStep;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn synthetic_bpf_sock_type() -> MirType {
        MirType::Struct {
            name: Some("bpf_sock".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "bound_dev_if".to_string(),
                    ty: MirType::U32,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "family".to_string(),
                    ty: MirType::U32,
                    offset: 4,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "type".to_string(),
                    ty: MirType::U32,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "protocol".to_string(),
                    ty: MirType::U32,
                    offset: 12,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "mark".to_string(),
                    ty: MirType::U32,
                    offset: 16,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "priority".to_string(),
                    ty: MirType::U32,
                    offset: 20,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "src_port".to_string(),
                    ty: MirType::U32,
                    offset: 44,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dst_port".to_string(),
                    ty: MirType::U16,
                    offset: 48,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "state".to_string(),
                    ty: MirType::U32,
                    offset: 72,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "rx_queue_mapping".to_string(),
                    ty: MirType::I32,
                    offset: 76,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }
    }

    pub(super) fn lower_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: nu_protocol::ast::Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::{Boolean, Comparison, Math, Operator};

        let lhs_vreg = self.get_vreg(lhs_dst);
        let rhs_vreg = self.get_vreg(rhs);

        let mir_op = match op {
            Operator::Math(Math::Add) => BinOpKind::Add,
            Operator::Math(Math::Subtract) => BinOpKind::Sub,
            Operator::Math(Math::Multiply) => BinOpKind::Mul,
            Operator::Math(Math::Divide) => BinOpKind::Div,
            Operator::Math(Math::Modulo) => BinOpKind::Mod,
            Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
            Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
            Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
            Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
            Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
            Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
            Operator::Bits(nu_protocol::ast::Bits::BitAnd) => BinOpKind::And,
            Operator::Bits(nu_protocol::ast::Bits::BitOr) => BinOpKind::Or,
            Operator::Bits(nu_protocol::ast::Bits::BitXor) => BinOpKind::Xor,
            Operator::Bits(nu_protocol::ast::Bits::ShiftLeft) => BinOpKind::Shl,
            Operator::Bits(nu_protocol::ast::Bits::ShiftRight) => BinOpKind::Shr,
            // Logical and/or - use bitwise ops since comparisons return 0 or 1
            Operator::Boolean(Boolean::And) => BinOpKind::And,
            Operator::Boolean(Boolean::Or) => BinOpKind::Or,
            Operator::Boolean(Boolean::Xor) => BinOpKind::Xor,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Operator {:?} not supported in eBPF",
                    op
                )));
            }
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: mir_op,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });
        self.clear_source_var(lhs_dst);

        Ok(())
    }

    /// Lower Match instruction (used for pattern matching and short-circuit boolean evaluation)
    pub(super) fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);

        match pattern {
            Pattern::Value(value) => match value {
                Value::Bool { val, .. } => {
                    if *val {
                        self.terminate(MirInst::Branch {
                            cond: src_vreg,
                            if_true,
                            if_false,
                        });
                    } else {
                        let tmp = self.func.alloc_vreg();
                        self.emit(MirInst::UnaryOp {
                            dst: tmp,
                            op: crate::compiler::mir::UnaryOpKind::Not,
                            src: MirValue::VReg(src_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: tmp,
                            if_true,
                            if_false,
                        });
                    }
                }
                Value::Nothing { .. } => {
                    let cmp_result = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_result,
                        op: BinOpKind::Eq,
                        lhs: MirValue::VReg(src_vreg),
                        rhs: MirValue::Const(0),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_result,
                        if_true,
                        if_false,
                    });
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Match against value type {:?} not supported in eBPF",
                        value.get_type()
                    )));
                }
            },
            Pattern::Variable(var_id) => {
                self.var_mappings.insert(*var_id, src_vreg);
                self.terminate(MirInst::Jump { target: if_true });
            }
            Pattern::IgnoreValue => {
                self.terminate(MirInst::Jump { target: if_true });
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "Pattern matching not supported in eBPF".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn typed_value_path_desc(path: &[PathMember]) -> String {
        let mut out = String::new();
        for (idx, member) in path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match member {
                PathMember::String { val, .. } => out.push_str(val),
                PathMember::Int { val, .. } => out.push_str(&val.to_string()),
            }
        }
        out
    }

    pub(super) fn typed_value_runtime_type(&self, reg: RegId, vreg: VReg) -> Option<MirType> {
        self.vreg_type_hints
            .get(&vreg)
            .cloned()
            .or_else(|| self.current_type_hints.get(&reg.get()).cloned())
            .or_else(|| self.get_metadata(reg).and_then(|m| m.field_type.clone()))
    }

    fn mir_type_is_signed(ty: &MirType) -> bool {
        matches!(ty, MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64)
    }

    fn mir_type_is_unsigned(ty: &MirType) -> bool {
        matches!(ty, MirType::U8 | MirType::U16 | MirType::U32 | MirType::U64)
    }

    pub(super) fn coerce_scalar_assignment_value(
        &mut self,
        src_vreg: VReg,
        src_ty: &MirType,
        dst_ty: &MirType,
    ) -> Option<VReg> {
        if src_ty == dst_ty {
            return Some(src_vreg);
        }

        let src_size = src_ty.size();
        let dst_size = dst_ty.size();
        if src_size == 0 || dst_size == 0 || src_size > dst_size {
            return None;
        }

        if Self::mir_type_is_unsigned(src_ty) && Self::mir_type_is_unsigned(dst_ty) {
            let widened = self.func.alloc_vreg();
            self.vreg_type_hints.insert(widened, dst_ty.clone());
            self.emit(MirInst::Copy {
                dst: widened,
                src: MirValue::VReg(src_vreg),
            });
            return Some(widened);
        }

        if Self::mir_type_is_signed(src_ty) && Self::mir_type_is_signed(dst_ty) {
            let sign_bit_shift = u32::try_from(src_size.checked_mul(8)?.checked_sub(1)?).ok()?;
            let sign_bit = 1i64.checked_shl(sign_bit_shift)?;
            let sign_bit_value = self.large_const_operand(dst_ty, sign_bit);
            let xor_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(xor_vreg, dst_ty.clone());
            self.emit(MirInst::BinOp {
                dst: xor_vreg,
                op: BinOpKind::Xor,
                lhs: MirValue::VReg(src_vreg),
                rhs: sign_bit_value,
            });

            let sign_bit_value = self.large_const_operand(dst_ty, sign_bit);
            let widened = self.func.alloc_vreg();
            self.vreg_type_hints.insert(widened, dst_ty.clone());
            self.emit(MirInst::BinOp {
                dst: widened,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(xor_vreg),
                rhs: sign_bit_value,
            });
            return Some(widened);
        }

        None
    }

    pub(super) fn large_const_operand(&mut self, ty: &MirType, value: i64) -> MirValue {
        if i32::try_from(value).is_ok() {
            return MirValue::Const(value);
        }

        let const_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(const_vreg, ty.clone());
        self.emit(MirInst::Copy {
            dst: const_vreg,
            src: MirValue::Const(value),
        });
        MirValue::VReg(const_vreg)
    }

    pub(super) fn emit_xdp_packet_guarded_load(
        &mut self,
        dst_vreg: VReg,
        packet_ptr_vreg: VReg,
        load_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if matches!(
            load_ty,
            MirType::Array { .. }
                | MirType::Struct { .. }
                | MirType::Ptr { .. }
                | MirType::MapRef { .. }
                | MirType::Unknown
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' requires a scalar element type, got {:?}",
                path_desc, load_ty
            )));
        }

        let access_size = i64::try_from(load_ty.size()).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' has unsupported size {}",
                path_desc,
                load_ty.size()
            ))
        })?;
        if access_size <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "xdp packet load for '{}' requires positive size",
                path_desc
            )));
        }

        self.vreg_type_hints.insert(dst_vreg, load_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let data_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(data_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: data_end_vreg,
            field: CtxField::DataEnd,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(access_end_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(packet_ptr_vreg),
            rhs: MirValue::Const(access_size),
        });

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(data_end_vreg),
        });

        let load_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: load_block,
            if_false: join_block,
        });

        self.current_block = load_block;
        self.emit(MirInst::Load {
            dst: dst_vreg,
            ptr: packet_ptr_vreg,
            offset: 0,
            ty: load_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }

    pub(super) fn emit_packet_big_endian_scalar_normalize(
        &mut self,
        dst_vreg: VReg,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let hint = ty.clone();
        match ty {
            MirType::U16 => {
                let mask_ff = self.large_const_operand(ty, 0xff);
                let shift_8 = self.large_const_operand(ty, 8);
                let low = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });

                let low_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(low_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: low_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(low),
                    rhs: shift_8.clone(),
                });

                let high = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8,
                });

                let high_masked = self.func.alloc_vreg();
                self.vreg_type_hints.insert(high_masked, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: high_masked,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(high),
                    rhs: mask_ff,
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(low_shifted),
                    rhs: MirValue::VReg(high_masked),
                });
                Ok(())
            }
            MirType::U32 => {
                let mask_ff = self.large_const_operand(ty, 0x0000_00ff);
                let mask_ff00 = self.large_const_operand(ty, 0x0000_ff00);
                let shift_8 = self.large_const_operand(ty, 8);
                let shift_24 = self.large_const_operand(ty, 24);
                let b0 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff.clone(),
                });
                let b0_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b0_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b0_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b0),
                    rhs: shift_24.clone(),
                });

                let b1 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: mask_ff00.clone(),
                });
                let b1_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b1_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b1_shifted,
                    op: BinOpKind::Shl,
                    lhs: MirValue::VReg(b1),
                    rhs: shift_8.clone(),
                });

                let b2_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_8.clone(),
                });
                let b2 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b2, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b2,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b2_shifted),
                    rhs: mask_ff00,
                });

                let b3_shifted = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3_shifted, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3_shifted,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_24,
                });
                let b3 = self.func.alloc_vreg();
                self.vreg_type_hints.insert(b3, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: b3,
                    op: BinOpKind::And,
                    lhs: MirValue::VReg(b3_shifted),
                    rhs: mask_ff,
                });

                let hi = self.func.alloc_vreg();
                self.vreg_type_hints.insert(hi, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: hi,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b0_shifted),
                    rhs: MirValue::VReg(b1_shifted),
                });
                let lo = self.func.alloc_vreg();
                self.vreg_type_hints.insert(lo, hint.clone());
                self.emit(MirInst::BinOp {
                    dst: lo,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(b2),
                    rhs: MirValue::VReg(b3),
                });

                self.vreg_type_hints.insert(dst_vreg, hint);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Or,
                    lhs: MirValue::VReg(hi),
                    rhs: MirValue::VReg(lo),
                });
                Ok(())
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "big-endian packet scalar normalization is not supported for {:?}",
                ty
            ))),
        }
    }

    pub(super) fn normalize_host_order_u32_array_slot(
        &mut self,
        base_ptr_vreg: VReg,
    ) -> Result<(), CompileError> {
        let element_ty = MirType::U32;
        for index in 0..4 {
            let word_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(word_vreg, element_ty.clone());
            self.emit(MirInst::Load {
                dst: word_vreg,
                ptr: base_ptr_vreg,
                offset: (index * 4) as i32,
                ty: element_ty.clone(),
            });
            self.emit_packet_big_endian_scalar_normalize(word_vreg, &element_ty)?;
            self.emit(MirInst::Store {
                ptr: base_ptr_vreg,
                offset: (index * 4) as i32,
                val: MirValue::VReg(word_vreg),
                ty: element_ty.clone(),
            });
        }
        Ok(())
    }

    pub(super) fn lower_typed_value_projection(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
        projected_semantics: Option<&AnnotatedValueSemantics>,
    ) -> Result<MirType, CompileError> {
        let projected_by_ref =
            |ty: &MirType| matches!(ty, MirType::Array { .. } | MirType::Struct { .. });

        enum ValueCursor {
            Pointer {
                base_vreg: VReg,
                address_space: AddressSpace,
                base_offset: usize,
                target_ty: MirType,
                direct: bool,
            },
            PacketScalar {
                base_vreg: VReg,
                base_offset: usize,
                element_ty: MirType,
                element_size: usize,
                big_endian: bool,
            },
        }

        let mut cursor = match base_runtime_ty {
            MirType::Ptr {
                pointee,
                address_space,
            } => ValueCursor::Pointer {
                base_vreg,
                address_space: *address_space,
                base_offset: 0,
                target_ty: pointee.as_ref().clone(),
                direct: true,
            },
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' requires a typed pointer value, got {:?}",
                    path_desc, base_runtime_ty
                )));
            }
        };

        for (segment_idx, member) in path_members.iter().enumerate() {
            let is_last = segment_idx + 1 == path_members.len();
            if let ValueCursor::PacketScalar {
                base_vreg,
                base_offset,
                element_ty,
                element_size,
                big_endian,
            } = &cursor
            {
                let packet_offset = match member {
                    PathMember::Int { val, .. } => {
                        let index = usize::try_from(*val).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "typed field path '{}' requires a non-negative packet scalar index",
                                path_desc
                            ))
                        })?;
                        base_offset
                            .checked_add(index.checked_mul(*element_size).ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' packet scalar index overflowed",
                                    path_desc
                                ))
                            })?)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' offset overflowed",
                                    path_desc
                                ))
                            })?
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' expects a numeric index after packet scalar view",
                            path_desc
                        )));
                    }
                };

                if !is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' does not support nested projection after a packet scalar index",
                        path_desc
                    )));
                }

                let packet_ptr_vreg = if packet_offset == 0 {
                    *base_vreg
                } else {
                    let ptr_vreg = self.func.alloc_vreg();
                    self.vreg_type_hints.insert(
                        ptr_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: AddressSpace::Packet,
                        },
                    );
                    self.emit(MirInst::BinOp {
                        dst: ptr_vreg,
                        op: BinOpKind::Add,
                        lhs: MirValue::VReg(*base_vreg),
                        rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                            packet_offset,
                            path_desc,
                        )?)),
                    });
                    ptr_vreg
                };
                let packet_ptr_vreg = self.packet_load_ptr_vreg(
                    packet_ptr_vreg,
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::Packet,
                    },
                    dst_vreg,
                );

                self.emit_xdp_packet_guarded_load(
                    dst_vreg,
                    packet_ptr_vreg,
                    element_ty,
                    path_desc,
                )?;
                if *big_endian {
                    self.emit_packet_big_endian_scalar_normalize(dst_vreg, element_ty)?;
                }
                return Ok(element_ty.clone());
            }

            loop {
                let ValueCursor::Pointer {
                    base_vreg,
                    address_space,
                    base_offset,
                    target_ty,
                    direct,
                } = &cursor
                else {
                    break;
                };
                let MirType::Ptr {
                    pointee,
                    address_space: next_space,
                } = target_ty
                else {
                    break;
                };
                if *direct && matches!(member, PathMember::Int { .. }) {
                    break;
                }

                let current_base_vreg = *base_vreg;
                let current_address_space = *address_space;
                let current_base_offset = *base_offset;
                let next_space = *next_space;
                let ptr_ty = MirType::Ptr {
                    pointee: pointee.clone(),
                    address_space: next_space,
                };
                let ptr_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(ptr_vreg, ptr_ty.clone());
                match current_address_space {
                    AddressSpace::Stack | AddressSpace::Map => {
                        self.emit(MirInst::Load {
                            dst: ptr_vreg,
                            ptr: current_base_vreg,
                            offset: Self::trampoline_projection_offset_i32(
                                current_base_offset,
                                path_desc,
                            )?,
                            ty: ptr_ty,
                        });
                    }
                    AddressSpace::Kernel | AddressSpace::User => {
                        let pointer_slot =
                            self.func
                                .alloc_stack_slot(align_to_eight(8), 8, StackSlotKind::Local);
                        self.record_stack_slot_type(pointer_slot, ptr_ty.clone());
                        self.emit_trampoline_probe_read_to_slot(
                            current_base_vreg,
                            current_address_space,
                            current_base_offset,
                            pointer_slot,
                            &ptr_ty,
                            path_desc,
                        )?;
                        self.emit(MirInst::LoadSlot {
                            dst: ptr_vreg,
                            slot: pointer_slot,
                            offset: 0,
                            ty: ptr_ty,
                        });
                    }
                    AddressSpace::Packet => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "xdp packet path '{}' does not support nested pointer dereferences",
                            path_desc
                        )));
                    }
                }
                cursor = ValueCursor::Pointer {
                    base_vreg: ptr_vreg,
                    address_space: next_space,
                    base_offset: 0,
                    target_ty: pointee.as_ref().clone(),
                    direct: true,
                };
            }

            let ValueCursor::Pointer {
                base_vreg,
                address_space,
                base_offset,
                target_ty,
                direct,
            } = &cursor
            else {
                continue;
            };

            if *address_space == AddressSpace::Packet {
                if let Some(kind) = Self::packet_payload_step_kind(target_ty, member) {
                    let payload_ptr_vreg = self.emit_packet_payload_ptr_step(
                        *base_vreg,
                        *base_offset,
                        kind,
                        path_desc,
                    )?;
                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(MirType::U8),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(payload_ptr_vreg),
                        });
                        return Ok(MirType::U8);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: payload_ptr_vreg,
                        address_space: *address_space,
                        base_offset: 0,
                        target_ty: MirType::U8,
                        direct: true,
                    };
                    continue;
                }

                if let Some(TypedProjectionStep {
                    offset: view_offset,
                    ty: view_ty,
                    ..
                }) = Self::packet_header_view_spec(target_ty, member)
                {
                    let field_offset = base_offset.checked_add(view_offset).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' offset overflowed",
                            path_desc
                        ))
                    })?;

                    if is_last {
                        self.vreg_type_hints.insert(
                            dst_vreg,
                            MirType::Ptr {
                                pointee: Box::new(view_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                        );
                        if field_offset == 0 {
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::VReg(*base_vreg),
                            });
                        } else {
                            self.emit(MirInst::BinOp {
                                dst: dst_vreg,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(*base_vreg),
                                rhs: MirValue::Const(i64::from(
                                    Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                )),
                            });
                        }
                        return Ok(view_ty);
                    }

                    cursor = ValueCursor::Pointer {
                        base_vreg: *base_vreg,
                        address_space: *address_space,
                        base_offset: field_offset,
                        target_ty: view_ty,
                        direct: false,
                    };
                    continue;
                }

                if matches!(target_ty, MirType::U8)
                    && let Some((element_ty, element_size, big_endian)) =
                        Self::packet_scalar_view_spec(member)
                {
                    if is_last {
                        let packet_ptr_vreg = self.packet_load_ptr_vreg(
                            *base_vreg,
                            MirType::Ptr {
                                pointee: Box::new(target_ty.clone()),
                                address_space: AddressSpace::Packet,
                            },
                            dst_vreg,
                        );
                        self.emit_xdp_packet_guarded_load(
                            dst_vreg,
                            packet_ptr_vreg,
                            &element_ty,
                            path_desc,
                        )?;
                        if big_endian {
                            self.emit_packet_big_endian_scalar_normalize(dst_vreg, &element_ty)?;
                        }
                        return Ok(element_ty);
                    }

                    cursor = ValueCursor::PacketScalar {
                        base_vreg: *base_vreg,
                        base_offset: *base_offset,
                        element_ty,
                        element_size,
                        big_endian,
                    };
                    continue;
                }
            }

            let TypedProjectionStep {
                offset: segment_offset,
                ty: next_ty,
                bitfield,
                packet_big_endian,
            } = match (direct, member) {
                (true, PathMember::Int { val, .. })
                    if !matches!(target_ty, MirType::Array { .. }) =>
                {
                    Self::resolve_pointer_sequence_index_step(target_ty, *val, path_desc)?
                }
                _ => Self::resolve_typed_value_projection_step(target_ty, member, path_desc)?,
            };
            let field_offset = base_offset.checked_add(segment_offset).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' offset overflowed",
                    path_desc
                ))
            })?;

            if is_last {
                if projected_by_ref(&next_ty) {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map => {
                            if let Some(AnnotatedValueSemantics::NumericList { max_len }) =
                                projected_semantics
                            {
                                let buffer_size =
                                    (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
                                let slot = self.func.alloc_stack_slot(
                                    buffer_size,
                                    8,
                                    StackSlotKind::ListBuffer,
                                );
                                self.record_list_buffer_slot_type(slot, *max_len);
                                self.emit(MirInst::ListNew {
                                    dst: dst_vreg,
                                    buffer: slot,
                                    max_len: *max_len,
                                });
                                self.vreg_type_hints.insert(
                                    dst_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(next_ty.clone()),
                                        address_space: AddressSpace::Stack,
                                    },
                                );
                                self.emit_ptr_to_slot_copy(
                                    slot,
                                    0,
                                    *base_vreg,
                                    field_offset,
                                    next_ty.size(),
                                )?;
                                let meta = self.get_or_create_metadata(dst_reg);
                                meta.list_buffer = Some((slot, *max_len));
                                meta.annotated_semantics = projected_semantics.cloned();
                                return Ok(next_ty);
                            }
                            if let Some(AnnotatedValueSemantics::String {
                                slot_len,
                                content_cap,
                            }) = projected_semantics
                            {
                                let slot = self.func.alloc_stack_slot(
                                    *slot_len,
                                    8,
                                    StackSlotKind::StringBuffer,
                                );
                                self.record_stack_slot_type(
                                    slot,
                                    MirType::Array {
                                        elem: Box::new(MirType::U8),
                                        len: *slot_len,
                                    },
                                );
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::StackSlot(slot),
                                });
                                self.vreg_type_hints.insert(
                                    dst_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(MirType::Array {
                                            elem: Box::new(MirType::U8),
                                            len: *slot_len,
                                        }),
                                        address_space: AddressSpace::Stack,
                                    },
                                );
                                let len_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::Load {
                                    dst: len_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: MirType::U64,
                                });
                                self.vreg_type_hints.insert(len_vreg, MirType::U64);
                                self.emit_ptr_to_slot_copy(
                                    slot,
                                    0,
                                    *base_vreg,
                                    field_offset.saturating_add(8),
                                    *slot_len,
                                )?;
                                let meta = self.get_or_create_metadata(dst_reg);
                                meta.string_slot = Some(slot);
                                meta.string_len_vreg = Some(len_vreg);
                                meta.string_len_bound = Some(*content_cap);
                                meta.annotated_semantics = projected_semantics.cloned();
                                return Ok(next_ty);
                            }
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            let projected_slot = self.func.alloc_stack_slot(
                                align_to_eight(next_ty.size()),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(projected_slot, next_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                *base_vreg,
                                *address_space,
                                field_offset,
                                projected_slot,
                                &next_ty,
                                path_desc,
                            )?;
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Stack,
                                },
                            );
                            self.emit(MirInst::Copy {
                                dst: dst_vreg,
                                src: MirValue::StackSlot(projected_slot),
                            });
                        }
                        AddressSpace::Packet => {
                            self.vreg_type_hints.insert(
                                dst_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: *address_space,
                                },
                            );
                            if field_offset == 0 {
                                self.emit(MirInst::Copy {
                                    dst: dst_vreg,
                                    src: MirValue::VReg(*base_vreg),
                                });
                            } else {
                                self.emit(MirInst::BinOp {
                                    dst: dst_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                            }
                        }
                    }
                } else {
                    match address_space {
                        AddressSpace::Stack | AddressSpace::Map => {
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: storage_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::Load {
                                    dst: dst_vreg,
                                    ptr: *base_vreg,
                                    offset: Self::trampoline_projection_offset_i32(
                                        field_offset,
                                        path_desc,
                                    )?,
                                    ty: next_ty.clone(),
                                });
                            }
                        }
                        AddressSpace::Kernel | AddressSpace::User => {
                            let projected_slot = self.func.alloc_stack_slot(
                                align_to_eight(next_ty.size()),
                                8,
                                StackSlotKind::Local,
                            );
                            self.record_stack_slot_type(projected_slot, next_ty.clone());
                            self.emit_trampoline_probe_read_to_slot(
                                *base_vreg,
                                *address_space,
                                field_offset,
                                projected_slot,
                                &next_ty,
                                path_desc,
                            )?;
                            let loaded_vreg = if bitfield.is_some() {
                                let storage_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(storage_vreg, next_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: storage_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: next_ty.clone(),
                                });
                                storage_vreg
                            } else {
                                dst_vreg
                            };
                            if let Some(bitfield) = bitfield {
                                self.emit_bitfield_extract(
                                    dst_vreg,
                                    loaded_vreg,
                                    &next_ty,
                                    bitfield,
                                )?;
                            } else {
                                self.vreg_type_hints.insert(dst_vreg, next_ty.clone());
                                self.emit(MirInst::LoadSlot {
                                    dst: dst_vreg,
                                    slot: projected_slot,
                                    offset: 0,
                                    ty: next_ty.clone(),
                                });
                            }
                        }
                        AddressSpace::Packet => {
                            if bitfield.is_some() {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "xdp packet path '{}' does not support bitfield extraction",
                                    path_desc
                                )));
                            }

                            let packet_ptr_vreg = if field_offset == 0 {
                                *base_vreg
                            } else {
                                let ptr_vreg = self.func.alloc_vreg();
                                self.vreg_type_hints.insert(
                                    ptr_vreg,
                                    MirType::Ptr {
                                        pointee: Box::new(next_ty.clone()),
                                        address_space: AddressSpace::Packet,
                                    },
                                );
                                self.emit(MirInst::BinOp {
                                    dst: ptr_vreg,
                                    op: BinOpKind::Add,
                                    lhs: MirValue::VReg(*base_vreg),
                                    rhs: MirValue::Const(i64::from(
                                        Self::trampoline_projection_offset_i32(
                                            field_offset,
                                            path_desc,
                                        )?,
                                    )),
                                });
                                ptr_vreg
                            };
                            let packet_ptr_vreg = self.packet_load_ptr_vreg(
                                packet_ptr_vreg,
                                MirType::Ptr {
                                    pointee: Box::new(next_ty.clone()),
                                    address_space: AddressSpace::Packet,
                                },
                                dst_vreg,
                            );
                            self.emit_xdp_packet_guarded_load(
                                dst_vreg,
                                packet_ptr_vreg,
                                &next_ty,
                                path_desc,
                            )?;
                            if packet_big_endian {
                                self.emit_packet_big_endian_scalar_normalize(dst_vreg, &next_ty)?;
                            }
                        }
                    }
                }
                return Ok(next_ty);
            }

            cursor = ValueCursor::Pointer {
                base_vreg: *base_vreg,
                address_space: *address_space,
                base_offset: field_offset,
                target_ty: next_ty,
                direct: false,
            };
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "empty typed field path '{}'",
            path_desc
        )))
    }
}
