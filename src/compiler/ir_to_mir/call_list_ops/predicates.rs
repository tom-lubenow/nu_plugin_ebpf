use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_all_or_any(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one closure argument in eBPF"
            )));
        }

        let closure_block_id = self
            .positional_args
            .first()
            .and_then(|(_, reg)| self.get_metadata(*reg))
            .and_then(|m| m.closure_block_id)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a closure argument in eBPF"
                ))
            })?;
        let closure_ir = self.closure_irs.get(&closure_block_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "Closure block {} not found",
                closure_block_id.get()
            ))
        })?;

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a stack-backed list input in eBPF"
                ))
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_all_or_any(
                cmd_name,
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                closure_block_id,
                closure_ir,
            )?
        {
            return Ok(());
        }
        let Some((_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed list input in eBPF"
            )));
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let initial_value = if cmd_name == "all" { 1 } else { 0 };
        let short_circuit_value = if cmd_name == "all" { 0 } else { 1 };

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            let identity_block = self.func.alloc_block();
            for i in 0..max_len {
                let predicate_block = self.func.alloc_block();
                let next_block = if i + 1 == max_len {
                    identity_block
                } else {
                    self.func.alloc_block()
                };
                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(i as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: predicate_block,
                    if_false: identity_block,
                });

                self.current_block = predicate_block;
                let elem_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: elem_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(i as i64),
                });
                self.vreg_type_hints.insert(elem_vreg, MirType::I64);

                let predicate =
                    self.inline_closure_with_in(closure_block_id, closure_ir, elem_vreg)?;
                let short_circuit_block = self.func.alloc_block();
                let (if_true, if_false) = if cmd_name == "all" {
                    (next_block, short_circuit_block)
                } else {
                    (short_circuit_block, next_block)
                };
                self.terminate(MirInst::Branch {
                    cond: predicate,
                    if_true,
                    if_false,
                });

                self.current_block = short_circuit_block;
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(short_circuit_value),
                });
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = next_block;
            }
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(initial_value),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });
            self.current_block = continuation_block;
        } else {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(initial_value),
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    fn lower_typed_fixed_array_all_or_any(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        closure_block_id: NuBlockId,
        closure_ir: &HirFunction,
    ) -> Result<bool, CompileError> {
        if matches!(
            input_meta.constant_value,
            Some(nu_protocol::Value::List { .. })
        ) && !matches!(
            input_meta.annotated_semantics,
            Some(AnnotatedValueSemantics::FixedArray { .. })
        ) {
            return Ok(false);
        }

        let Some(mut base_runtime_ty) = self.typed_value_runtime_type(input_reg, input_vreg) else {
            return Ok(false);
        };
        let Some((elem_ty, array_len)) = Self::aggregate_call_value_type(&base_runtime_ty)
            .and_then(|ty| match ty {
                MirType::Array { elem, len } => Some((elem.as_ref().clone(), *len)),
                _ => None,
            })
        else {
            return Ok(false);
        };

        if !Self::typed_fixed_array_predicate_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed arrays currently supports integer scalar elements in eBPF, got {:?}",
                elem_ty
            )));
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires typed fixed-array input in eBPF"
                    ))
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires typed fixed-array pointer input in eBPF"
            )));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let initial_value = if cmd_name == "all" { 1 } else { 0 };
        let short_circuit_value = if cmd_name == "all" { 0 } else { 1 };

        if array_len > 0 {
            let continuation_block = self.func.alloc_block();
            let identity_block = self.func.alloc_block();
            for i in 0..array_len {
                let predicate_block = self.func.alloc_block();
                let next_block = if i + 1 == array_len {
                    identity_block
                } else {
                    self.func.alloc_block()
                };

                self.terminate(MirInst::Jump {
                    target: predicate_block,
                });
                self.current_block = predicate_block;
                let elem_vreg =
                    self.emit_typed_fixed_array_predicate_item(cmd_name, input_vreg, &elem_ty, i)?;

                let predicate =
                    self.inline_closure_with_in(closure_block_id, closure_ir, elem_vreg)?;
                let short_circuit_block = self.func.alloc_block();
                let (if_true, if_false) = if cmd_name == "all" {
                    (next_block, short_circuit_block)
                } else {
                    (short_circuit_block, next_block)
                };
                self.terminate(MirInst::Branch {
                    cond: predicate,
                    if_true,
                    if_false,
                });

                self.current_block = short_circuit_block;
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(short_circuit_value),
                });
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = next_block;
            }
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(initial_value),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });
            self.current_block = continuation_block;
        } else {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(initial_value),
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(true)
    }

    fn typed_fixed_array_predicate_scalar_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty)
            || matches!(ty, MirType::U64 | MirType::Bool)
    }

    fn emit_typed_fixed_array_predicate_item(
        &mut self,
        cmd_name: &str,
        input_vreg: VReg,
        elem_ty: &MirType,
        index: usize,
    ) -> Result<VReg, CompileError> {
        if !matches!(elem_ty, MirType::U64 | MirType::Bool) {
            return self
                .emit_typed_fixed_array_numeric_list_item(cmd_name, input_vreg, elem_ty, index);
        }

        let elem_size = elem_ty.size();
        let offset = index.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array item offset overflowed in eBPF"
            ))
        })?;
        let offset = Self::checked_mir_offset(offset, "typed fixed-array predicate item")?;

        let raw_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Load {
            dst: raw_vreg,
            ptr: input_vreg,
            offset,
            ty: elem_ty.clone(),
        });
        self.vreg_type_hints.insert(raw_vreg, elem_ty.clone());
        Ok(raw_vreg)
    }
}
