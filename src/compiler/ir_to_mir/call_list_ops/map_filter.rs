use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn typed_fixed_array_numeric_list_input(
        &mut self,
        cmd_name: &str,
        input_reg: RegId,
        input_vreg: VReg,
        input_meta: &RegMetadata,
    ) -> Result<Option<(VReg, MirType, usize)>, CompileError> {
        self.typed_fixed_array_stack_list_input(
            cmd_name,
            input_reg,
            input_vreg,
            input_meta,
            Self::typed_fixed_array_numeric_list_scalar_type,
            Self::typed_fixed_array_numeric_list_scalar_type_description(),
        )
    }

    fn typed_fixed_array_stack_list_input(
        &mut self,
        cmd_name: &str,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        supported_scalar_type: fn(&MirType) -> bool,
        supported_scalar_type_description: &'static str,
    ) -> Result<Option<(VReg, MirType, usize)>, CompileError> {
        if input_meta.list_buffer.is_some() {
            return Ok(None);
        }
        if matches!(
            input_meta.constant_value,
            Some(nu_protocol::Value::List { .. })
        ) && !matches!(
            input_meta.annotated_semantics,
            Some(AnnotatedValueSemantics::FixedArray { .. })
        ) {
            return Ok(None);
        }

        let Some(mut base_runtime_ty) = self.typed_value_runtime_type(input_reg, input_vreg) else {
            return Ok(None);
        };
        let Some((elem_ty, array_len)) = Self::aggregate_call_value_type(&base_runtime_ty)
            .and_then(|ty| match ty {
                MirType::Array { elem, len } => Some((elem.as_ref().clone(), *len)),
                _ => None,
            })
        else {
            return Ok(None);
        };

        if !supported_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed arrays currently supports {} in eBPF, got {:?}",
                supported_scalar_type_description, elem_ty
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

        Ok(Some((input_vreg, elem_ty, array_len)))
    }

    pub(in crate::compiler::ir_to_mir) fn lower_typed_fixed_array_where(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        input_reg: RegId,
        input_vreg: VReg,
        input_meta: &RegMetadata,
        closure_block_id: NuBlockId,
        closure_ir: &HirFunction,
    ) -> Result<bool, CompileError> {
        let Some((input_vreg, elem_ty, array_len)) = self.typed_fixed_array_stack_list_input(
            "where",
            input_reg,
            input_vreg,
            input_meta,
            Self::typed_fixed_array_where_scalar_type,
            Self::typed_fixed_array_where_scalar_type_description(),
        )?
        else {
            return Ok(false);
        };

        let constant_predicate = Self::constant_bool_closure_result(closure_ir);
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(dst_vreg, array_len);

        if array_len > 0 {
            let continuation_block = self.func.alloc_block();
            for i in 0..array_len {
                let predicate_block = self.func.alloc_block();
                let next_block = if i + 1 == array_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                self.terminate(MirInst::Jump {
                    target: predicate_block,
                });
                self.current_block = predicate_block;

                let elem_vreg =
                    self.emit_typed_fixed_array_where_item("where", input_vreg, &elem_ty, i)?;
                let predicate =
                    self.inline_closure_with_in(closure_block_id, closure_ir, elem_vreg)?;

                let push_block = self.func.alloc_block();
                self.terminate(MirInst::Branch {
                    cond: predicate,
                    if_true: push_block,
                    if_false: next_block,
                });

                self.current_block = push_block;
                let item_vreg = if matches!(elem_ty, MirType::Bool) {
                    self.emit_typed_fixed_array_numeric_list_item("where", input_vreg, &elem_ty, i)?
                } else {
                    elem_vreg
                };
                self.emit(MirInst::ListPush {
                    list: dst_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        let known_len = match constant_predicate {
            Some(true) => Some(array_len),
            Some(false) => Some(0),
            None => None,
        };
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, array_len, known_len,
        );
        Ok(true)
    }

    pub(in crate::compiler::ir_to_mir) fn lower_typed_fixed_array_each(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        input_reg: RegId,
        input_vreg: VReg,
        input_meta: &RegMetadata,
        closure_block_id: NuBlockId,
        closure_ir: &HirFunction,
    ) -> Result<bool, CompileError> {
        let Some((input_vreg, elem_ty, array_len)) =
            self.typed_fixed_array_numeric_list_input("each", input_reg, input_vreg, input_meta)?
        else {
            return Ok(false);
        };

        let (out_slot, out_ty) = self.create_stack_numeric_list_result(dst_vreg, array_len);

        if array_len > 0 {
            let continuation_block = self.func.alloc_block();
            for i in 0..array_len {
                let transform_block = self.func.alloc_block();
                let next_block = if i + 1 == array_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                self.terminate(MirInst::Jump {
                    target: transform_block,
                });
                self.current_block = transform_block;

                let elem_vreg =
                    self.emit_typed_fixed_array_numeric_list_item("each", input_vreg, &elem_ty, i)?;
                let transformed =
                    self.inline_closure_with_in(closure_block_id, closure_ir, elem_vreg)?;
                self.emit(MirInst::ListPush {
                    list: dst_vreg,
                    item: transformed,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            array_len,
            Some(array_len),
        );
        Ok(true)
    }

    fn typed_fixed_array_where_scalar_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty) || matches!(ty, MirType::Bool)
    }

    fn typed_fixed_array_where_scalar_type_description() -> &'static str {
        "signed integer, bool, or <=32-bit unsigned integer scalar elements"
    }

    fn emit_typed_fixed_array_where_item(
        &mut self,
        cmd_name: &str,
        input_vreg: VReg,
        elem_ty: &MirType,
        index: usize,
    ) -> Result<VReg, CompileError> {
        if matches!(elem_ty, MirType::Bool) {
            self.emit_typed_fixed_array_predicate_item(cmd_name, input_vreg, elem_ty, index)
        } else {
            self.emit_typed_fixed_array_numeric_list_item(cmd_name, input_vreg, elem_ty, index)
        }
    }

    pub(in crate::compiler::ir_to_mir) fn constant_bool_closure_result(
        closure_ir: &HirFunction,
    ) -> Option<bool> {
        let [block] = closure_ir.blocks.as_slice() else {
            return None;
        };
        if block.id != closure_ir.entry {
            return None;
        }
        let [
            HirStmt::LoadLiteral {
                dst,
                lit: HirLiteral::Bool(value),
            },
        ] = block.stmts.as_slice()
        else {
            return None;
        };
        let src = match &block.terminator {
            HirTerminator::Return { src } | HirTerminator::ReturnEarly { src } => src,
            _ => return None,
        };
        if dst == src { Some(*value) } else { None }
    }
}
