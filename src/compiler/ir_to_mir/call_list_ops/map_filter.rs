use super::*;

pub(in crate::compiler::ir_to_mir) struct TypedFixedArrayWhereLowering<'a> {
    pub(in crate::compiler::ir_to_mir) src_dst: RegId,
    pub(in crate::compiler::ir_to_mir) dst_vreg: VReg,
    pub(in crate::compiler::ir_to_mir) input_reg: RegId,
    pub(in crate::compiler::ir_to_mir) input_vreg: VReg,
    pub(in crate::compiler::ir_to_mir) input_meta: &'a RegMetadata,
    pub(in crate::compiler::ir_to_mir) closure_block_id: NuBlockId,
    pub(in crate::compiler::ir_to_mir) closure_ir: &'a HirFunction,
}

pub(in crate::compiler::ir_to_mir) struct TypedFixedArrayEachLowering<'a> {
    pub(in crate::compiler::ir_to_mir) src_dst: RegId,
    pub(in crate::compiler::ir_to_mir) dst_vreg: VReg,
    pub(in crate::compiler::ir_to_mir) input_reg: RegId,
    pub(in crate::compiler::ir_to_mir) input_vreg: VReg,
    pub(in crate::compiler::ir_to_mir) input_meta: &'a RegMetadata,
    pub(in crate::compiler::ir_to_mir) closure_block_id: NuBlockId,
    pub(in crate::compiler::ir_to_mir) closure_ir: &'a HirFunction,
}

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
        let Some((elem_ty, array_len)) =
            Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty)
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
            && Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty).is_some()
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
        Self::validate_typed_fixed_array_stack_list_address_space(
            cmd_name,
            address_space,
            input_meta,
        )?;

        Ok(Some((input_vreg, elem_ty, array_len)))
    }

    pub(in crate::compiler::ir_to_mir) fn typed_fixed_array_stack_list_array_type(
        ty: &MirType,
    ) -> Option<(MirType, usize)> {
        let array_ty = match ty {
            MirType::Array { .. } => ty,
            MirType::Ptr {
                pointee,
                address_space:
                    AddressSpace::Stack
                    | AddressSpace::Map
                    | AddressSpace::Context
                    | AddressSpace::Kernel,
            } if matches!(pointee.as_ref(), MirType::Array { .. }) => pointee.as_ref(),
            _ => return None,
        };
        match array_ty {
            MirType::Array { elem, len } => Some((elem.as_ref().clone(), *len)),
            _ => None,
        }
    }

    pub(in crate::compiler::ir_to_mir) fn validate_typed_fixed_array_stack_list_address_space(
        cmd_name: &str,
        address_space: AddressSpace,
        input_meta: &RegMetadata,
    ) -> Result<(), CompileError> {
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context | AddressSpace::Kernel
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }
        if address_space == AddressSpace::Kernel && !input_meta.trusted_btf {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed-array pointers in Kernel address space requires trusted BTF provenance in eBPF"
            )));
        }
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_typed_fixed_array_where(
        &mut self,
        lowering: TypedFixedArrayWhereLowering<'_>,
    ) -> Result<bool, CompileError> {
        let TypedFixedArrayWhereLowering {
            src_dst,
            dst_vreg,
            input_reg,
            input_vreg,
            input_meta,
            closure_block_id,
            closure_ir,
        } = lowering;

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

        if array_len > 0 && !matches!(constant_predicate, Some(false)) {
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

                if matches!(constant_predicate, Some(true)) {
                    let item_vreg = self.emit_typed_fixed_array_numeric_list_item(
                        "where", input_vreg, &elem_ty, i,
                    )?;
                    self.emit(MirInst::ListPush {
                        list: dst_vreg,
                        item: item_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });
                    self.current_block = next_block;
                    continue;
                }

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
        lowering: TypedFixedArrayEachLowering<'_>,
    ) -> Result<bool, CompileError> {
        let TypedFixedArrayEachLowering {
            src_dst,
            dst_vreg,
            input_reg,
            input_vreg,
            input_meta,
            closure_block_id,
            closure_ir,
        } = lowering;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn typed_fixed_array_numeric_list_input_accepts_only_trusted_kernel_arrays() {
        let decl_names = HashMap::new();
        let closure_irs = HashMap::new();
        let closure_param_sources = HashMap::new();
        let captures = Vec::new();
        let user_functions = HashMap::new();
        let decl_signatures = HashMap::new();
        let mut lowering = HirToMirLowering::new(HirToMirLoweringInput {
            probe_ctx: None,
            decl_names: &decl_names,
            closure_irs: &closure_irs,
            closure_param_sources: &closure_param_sources,
            captures: &captures,
            ctx_param: None,
            type_hints: None,
            external_map_key_types: None,
            external_map_key_semantics: None,
            external_map_max_entries: None,
            external_map_inner_templates: None,
            external_map_value_types: None,
            external_map_value_semantics: None,
            user_functions: &user_functions,
            decl_signatures: &decl_signatures,
        });

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 3,
            }),
            address_space: AddressSpace::Kernel,
        };

        let trusted_reg = RegId::new(1);
        let trusted_vreg = lowering.get_vreg(trusted_reg);
        lowering
            .vreg_type_hints
            .insert(trusted_vreg, ptr_ty.clone());
        let trusted_meta = RegMetadata {
            field_type: Some(ptr_ty.clone()),
            trusted_btf: true,
            ..Default::default()
        };
        let accepted = lowering
            .typed_fixed_array_numeric_list_input("each", trusted_reg, trusted_vreg, &trusted_meta)
            .expect("trusted kernel fixed-array input should lower")
            .expect("trusted kernel fixed-array input should be recognized");
        assert_eq!(accepted, (trusted_vreg, MirType::U32, 3));

        let untrusted_reg = RegId::new(2);
        let untrusted_vreg = lowering.get_vreg(untrusted_reg);
        lowering.vreg_type_hints.insert(untrusted_vreg, ptr_ty);
        let untrusted_meta = RegMetadata {
            field_type: lowering.vreg_type_hints.get(&untrusted_vreg).cloned(),
            ..Default::default()
        };
        let err = lowering
            .typed_fixed_array_numeric_list_input(
                "each",
                untrusted_reg,
                untrusted_vreg,
                &untrusted_meta,
            )
            .expect_err("untrusted kernel fixed-array input should be rejected");
        assert!(
            err.to_string().contains("requires trusted BTF provenance"),
            "unexpected error: {err}"
        );
    }
}
