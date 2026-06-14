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
        if let Some(value @ nu_protocol::Value::List { .. }) = input_meta.constant_value.as_ref()
            && !matches!(
                input_meta.annotated_semantics,
                Some(AnnotatedValueSemantics::FixedArray { .. })
            )
            && (crate::compiler::hir::supports_numeric_constant_list(value)
                || !crate::compiler::hir::supports_fixed_array_constant_list(value))
        {
            return Ok(None);
        }

        let Some(mut base_runtime_ty) = Self::metadata_fixed_array_layout(input_meta)?
            .or_else(|| self.typed_value_runtime_type(input_reg, input_vreg))
        else {
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
            Self::typed_fixed_array_where_input_type,
            Self::typed_fixed_array_where_input_type_description(),
        )?
        else {
            return Ok(false);
        };

        let scalar_where_item = Self::typed_fixed_array_where_scalar_type(&elem_ty);
        let constant_predicate = Self::constant_bool_closure_result(closure_ir);
        if !scalar_where_item && !self.current_call_result_list_shape_metadata_only {
            if matches!(constant_predicate, Some(true)) {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(input_vreg),
                });
                self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, input_reg, input_vreg);
                return Ok(true);
            }
            return Err(CompileError::UnsupportedInstruction(format!(
                "where on typed fixed arrays with u64, fixed-array, or record elements is supported only for metadata-only shape consumers such as length/is-empty in eBPF, got {:?}",
                elem_ty
            )));
        }
        let (input_vreg, base_runtime_ty) =
            self.preserve_typed_fixed_array_input("where", input_reg, input_vreg, dst_vreg)?;
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
                    let item_vreg = if scalar_where_item {
                        self.emit_typed_fixed_array_numeric_list_item(
                            "where", input_vreg, &elem_ty, i,
                        )?
                    } else {
                        self.emit_typed_fixed_array_shape_marker()
                    };
                    self.emit(MirInst::ListPush {
                        list: dst_vreg,
                        item: item_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });
                    self.current_block = next_block;
                    continue;
                }

                let (elem_vreg, elem_meta) = if scalar_where_item {
                    (
                        self.emit_typed_fixed_array_where_item("where", input_vreg, &elem_ty, i)?,
                        None,
                    )
                } else {
                    self.emit_typed_fixed_array_each_item(
                        input_vreg,
                        input_meta,
                        &base_runtime_ty,
                        &elem_ty,
                        i,
                    )?
                };
                let predicate = self.inline_closure_with_in_metadata(
                    closure_block_id,
                    closure_ir,
                    elem_vreg,
                    elem_meta,
                )?;

                let push_block = self.func.alloc_block();
                self.terminate(MirInst::Branch {
                    cond: predicate,
                    if_true: push_block,
                    if_false: next_block,
                });

                self.current_block = push_block;
                let item_vreg = if !scalar_where_item {
                    self.emit_typed_fixed_array_shape_marker()
                } else if matches!(elem_ty, MirType::Bool) {
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

        let Some((input_vreg, elem_ty, array_len)) = self.typed_fixed_array_stack_list_input(
            "each",
            input_reg,
            input_vreg,
            input_meta,
            Self::typed_fixed_array_each_input_type,
            Self::typed_fixed_array_each_input_type_description(),
        )?
        else {
            return Ok(false);
        };

        let (input_vreg, base_runtime_ty) =
            self.preserve_typed_fixed_array_input("each", input_reg, input_vreg, dst_vreg)?;
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

                let (elem_vreg, elem_meta) = self.emit_typed_fixed_array_each_item(
                    input_vreg,
                    input_meta,
                    &base_runtime_ty,
                    &elem_ty,
                    i,
                )?;
                let transformed = self.inline_closure_with_in_metadata(
                    closure_block_id,
                    closure_ir,
                    elem_vreg,
                    elem_meta,
                )?;
                if matches!(elem_ty, MirType::U64)
                    && matches!(self.vreg_type_hints.get(&transformed), Some(MirType::U64))
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "each on typed fixed arrays with u64 elements requires the closure to return a bool, signed integer, or <=32-bit unsigned integer value in eBPF"
                            .into(),
                    ));
                }
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

    fn preserve_typed_fixed_array_input(
        &mut self,
        cmd_name: &str,
        input_reg: RegId,
        input_vreg: VReg,
        dst_vreg: VReg,
    ) -> Result<(VReg, MirType), CompileError> {
        let base_runtime_ty = self
            .typed_value_runtime_type(input_reg, input_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires typed fixed-array input in eBPF"
                ))
            })?;
        if input_vreg != dst_vreg {
            return Ok((input_vreg, base_runtime_ty));
        }

        let preserved_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved_vreg,
            src: MirValue::VReg(input_vreg),
        });
        self.vreg_type_hints
            .insert(preserved_vreg, base_runtime_ty.clone());
        Ok((preserved_vreg, base_runtime_ty))
    }

    fn typed_fixed_array_each_input_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty)
            || matches!(
                ty,
                MirType::U64 | MirType::Bool | MirType::Array { .. } | MirType::Struct { .. }
            )
    }

    fn typed_fixed_array_each_input_type_description() -> &'static str {
        "signed integer, bool, unsigned integer scalar, fixed-array, or record elements"
    }

    pub(super) fn emit_typed_fixed_array_each_item(
        &mut self,
        input_vreg: VReg,
        input_meta: &RegMetadata,
        base_runtime_ty: &MirType,
        elem_ty: &MirType,
        index: usize,
    ) -> Result<(VReg, Option<RegMetadata>), CompileError> {
        if Self::typed_fixed_array_numeric_list_scalar_type(elem_ty) {
            return self
                .emit_typed_fixed_array_numeric_list_item("each", input_vreg, elem_ty, index)
                .map(|vreg| (vreg, None));
        }
        if matches!(elem_ty, MirType::Bool) {
            return self
                .emit_typed_fixed_array_predicate_item("each", input_vreg, elem_ty, index)
                .map(|vreg| (vreg, None));
        }
        if matches!(elem_ty, MirType::U64) {
            return self
                .emit_typed_fixed_array_predicate_item("each", input_vreg, elem_ty, index)
                .map(|vreg| (vreg, None));
        }

        const SYNTHETIC_EACH_ITEM_REG: u32 = u32::MAX - 1;
        let item_reg = RegId::new(SYNTHETIC_EACH_ITEM_REG);
        let old_reg_mapping = self.reg_map.remove(&item_reg.get());
        let old_meta = self.reg_metadata.remove(&item_reg.get());
        let projected_semantics = Self::typed_fixed_array_element_semantics(input_meta)?;
        let root_ctx_field = input_meta.root_ctx_field.clone();
        self.lower_dynamic_typed_numeric_get(
            item_reg,
            input_vreg,
            base_runtime_ty,
            MirValue::Const(i64::try_from(index).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "each fixed-array index {index} does not fit in i64"
                ))
            })?),
            projected_semantics.as_ref(),
            root_ctx_field.as_ref(),
        )?;
        if let Some(semantics) = projected_semantics {
            self.get_or_create_metadata(item_reg).annotated_semantics = Some(semantics);
        }
        let item_vreg = self.get_vreg(item_reg);
        let item_meta = self.get_metadata(item_reg).cloned();
        if let Some(old_reg_mapping) = old_reg_mapping {
            self.reg_map.insert(item_reg.get(), old_reg_mapping);
        } else {
            self.reg_map.remove(&item_reg.get());
        }
        if let Some(old_meta) = old_meta {
            self.reg_metadata.insert(item_reg.get(), old_meta);
        } else {
            self.reg_metadata.remove(&item_reg.get());
        }
        Ok((item_vreg, item_meta))
    }

    fn typed_fixed_array_element_semantics(
        input_meta: &RegMetadata,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        if let Some(AnnotatedValueSemantics::FixedArray { elem, .. }) =
            input_meta.annotated_semantics.as_ref()
        {
            return Ok(Some(elem.as_ref().clone()));
        }
        let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.as_ref() else {
            return Ok(None);
        };
        match Self::fixed_array_value_semantics(vals)? {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => Ok(Some(*elem)),
            _ => Ok(None),
        }
    }

    fn typed_fixed_array_where_scalar_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty) || matches!(ty, MirType::Bool)
    }

    fn typed_fixed_array_where_input_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_where_scalar_type(ty)
            || matches!(
                ty,
                MirType::U64 | MirType::Array { .. } | MirType::Struct { .. }
            )
    }

    fn typed_fixed_array_where_input_type_description() -> &'static str {
        "signed integer, bool, unsigned integer scalar, fixed-array, or record elements"
    }

    pub(super) fn emit_typed_fixed_array_shape_marker(&mut self) -> VReg {
        let marker = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: marker,
            src: MirValue::Const(1),
        });
        self.vreg_type_hints.insert(marker, MirType::I64);
        marker
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
