use super::*;

struct TypedFixedArrayAllOrAny<'a> {
    cmd_name: &'a str,
    src_dst: RegId,
    dst_vreg: VReg,
    src_dst_had_value: bool,
    input_reg: RegId,
    input_vreg: VReg,
    input_meta: &'a RegMetadata,
    closure_block_id: NuBlockId,
    closure_ir: &'a HirFunction,
}

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
            && self.lower_typed_fixed_array_all_or_any(TypedFixedArrayAllOrAny {
                cmd_name,
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                input_meta: &input_meta,
                closure_block_id,
                closure_ir,
            })?
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
        lowering: TypedFixedArrayAllOrAny<'_>,
    ) -> Result<bool, CompileError> {
        let TypedFixedArrayAllOrAny {
            cmd_name,
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            mut input_vreg,
            input_meta,
            closure_block_id,
            closure_ir,
        } = lowering;

        if matches!(
            input_meta.constant_value,
            Some(nu_protocol::Value::List { .. })
        ) && !Self::metadata_declares_fixed_array_layout(input_meta)
        {
            return Ok(false);
        }

        let Some(mut base_runtime_ty) = self.typed_value_runtime_type(input_reg, input_vreg) else {
            return Ok(false);
        };
        let Some((elem_ty, array_len)) =
            Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty)
        else {
            return Ok(false);
        };

        if !Self::typed_fixed_array_predicate_input_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed arrays currently supports integer, bool, fixed-array, or record elements in eBPF, got {:?}",
                elem_ty
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

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let scalar_predicate_item = Self::typed_fixed_array_predicate_scalar_type(&elem_ty);
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
                let (elem_vreg, elem_meta) = if scalar_predicate_item {
                    (
                        self.emit_typed_fixed_array_predicate_item(
                            cmd_name, input_vreg, &elem_ty, i,
                        )?,
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

    fn typed_fixed_array_predicate_input_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_predicate_scalar_type(ty)
            || matches!(ty, MirType::Array { .. } | MirType::Struct { .. })
    }

    pub(super) fn emit_typed_fixed_array_predicate_item(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::hir::{
        HirBlock, HirBlockId, HirFunction, HirLiteral, HirStmt, HirTerminator,
    };
    use std::collections::HashMap;

    fn constant_bool_closure(value: bool) -> HirFunction {
        let result_reg = RegId::new(0);
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: result_reg,
                    lit: HirLiteral::Bool(value),
                }],
                terminator: HirTerminator::Return { src: result_reg },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 1,
            file_count: 0,
        }
    }

    #[test]
    fn all_accepts_trusted_kernel_fixed_array() {
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
        let entry = lowering.func.alloc_block();
        lowering.func.entry = entry;
        lowering.current_block = entry;

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 2,
            }),
            address_space: AddressSpace::Kernel,
        };
        let input_reg = RegId::new(1);
        let input_vreg = lowering.get_vreg(input_reg);
        lowering.vreg_type_hints.insert(input_vreg, ptr_ty.clone());
        let input_meta = RegMetadata {
            field_type: Some(ptr_ty),
            trusted_btf: true,
            ..Default::default()
        };

        let src_dst = RegId::new(2);
        let dst_vreg = lowering.get_vreg(src_dst);
        let closure_ir = constant_bool_closure(true);
        lowering
            .lower_typed_fixed_array_all_or_any(TypedFixedArrayAllOrAny {
                cmd_name: "all",
                src_dst,
                dst_vreg,
                src_dst_had_value: false,
                input_reg,
                input_vreg,
                input_meta: &input_meta,
                closure_block_id: NuBlockId::new(0),
                closure_ir: &closure_ir,
            })
            .expect("trusted kernel fixed-array all should lower");

        let load_count = lowering
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|inst| {
                matches!(
                    inst,
                    MirInst::Load {
                        ptr,
                        ty: MirType::U32,
                        ..
                    } if *ptr == input_vreg
                )
            })
            .count();
        assert_eq!(load_count, 2);
        assert_eq!(
            lowering
                .reg_metadata
                .get(&src_dst.get())
                .and_then(|meta| meta.field_type.as_ref()),
            Some(&MirType::Bool)
        );
        assert_eq!(
            lowering.vreg_type_hints.get(&dst_vreg),
            Some(&MirType::Bool)
        );
    }
}
