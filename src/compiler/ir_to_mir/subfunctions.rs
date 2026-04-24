use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_helper_callback_subfunction(
        &mut self,
        block_id: NuBlockId,
        name: &str,
        arg_seeds: &[SubfunctionArgSeed],
    ) -> Result<SubfunctionId, CompileError> {
        let hir = self.closure_irs.get(&block_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!("Closure block {:?} not found", block_id))
        })?;
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let param_vars = Self::infer_param_vars(hir);
        let param_count = arg_seeds.len().saturating_sub(usize::from(needs_input));
        let declared_params = param_vars.len() + usize::from(needs_input);
        if declared_params > arg_seeds.len() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "callback closure for '{}' declares {} parameters, but the callback ABI supplies {}",
                name,
                declared_params,
                arg_seeds.len()
            )));
        }

        let mut subfn = MirFunction::with_name(name.to_string());
        subfn.param_count = arg_seeds.len();

        let old_func = std::mem::replace(&mut self.func, subfn);
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_current_block = self.current_block;
        let old_pipeline_input = self.pipeline_input.take();
        let old_pipeline_input_reg = self.pipeline_input_reg.take();
        let old_positional_args = std::mem::take(&mut self.positional_args);
        let old_named_flags = std::mem::take(&mut self.named_flags);
        let old_named_args = std::mem::take(&mut self.named_args);
        let old_var_mappings = std::mem::take(&mut self.var_mappings);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_type_hints = std::mem::take(&mut self.current_type_hints);
        let old_vreg_hints = std::mem::take(&mut self.vreg_type_hints);
        let old_stack_slot_hints = std::mem::take(&mut self.stack_slot_type_hints);
        let old_subfunction_global_aliases = std::mem::take(&mut self.subfunction_global_aliases);
        let old_ctx_param = self.ctx_param;
        let old_return_seed_state = std::mem::take(&mut self.current_return_seed_state);
        let old_aggregate_return = std::mem::take(&mut self.current_subfunction_aggregate_return);

        self.ctx_param = None;
        let mut next_arg_seed = 0usize;

        if needs_input {
            let vreg = self.func.alloc_vreg();
            if let Some(reg) = input_reg {
                self.reg_map.insert(reg.get(), vreg);
            }
            if uses_in {
                self.var_mappings.insert(IN_VARIABLE_ID, vreg);
            }
            let seed = arg_seeds.get(next_arg_seed);
            self.seed_subfunction_param(
                vreg,
                next_arg_seed,
                seed,
                input_reg,
                uses_in.then_some(IN_VARIABLE_ID),
            );
            next_arg_seed += 1;
        }

        for (idx, var_id) in param_vars.iter().enumerate() {
            let vreg = self.func.alloc_vreg();
            self.var_mappings.insert(*var_id, vreg);
            let seed = arg_seeds.get(next_arg_seed + idx);
            self.seed_subfunction_param(vreg, next_arg_seed + idx, seed, None, Some(*var_id));
        }
        for extra_idx in param_vars.len()..param_count {
            let unused = self.func.alloc_vreg();
            let seed = arg_seeds.get(next_arg_seed + extra_idx);
            self.seed_subfunction_param(unused, next_arg_seed + extra_idx, seed, None, None);
        }

        self.hir_block_map.insert(hir.entry, self.func.entry);
        self.current_block = self.func.entry;

        let result = self.lower_block(hir);

        let subfn = std::mem::replace(&mut self.func, old_func);
        let subfn_hints = std::mem::replace(&mut self.vreg_type_hints, old_vreg_hints);
        let subfn_stack_slot_hints =
            std::mem::replace(&mut self.stack_slot_type_hints, old_stack_slot_hints);
        let subfn_return_seed =
            match std::mem::replace(&mut self.current_return_seed_state, old_return_seed_state) {
                CurrentReturnSeedState::Known(seed) => seed,
                CurrentReturnSeedState::Unset | CurrentReturnSeedState::Conflict => None,
            };

        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.current_block = old_current_block;
        self.pipeline_input = old_pipeline_input;
        self.pipeline_input_reg = old_pipeline_input_reg;
        self.positional_args = old_positional_args;
        self.named_flags = old_named_flags;
        self.named_args = old_named_args;
        self.var_mappings = old_var_mappings;
        self.loop_contexts = old_loop_contexts;
        self.hir_block_map = old_hir_block_map;
        self.loop_body_inits = old_loop_body_inits;
        self.current_type_hints = old_type_hints;
        self.subfunction_global_aliases = old_subfunction_global_aliases;
        self.ctx_param = old_ctx_param;
        self.current_subfunction_aggregate_return = old_aggregate_return;

        if let Err(err) = result {
            return Err(err);
        }

        let subfn_id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(subfn);
        self.subfunction_hints.push(subfn_hints);
        self.subfunction_stack_slot_hints
            .push(subfn_stack_slot_hints);
        self.subfunction_return_seeds.push(subfn_return_seed);

        Ok(subfn_id)
    }

    fn seed_subfunction_param(
        &mut self,
        vreg: VReg,
        param_idx: usize,
        seed: Option<&SubfunctionArgSeed>,
        reg: Option<RegId>,
        var: Option<VarId>,
    ) {
        let Some(seed) = seed else {
            return;
        };

        if let Some(var) = var
            && let Some(source_var) = seed.metadata.as_ref().and_then(|meta| meta.source_var)
            && source_var != var
            && (self.annotated_mut_globals.contains_key(&source_var)
                || self.mutable_capture_globals.contains_key(&source_var))
        {
            self.subfunction_global_aliases.insert(var, source_var);
            if let Some(symbol) = self
                .annotated_mut_globals
                .get(&source_var)
                .map(|global| global.symbol.clone())
                .or_else(|| {
                    self.mutable_capture_globals
                        .get(&source_var)
                        .map(|global| global.symbol.clone())
                })
            {
                self.func.global_param_aliases.insert(symbol, param_idx);
            }
        }

        if let Some(ty) = seed.type_hint.clone() {
            self.vreg_type_hints.insert(vreg, ty);
        }

        if let Some(stack_object) = &seed.synthetic_stack_slot {
            let slot = self.func.alloc_stack_slot(
                stack_object.size,
                stack_object.align,
                StackSlotKind::Local,
            );
            self.record_stack_slot_type(slot, stack_object.ty.clone());
            self.func.param_stack_slots.insert(param_idx, slot);
            if stack_object.initialize_dynptr {
                self.func.entry_initialized_dynptr_slots.insert(slot);
            }
        }

        if let Some(mut meta) = seed.metadata.clone() {
            meta.trusted_btf = false;
            if let Some(reg) = reg {
                self.reg_metadata.insert(reg.get(), meta.clone());
            }
            if let Some(var) = var {
                self.var_metadata.insert(var, meta);
            }
        }
    }

    pub(super) fn get_or_create_subfunction(
        &mut self,
        decl_id: DeclId,
        arg_seeds: &[SubfunctionArgSeed],
    ) -> Result<SubfunctionId, CompileError> {
        let key = SubfunctionSpecializationKey {
            decl_id,
            arg_types: arg_seeds
                .iter()
                .map(|seed| seed.type_hint.clone())
                .collect(),
        };
        if let Some(&subfn_id) = self.subfunction_registry.get(&key) {
            return Ok(subfn_id);
        }

        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;

        if !self.subfunction_in_progress.insert(decl_id) {
            return Err(CompileError::UnsupportedInstruction(
                "Recursive user-defined functions are not supported in eBPF".into(),
            ));
        }

        let param_vars = self.subfunction_params(decl_id, hir);
        let sig = self.decl_signatures.get(&decl_id);
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));
        let aggregate_return_abi = self.subfunction_aggregate_return_abi(decl_id, hir);

        let mut subfn = MirFunction::with_name(name);
        let sig_param_count = sig.map(Self::sig_param_count);
        let param_count = sig_param_count.unwrap_or(param_vars.len());
        subfn.param_count =
            param_count + usize::from(needs_input) + usize::from(aggregate_return_abi.is_some());

        let old_func = std::mem::replace(&mut self.func, subfn);
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_current_block = self.current_block;
        let old_pipeline_input = self.pipeline_input.take();
        let old_pipeline_input_reg = self.pipeline_input_reg.take();
        let old_positional_args = std::mem::take(&mut self.positional_args);
        let old_named_flags = std::mem::take(&mut self.named_flags);
        let old_named_args = std::mem::take(&mut self.named_args);
        let old_var_mappings = std::mem::take(&mut self.var_mappings);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_type_hints = std::mem::replace(
            &mut self.current_type_hints,
            self.decl_type_hints
                .get(&decl_id)
                .cloned()
                .unwrap_or_default(),
        );
        let old_vreg_hints = std::mem::take(&mut self.vreg_type_hints);
        let old_stack_slot_hints = std::mem::take(&mut self.stack_slot_type_hints);
        let old_subfunction_global_aliases = std::mem::take(&mut self.subfunction_global_aliases);
        let old_ctx_param = self.ctx_param;
        let old_return_seed_state = std::mem::take(&mut self.current_return_seed_state);
        let old_aggregate_return = std::mem::take(&mut self.current_subfunction_aggregate_return);

        self.ctx_param = None;
        let mut next_arg_seed = 0usize;

        let param_base = Self::infer_param_base_var_id(hir)
            .or_else(|| sig.and_then(|_| Self::infer_referenced_var_base_var_id(hir)));
        if needs_input {
            let vreg = self.func.alloc_vreg();
            if let Some(reg) = input_reg {
                self.reg_map.insert(reg.get(), vreg);
            }
            if uses_in {
                self.var_mappings.insert(IN_VARIABLE_ID, vreg);
            }
            let seed = arg_seeds.get(next_arg_seed);
            self.seed_subfunction_param(
                vreg,
                next_arg_seed,
                seed,
                input_reg,
                uses_in.then_some(IN_VARIABLE_ID),
            );
            next_arg_seed += 1;
        }

        if let Some(base) = param_base {
            let base = base.get();
            for i in 0..param_count {
                let vreg = self.func.alloc_vreg();
                let var_id = VarId::new(base + i);
                self.var_mappings.insert(var_id, vreg);
                let seed = arg_seeds.get(next_arg_seed + i);
                self.seed_subfunction_param(vreg, next_arg_seed + i, seed, None, Some(var_id));
            }
        } else {
            for (idx, var_id) in param_vars.iter().enumerate() {
                let vreg = self.func.alloc_vreg();
                self.var_mappings.insert(*var_id, vreg);
                let seed = arg_seeds.get(next_arg_seed + idx);
                self.seed_subfunction_param(vreg, next_arg_seed + idx, seed, None, Some(*var_id));
            }
            for _ in param_vars.len()..param_count {
                let _unused = self.func.alloc_vreg();
            }
        }

        if let Some(abi) = aggregate_return_abi {
            let vreg = self.func.alloc_vreg();
            let seed_idx = next_arg_seed + param_count;
            let seed = arg_seeds.get(seed_idx);
            self.seed_subfunction_param(vreg, seed_idx, seed, None, None);
            self.current_subfunction_aggregate_return = Some(match abi {
                SubfunctionAggregateReturnAbi::Record { ty } => {
                    self.vreg_type_hints.insert(
                        vreg,
                        MirType::Ptr {
                            pointee: Box::new(ty.clone()),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    ActiveSubfunctionAggregateReturn::Record { ptr_vreg: vreg, ty }
                }
                SubfunctionAggregateReturnAbi::List { max_len } => {
                    self.vreg_type_hints.insert(
                        vreg,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::I64),
                                len: max_len.saturating_add(1),
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    ActiveSubfunctionAggregateReturn::List {
                        ptr_vreg: vreg,
                        max_len,
                    }
                }
                SubfunctionAggregateReturnAbi::String { slot_len } => {
                    self.vreg_type_hints.insert(
                        vreg,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: slot_len,
                            }),
                            address_space: crate::compiler::mir::AddressSpace::Stack,
                        },
                    );
                    ActiveSubfunctionAggregateReturn::String {
                        ptr_vreg: vreg,
                        slot_len,
                    }
                }
            });
        }

        let result = self.lower_block(hir);

        let subfn = std::mem::replace(&mut self.func, old_func);
        let subfn_hints = std::mem::replace(&mut self.vreg_type_hints, old_vreg_hints);
        let subfn_stack_slot_hints =
            std::mem::replace(&mut self.stack_slot_type_hints, old_stack_slot_hints);
        let subfn_return_seed =
            match std::mem::replace(&mut self.current_return_seed_state, old_return_seed_state) {
                CurrentReturnSeedState::Known(seed) => seed,
                CurrentReturnSeedState::Unset | CurrentReturnSeedState::Conflict => None,
            };

        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.current_block = old_current_block;
        self.pipeline_input = old_pipeline_input;
        self.pipeline_input_reg = old_pipeline_input_reg;
        self.positional_args = old_positional_args;
        self.named_flags = old_named_flags;
        self.named_args = old_named_args;
        self.var_mappings = old_var_mappings;
        self.loop_contexts = old_loop_contexts;
        self.hir_block_map = old_hir_block_map;
        self.loop_body_inits = old_loop_body_inits;
        self.current_type_hints = old_type_hints;
        self.subfunction_global_aliases = old_subfunction_global_aliases;
        self.ctx_param = old_ctx_param;
        self.current_subfunction_aggregate_return = old_aggregate_return;

        self.subfunction_in_progress.remove(&decl_id);

        if let Err(err) = result {
            return Err(err);
        }

        let subfn_id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(subfn);
        self.subfunction_hints.push(subfn_hints);
        self.subfunction_stack_slot_hints
            .push(subfn_stack_slot_hints);
        self.subfunction_return_seeds.push(subfn_return_seed);
        self.subfunction_registry.insert(key, subfn_id);

        Ok(subfn_id)
    }
}
