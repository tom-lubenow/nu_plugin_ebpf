use super::*;
use crate::compiler::instruction::KfuncSignature;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn set_call_args(&mut self, args: &HirCallArgs) -> Result<(), CompileError> {
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();

        for reg in &args.positional {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for reg in &args.rest {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for (name, reg) in &args.named {
            let name = std::str::from_utf8(name)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid arg name".into()))?
                .to_string();
            let vreg = self.get_vreg(*reg);
            self.named_args.insert(name, (vreg, *reg));
        }
        for flag in &args.flags {
            let flag = std::str::from_utf8(flag)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid flag name".into()))?
                .to_string();
            self.named_flags.push(flag);
        }

        Ok(())
    }

    pub(super) fn clear_call_state(&mut self) {
        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();
    }

    pub(super) fn const_vreg(&mut self, value: i64) -> VReg {
        let vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: vreg,
            src: MirValue::Const(value),
        });
        vreg
    }

    pub(super) fn input_vreg_for_call(&mut self, src_dst: RegId) -> VReg {
        if let Some(vreg) = self.pipeline_input {
            return vreg;
        }
        if self.reg_map.contains_key(&src_dst.get()) {
            return self.get_vreg(src_dst);
        }
        self.const_vreg(0)
    }

    pub(super) fn lower_call(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
    ) -> Result<(), CompileError> {
        let src_dst_had_value = self.reg_map.contains_key(&src_dst.get());
        let dst_vreg = self.get_vreg(src_dst);

        if self.user_functions.contains_key(&decl_id) {
            self.lower_user_function_call(decl_id, src_dst, dst_vreg)?;
            self.clear_call_state();
            return Ok(());
        }

        // Look up command name from our decl_names mapping
        let cmd_name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        match cmd_name.as_str() {
            "emit" => {
                self.needs_ringbuf = true;
                // Check if we're emitting a record - check both pipeline_input_reg and src_dst
                // (src_dst is used when record is piped directly: { ... } | emit)
                let record_fields = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .map(|m| m.record_fields.clone())
                    .filter(|f| !f.is_empty())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .map(|m| m.record_fields.clone())
                            .filter(|f| !f.is_empty())
                    })
                    .unwrap_or_default();

                if !record_fields.is_empty() {
                    // Emit a structured record
                    let fields: Vec<RecordFieldDef> = record_fields
                        .iter()
                        .map(|f| RecordFieldDef {
                            name: f.name.clone(),
                            value: f.value_vreg,
                            ty: f.ty.clone(),
                        })
                        .collect();
                    self.emit(MirInst::EmitRecord { fields });
                } else {
                    let field_type = self
                        .pipeline_input_reg
                        .and_then(|reg| self.get_metadata(reg))
                        .and_then(|m| m.field_type.clone())
                        .or_else(|| {
                            self.get_metadata(src_dst)
                                .and_then(|m| m.field_type.clone())
                        });
                    let size = match field_type {
                        Some(MirType::Array { elem, len })
                            if matches!(elem.as_ref(), MirType::U8) =>
                        {
                            len
                        }
                        _ => 8,
                    };
                    // Emit a single value
                    let data_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                    self.emit(MirInst::EmitEvent {
                        data: data_vreg,
                        size,
                    });
                }
                // Set result to 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "count" => {
                self.needs_counter_map = true;
                let key_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let key_type = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.field_type.clone())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .and_then(|m| m.field_type.clone())
                    });

                // Check for --per-cpu flag
                let per_cpu = self.named_flags.contains(&"per-cpu".to_string());

                let (map_name, map_kind) = match key_type {
                    Some(MirType::Array { ref elem, len })
                        if matches!(elem.as_ref(), MirType::U8) =>
                    {
                        if len == 16 {
                            let kind = if per_cpu {
                                MapKind::PerCpuHash
                            } else {
                                MapKind::Hash
                            };
                            ("str_counters", kind)
                        } else {
                            return Err(CompileError::UnsupportedInstruction(
                                "count only supports 16-byte strings (e.g., $ctx.comm)".into(),
                            ));
                        }
                    }
                    _ => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        ("counters", kind)
                    }
                };

                // Map update increments counter for key
                self.emit(MirInst::MapUpdate {
                    map: MapRef {
                        name: map_name.to_string(),
                        kind: map_kind,
                    },
                    key: key_vreg,
                    val: dst_vreg, // handled specially in MIR->eBPF
                    flags: 0,
                });

                // Return 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });

                // Set type for key (useful for pointer safety)
                let meta = self.get_or_create_metadata(src_dst);
                meta.field_type = key_type;
            }

            "histogram" => {
                self.needs_histogram_map = true;
                let value_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                self.emit(MirInst::Histogram { value: value_vreg });
                // Return 0 (pass-through)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "start-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StartTimer);
                // Return 0 (void)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "stop-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StopTimer { dst: dst_vreg });
            }

            "read-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);

                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: true,
                    max_len: aligned_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.string_len_bound = Some(aligned_len.saturating_sub(1));
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
            }

            "read-kernel-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-kernel-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);

                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: false,
                    max_len: aligned_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.string_len_bound = Some(aligned_len.saturating_sub(1));
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
            }

            "kfunc-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "kfunc-call does not accept flags".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "kfunc-call requires a literal kfunc name as the first positional argument"
                            .into(),
                    )
                })?;

                let kfunc = self
                    .get_metadata(name_reg)
                    .and_then(|m| m.literal_string.clone())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call requires first positional argument to be a string literal"
                                .into(),
                        )
                    })?;

                let btf_id = if let Some((_, reg)) = self.named_args.get("btf-id") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "kfunc-call --btf-id must be a compile-time integer literal".into(),
                            )
                        })?;
                    Some(u32::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call --btf-id must be >= 0".into(),
                        )
                    })?)
                } else {
                    None
                };

                for key in self.named_args.keys() {
                    if key != "btf-id" {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "kfunc-call does not accept named argument '{}'",
                            key
                        )));
                    }
                }

                let mut args = Vec::new();
                let is_known_zero_arg = KfuncSignature::for_name(&kfunc)
                    .map(|sig| sig.max_args == 0)
                    .unwrap_or(false);
                if let Some(input) = self.pipeline_input {
                    args.push(input);
                } else if src_dst_had_value && !is_known_zero_arg {
                    args.push(dst_vreg);
                }

                for (arg_vreg, _) in self.positional_args.iter().skip(1) {
                    args.push(*arg_vreg);
                }

                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF kfunc calls support at most 5 arguments".into(),
                    ));
                }

                self.emit(MirInst::CallKfunc {
                    dst: dst_vreg,
                    kfunc,
                    btf_id,
                    args,
                });
            }

            "where" => {
                // where { condition } - filter pipeline by condition
                // Get the pipeline input (value to filter)
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Inline the closure with $in bound to input_vreg
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;
                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;

                    // Create exit block and continue block
                    let exit_block = self.func.alloc_block();
                    let continue_block = self.func.alloc_block();

                    // Branch: if result is 0/false, exit
                    let negated = self.func.alloc_vreg();
                    self.emit(MirInst::UnaryOp {
                        dst: negated,
                        op: crate::compiler::mir::UnaryOpKind::Not,
                        src: MirValue::VReg(result_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: negated,
                        if_true: exit_block,
                        if_false: continue_block,
                    });

                    // Exit block returns 0
                    self.current_block = exit_block;
                    self.terminate(MirInst::Return {
                        val: Some(MirValue::Const(0)),
                    });

                    // Continue block passes the original value through
                    self.current_block = continue_block;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });

                    // Copy metadata from input to output
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "where requires a closure argument".into(),
                    ));
                }
            }

            "each" => {
                // each { closure } - transform pipeline values
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Look up the closure IR
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;

                    // For lists, we can map each element
                    let meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                    if let Some(meta) = meta {
                        if let Some((_slot, max_len)) = meta.list_buffer {
                            // Create a new list for output
                            let out_slot = self.func.alloc_stack_slot(
                                align_to_eight(8 + max_len * 8),
                                8,
                                StackSlotKind::ListBuffer,
                            );
                            self.emit(MirInst::ListNew {
                                dst: dst_vreg,
                                buffer: out_slot,
                                max_len,
                            });

                            for i in 0..max_len {
                                let elem_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::ListGet {
                                    dst: elem_vreg,
                                    list: input_vreg,
                                    idx: MirValue::Const(i as i64),
                                });

                                // Transform element with closure
                                let transformed =
                                    self.inline_closure_with_in(block_id, closure_ir, elem_vreg)?;
                                self.emit(MirInst::ListPush {
                                    list: dst_vreg,
                                    item: transformed,
                                });
                            }

                            // Copy metadata for output list
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.list_buffer = Some((out_slot, max_len));
                            out_meta.field_type = meta.field_type;
                            return Ok(());
                        }
                    }

                    // Default: apply closure and return transformed value
                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(result_vreg),
                    });

                    // Copy metadata from input to output
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "each requires a closure argument".into(),
                    ));
                }
            }

            "skip" => {
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Skip expects a positional argument for count
                let skip_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(0);

                if skip_count <= 0 {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    return Ok(());
                }

                // Create a counter vreg to track how many items have been skipped
                let counter = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: counter,
                    src: MirValue::Const(0),
                });

                let loop_header = self.func.alloc_block();
                let loop_body = self.func.alloc_block();
                let loop_exit = self.func.alloc_block();

                self.terminate(MirInst::LoopHeader {
                    counter,
                    limit: skip_count,
                    body: loop_body,
                    exit: loop_exit,
                });

                self.current_block = loop_body;
                self.terminate(MirInst::LoopBack {
                    counter,
                    step: 1,
                    header: loop_header,
                });

                self.current_block = loop_exit;

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(input_vreg),
                });

                if let Some(reg) = input_reg {
                    if let Some(meta) = self.get_metadata(reg).cloned() {
                        let out_meta = self.get_or_create_metadata(src_dst);
                        out_meta.field_type = meta.field_type;
                        out_meta.string_slot = meta.string_slot;
                        out_meta.record_fields = meta.record_fields;
                    }
                }
            }

            "first" | "last" => {
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                let take_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1);

                if take_count <= 0 {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    return Ok(());
                }

                if cmd_name == "first" {
                    // Just pass the first element through
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    // For 'last', we need to loop to the end (not practical in eBPF)
                    // So we'll just return the input value for now
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                }
            }

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Command '{}' not supported in eBPF",
                    cmd_name
                )));
            }
        }

        self.clear_call_state();
        Ok(())
    }
}
