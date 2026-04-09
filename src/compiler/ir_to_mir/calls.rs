use super::*;
use crate::compiler::ProgramIntrinsic;
use crate::compiler::instruction::{
    KfuncSignature, kfunc_pointer_arg_fixed_size, kfunc_pointer_arg_requires_stack_slot_base,
};
use crate::compiler::mir::{
    AddressSpace, BYTES_COUNTER_MAP_NAME, COUNTER_MAP_NAME, STRING_COUNTER_MAP_NAME,
};

#[derive(Debug, Clone)]
struct ScalarKfuncOutArgWriteback {
    slot: StackSlotId,
    source_var: VarId,
    scalar_ty: MirType,
    original_arg_vreg: VReg,
}

impl<'a> HirToMirLowering<'a> {
    fn aggregate_call_value_type<'b>(ty: &'b MirType) -> Option<&'b MirType> {
        match ty {
            MirType::Array { .. } | MirType::Struct { .. } => Some(ty),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
            {
                Some(pointee.as_ref())
            }
            _ => None,
        }
    }

    fn aggregate_call_value_byte_array_len(ty: &MirType) -> Option<usize> {
        match ty {
            ty if ty.byte_array_len().is_some() => ty.byte_array_len(),
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => pointee.byte_array_len(),
            _ => None,
        }
    }

    fn literal_string_arg(&self, reg: RegId, context: &str) -> Result<String, CompileError> {
        self.get_metadata(reg)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} requires a compile-time string literal"
                ))
            })
    }

    fn parse_generic_map_kind(kind: &str) -> Option<MapKind> {
        match kind {
            "hash" => Some(MapKind::Hash),
            "array" => Some(MapKind::Array),
            "lpm-trie" | "lpm_trie" | "lpmtrie" => Some(MapKind::LpmTrie),
            "lru-hash" | "lru_hash" | "lruhash" => Some(MapKind::LruHash),
            "per-cpu-hash" | "percpu-hash" | "per_cpu_hash" => Some(MapKind::PerCpuHash),
            "per-cpu-array" | "percpu-array" | "per_cpu_array" => Some(MapKind::PerCpuArray),
            "lru-per-cpu-hash" | "lru-percpu-hash" | "lru_per_cpu_hash" | "lrupercpuhash" => {
                Some(MapKind::LruPerCpuHash)
            }
            _ => None,
        }
    }

    fn generic_map_kind_arg(&self, context: &str) -> Result<MapKind, CompileError> {
        let Some((_, reg)) = self.named_args.get("kind") else {
            return Ok(MapKind::Hash);
        };
        let kind = self.literal_string_arg(*reg, &format!("{context} --kind"))?;
        Self::parse_generic_map_kind(&kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} --kind must be one of: hash, array, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash"
            ))
        })
    }

    fn validate_generic_map_name(&self, map_name: &str, context: &str) -> Result<(), CompileError> {
        let mut chars = map_name.chars();
        let Some(first) = chars.next() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name must not be empty"
            )));
        };
        if !(first == '_' || first.is_ascii_alphabetic())
            || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} map name '{map_name}' must match [A-Za-z_][A-Za-z0-9_]*"
            )));
        }
        Ok(())
    }

    fn require_only_named_args(&self, context: &str, allowed: &[&str]) -> Result<(), CompileError> {
        for key in self.named_args.keys() {
            if !allowed.iter().any(|allowed_key| allowed_key == key) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} does not accept named argument '{}'",
                    key
                )));
            }
        }
        Ok(())
    }

    fn reset_call_result_metadata(&mut self, reg: RegId) {
        *self.get_or_create_metadata(reg) = RegMetadata::default();
    }

    fn materialize_scalar_kfunc_out_arg(
        &mut self,
        kfunc: &str,
        arg_idx: usize,
        arg_vreg: VReg,
        arg_reg: Option<RegId>,
    ) -> Result<(VReg, Option<ScalarKfuncOutArgWriteback>), CompileError> {
        let Some(arg_reg) = arg_reg else {
            return Ok((arg_vreg, None));
        };
        if matches!(
            self.vreg_type_hints.get(&arg_vreg),
            Some(MirType::Ptr { .. })
        ) {
            return Ok((arg_vreg, None));
        }

        if !kfunc_pointer_arg_requires_stack_slot_base(kfunc, arg_idx) {
            return Ok((arg_vreg, None));
        }

        let Some(source_var) = self.get_metadata(arg_reg).and_then(|meta| meta.source_var) else {
            return Ok((arg_vreg, None));
        };
        let Some(fixed_size) = kfunc_pointer_arg_fixed_size(kfunc, arg_idx) else {
            return Ok((arg_vreg, None));
        };
        let Some(scalar_ty) = self.direct_scalar_var_out_arg_type(arg_reg, arg_vreg, fixed_size)
        else {
            return Ok((arg_vreg, None));
        };

        let slot = self.func.alloc_stack_slot(
            align_to_eight(fixed_size.max(scalar_ty.size())),
            8,
            StackSlotKind::Local,
        );
        self.record_stack_slot_type(slot, scalar_ty.clone());
        self.emit(MirInst::StoreSlot {
            slot,
            offset: 0,
            val: MirValue::VReg(arg_vreg),
            ty: scalar_ty.clone(),
        });

        let ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: ptr_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            ptr_vreg,
            MirType::Ptr {
                pointee: Box::new(scalar_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        Ok((
            ptr_vreg,
            Some(ScalarKfuncOutArgWriteback {
                slot,
                source_var,
                scalar_ty,
                original_arg_vreg: arg_vreg,
            }),
        ))
    }

    fn write_back_scalar_kfunc_out_args(
        &mut self,
        writebacks: Vec<ScalarKfuncOutArgWriteback>,
    ) -> Result<(), CompileError> {
        for writeback in writebacks {
            let reloaded_vreg = self.func.alloc_vreg();
            self.emit(MirInst::LoadSlot {
                dst: reloaded_vreg,
                slot: writeback.slot,
                offset: 0,
                ty: writeback.scalar_ty.clone(),
            });
            self.vreg_type_hints
                .insert(reloaded_vreg, writeback.scalar_ty.clone());
            self.emit(MirInst::Copy {
                dst: writeback.original_arg_vreg,
                src: MirValue::VReg(reloaded_vreg),
            });
            self.vreg_type_hints
                .insert(writeback.original_arg_vreg, writeback.scalar_ty.clone());
            self.write_back_direct_scalar_var(
                writeback.source_var,
                writeback.scalar_ty,
                reloaded_vreg,
            )?;
        }
        Ok(())
    }

    fn validate_intrinsic_support(&self, intrinsic: ProgramIntrinsic) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Ok(());
        };
        if ctx.probe_type.supports_intrinsic(intrinsic) {
            return Ok(());
        }
        Err(CompileError::UnsupportedInstruction(format!(
            "{} is not supported on {} programs",
            intrinsic.command_name(),
            ctx.probe_type.canonical_prefix()
        )))
    }

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

        if let Some(intrinsic) = ProgramIntrinsic::from_command_name(&cmd_name) {
            self.validate_intrinsic_support(intrinsic)?;
        }

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
                    let size = match field_type.as_ref() {
                        Some(ty) if Self::aggregate_call_value_byte_array_len(ty).is_some() => {
                            Self::aggregate_call_value_byte_array_len(ty).unwrap()
                        }
                        Some(ty) if Self::aggregate_call_value_type(ty).is_some() => {
                            Self::aggregate_call_value_type(ty).unwrap().size()
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

                let (map_name, map_kind) = match key_type.as_ref() {
                    Some(ty) if Self::aggregate_call_value_byte_array_len(ty) == Some(16) => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (STRING_COUNTER_MAP_NAME, kind)
                    }
                    Some(ty) if Self::aggregate_call_value_type(ty).is_some() => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (BYTES_COUNTER_MAP_NAME, kind)
                    }
                    _ => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (COUNTER_MAP_NAME, kind)
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
                self.record_stack_slot_type(
                    slot,
                    MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: aligned_len,
                    },
                );
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
                self.record_stack_slot_type(
                    slot,
                    MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: aligned_len,
                    },
                );
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
                let is_known_zero_arg = KfuncSignature::for_name_or_kernel_btf(&kfunc)
                    .map(|sig| sig.max_args == 0)
                    .unwrap_or(false);
                if let Some(input) = self.pipeline_input {
                    args.push((input, self.pipeline_input_reg));
                } else if src_dst_had_value && !is_known_zero_arg {
                    args.push((dst_vreg, Some(src_dst)));
                }

                for (arg_vreg, arg_reg) in self.positional_args.iter().skip(1) {
                    args.push((*arg_vreg, Some(*arg_reg)));
                }

                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF kfunc calls support at most 5 arguments".into(),
                    ));
                }

                let mut call_args = Vec::with_capacity(args.len());
                let mut writebacks = Vec::new();
                for (idx, (arg_vreg, arg_reg)) in args.into_iter().enumerate() {
                    let (call_arg_vreg, writeback) =
                        self.materialize_scalar_kfunc_out_arg(&kfunc, idx, arg_vreg, arg_reg)?;
                    call_args.push(call_arg_vreg);
                    if let Some(writeback) = writeback {
                        writebacks.push(writeback);
                    }
                }

                self.emit(MirInst::CallKfunc {
                    dst: dst_vreg,
                    kfunc,
                    btf_id,
                    args: call_args,
                });
                self.write_back_scalar_kfunc_out_args(writebacks)?;
            }

            "map-get" => {
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-get does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-get", &["kind"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-get requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-get")?;
                self.validate_generic_map_name(&map_name, "map-get")?;
                let map_kind = self.generic_map_kind_arg("map-get")?;
                let map_ref = MapRef {
                    name: map_name.clone(),
                    kind: map_kind,
                };
                let key_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-get requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                let lookup_vreg = self.func.alloc_vreg();

                self.emit(MirInst::MapLookup {
                    dst: lookup_vreg,
                    map: map_ref.clone(),
                    key: key_vreg,
                });
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::VReg(lookup_vreg),
                });

                let stored_ty = self.named_map_value_type(&map_ref).cloned();
                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(stored_ty.clone().unwrap_or(MirType::U8)),
                    address_space: AddressSpace::Map,
                };
                self.vreg_type_hints.insert(lookup_vreg, runtime_ty.clone());
                self.vreg_type_hints.insert(result_vreg, runtime_ty);

                self.reset_call_result_metadata(src_dst);
                if let Some(value_ty @ (MirType::Array { .. } | MirType::Struct { .. })) = stored_ty
                {
                    let meta = self.get_or_create_metadata(src_dst);
                    meta.field_type = Some(MirType::Ptr {
                        pointee: Box::new(value_ty),
                        address_space: AddressSpace::Map,
                    });
                }
            }

            "map-put" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-put does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-put", &["kind", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-put requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-put")?;
                self.validate_generic_map_name(&map_name, "map-put")?;
                let map_kind = self.generic_map_kind_arg("map-put")?;
                let map_ref = MapRef {
                    name: map_name.clone(),
                    kind: map_kind,
                };
                let key_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-put requires a key as the second positional argument".into(),
                        )
                    })?;
                let flags = if let Some((_, reg)) = self.named_args.get("flags") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-put --flags must be a compile-time integer literal".into(),
                            )
                        })?;
                    u64::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction("map-put --flags must be >= 0".into())
                    })?
                } else {
                    0
                };
                let value_vreg = self
                    .pipeline_input
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-put requires a value from pipeline input".into(),
                        )
                    })?;

                self.emit(MirInst::MapUpdate {
                    map: map_ref.clone(),
                    key: key_vreg,
                    val: value_vreg,
                    flags,
                });

                let value_ty = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.field_type.clone())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .and_then(|m| m.field_type.clone())
                    });
                if let Some(value_ty) = value_ty {
                    let stored_value_ty = self.stored_generic_map_value_type(&value_ty);
                    if self.externally_seeded_map_value_types.contains(&map_ref) {
                        if let Some(existing) = self.named_map_value_type(&map_ref) {
                            if existing != &stored_value_ty {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "map-put value type for '{}' conflicts with pinned map schema",
                                    map_ref.name
                                )));
                            }
                        }
                    }
                    self.register_named_map_value_type(&map_ref, &stored_value_ty);
                }

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "map-delete" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-delete does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-delete", &["kind"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-delete requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-delete")?;
                self.validate_generic_map_name(&map_name, "map-delete")?;
                let map_kind = self.generic_map_kind_arg("map-delete")?;
                let map_ref = MapRef {
                    name: map_name,
                    kind: map_kind,
                };
                let key_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-delete requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;

                self.emit(MirInst::MapDelete {
                    map: map_ref,
                    key: key_vreg,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "global-define" => {
                let has_type_spec = self.named_args.contains_key("type");
                let zero_init = self.named_flags.iter().any(|flag| flag == "zero");
                if self.named_flags.iter().any(|flag| flag != "zero") {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define only accepts the --zero flag".into(),
                    ));
                }
                self.require_only_named_args("global-define", &["type"])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-define")?;
                self.validate_generic_map_name(&global_name, "global-define")?;
                if has_type_spec {
                    if zero_init {
                        return Err(CompileError::UnsupportedInstruction(
                            "global-define --type already implies zero initialization; do not combine it with --zero".into(),
                        ));
                    }
                    if self.pipeline_input.is_some() || src_dst_had_value {
                        return Err(CompileError::UnsupportedInstruction(
                            "global-define --type does not accept pipeline input; it declares layout directly".into(),
                        ));
                    }
                    let (type_vreg, type_reg) =
                        self.named_args.get("type").copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "global-define --type requires a compile-time type string".into(),
                            )
                        })?;
                    let _ = type_vreg;
                    let type_spec = self.literal_string_arg(type_reg, "global-define --type")?;
                    self.define_named_program_global_from_type_spec(&global_name, &type_spec)?;

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    self.reset_call_result_metadata(src_dst);
                    return Ok(());
                }
                let value_vreg = self
                    .pipeline_input
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            if zero_init {
                                "global-define --zero requires a value from pipeline input to establish layout"
                                    .into()
                            } else {
                                "global-define requires a compile-time constant value from pipeline input"
                                    .into()
                            },
                        )
                    })?;
                let value_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "global-define requires a source value with tracked metadata".into(),
                        )
                    })?;
                if !zero_init
                    && self
                        .get_metadata(value_reg)
                        .and_then(|meta| meta.constant_value.as_ref())
                        .is_none()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define requires a compile-time constant value".into(),
                    ));
                }
                if zero_init {
                    self.ensure_zeroed_named_program_global(&global_name, value_reg, value_vreg)?;
                } else {
                    self.ensure_named_program_global(&global_name, value_reg, value_vreg)?;
                }

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "global-get" => {
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-get does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("global-get", &[])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-get requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-get")?;
                self.validate_generic_map_name(&global_name, "global-get")?;
                let global = self
                    .named_program_global(&global_name)
                    .cloned()
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "global-get for '{}' requires a same-program global-define or layout-establishing global-set",
                            global_name
                        ))
                    })?;

                self.load_mutable_global_value(src_dst, result_vreg, &global)?;
            }

            "global-set" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-set does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("global-set", &[])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-set requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-set")?;
                self.validate_generic_map_name(&global_name, "global-set")?;
                let value_vreg = self
                    .pipeline_input
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "global-set requires a value from pipeline input".into(),
                        )
                    })?;
                let value_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "global-set requires a source value with tracked metadata".into(),
                        )
                    })?;
                let global =
                    self.ensure_named_program_global(&global_name, value_reg, value_vreg)?;
                self.store_into_mutable_global(
                    &format!("global '{}'", global_name),
                    &global,
                    value_reg,
                    value_vreg,
                )?;

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
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
                            self.record_list_buffer_slot_type(out_slot, max_len);
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
                    start: 0,
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

            "get" => {
                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "get does not accept named flags or arguments in eBPF".into(),
                    ));
                }

                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                let (idx_vreg, idx_reg) =
                    self.positional_args.first().copied().ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "get requires a numeric positional index argument".into(),
                        )
                    })?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "get accepts exactly one positional index argument in eBPF".into(),
                    ));
                }

                let idx = self
                    .get_metadata(idx_reg)
                    .and_then(|meta| {
                        meta.literal_int.or_else(|| {
                            meta.cell_path
                                .as_ref()
                                .and_then(|path| match path.members.as_slice() {
                                    [PathMember::Int { val, .. }] => Some(*val as i64),
                                    _ => None,
                                })
                        })
                    })
                    .map(MirValue::Const)
                    .unwrap_or(MirValue::VReg(idx_vreg));
                let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                let mut handled_list_get = false;
                if let Some(meta) = input_meta {
                    if meta.list_buffer.is_some() {
                        self.emit(MirInst::ListGet {
                            dst: dst_vreg,
                            list: input_vreg,
                            idx: idx.clone(),
                        });

                        let out_meta = self.get_or_create_metadata(src_dst);
                        out_meta.field_type = Some(MirType::I64);
                        handled_list_get = true;
                    }
                }

                if handled_list_get {
                    // Metadata is already updated for stack-backed list access.
                } else {
                    let input_reg = input_reg.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "get requires a list value or typed kernel/user pointer input".into(),
                        )
                    })?;
                    let base_runtime_ty = self
                        .typed_value_runtime_type(input_reg, input_vreg)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "get requires a list value or typed kernel/user pointer input"
                                    .into(),
                            )
                        })?;

                    match &base_runtime_ty {
                        MirType::Ptr { .. } => {
                            self.lower_dynamic_typed_numeric_get(
                                src_dst,
                                input_vreg,
                                &base_runtime_ty,
                                idx,
                            )?;
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "get requires a list value or typed pointer input, got {:?}",
                                base_runtime_ty
                            )));
                        }
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
