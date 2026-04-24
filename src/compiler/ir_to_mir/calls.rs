use super::*;
use crate::compiler::elf::{MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::{
    BpfHelper, HelperArgKind, HelperExplicitMapKindFamily, HelperRetKind, HelperSignature,
    KfuncSignature, helper_acquire_ref_kind,
};
use crate::compiler::mir::{
    AddressSpace, BYTES_COUNTER_MAP_NAME, COUNTER_MAP_NAME, MapOpKind, STRING_COUNTER_MAP_NAME,
};
use crate::compiler::{ProgramIntrinsic, TypeInference};

const BPF_SK_LOOKUP_F_REPLACE: u64 = 1 << 0;
const BPF_SK_LOOKUP_F_NO_REUSEPORT: u64 = 1 << 1;

impl<'a> HirToMirLowering<'a> {
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
                        .map(|f| {
                            let value =
                                if matches!(f.ty, MirType::Array { .. } | MirType::Struct { .. }) {
                                    self.materialized_record_field_value_vreg(f)?
                                } else {
                                    f.value_vreg
                                };
                            Ok(RecordFieldDef {
                                name: f.name.clone(),
                                value,
                                ty: f.ty.clone(),
                            })
                        })
                        .collect::<Result<Vec<_>, CompileError>>()?;
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
                self.reset_call_result_metadata(src_dst);
            }

            "count" => {
                self.needs_counter_map = true;
                let key_reg = self.pipeline_input_reg.unwrap_or(src_dst);
                let mut key_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let key_type = self
                    .get_metadata(key_reg)
                    .and_then(|m| {
                        m.field_type
                            .clone()
                            .or_else(|| Self::metadata_record_layout(m))
                    })
                    .or_else(|| self.vreg_type_hints.get(&key_vreg).cloned())
                    .map(|ty| self.stored_generic_map_value_type(&ty));

                if let Some(key_type) = key_type.as_ref()
                    && Self::aggregate_call_value_type(key_type).is_some()
                {
                    key_vreg = self.materialized_metadata_aggregate_vreg(key_reg, key_vreg)?;
                }

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

                let result_vreg = self.assign_fresh_vreg(src_dst);

                // Return 0
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(result_vreg, MirType::I64);

                self.reset_call_result_metadata(src_dst);
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
                self.reset_call_result_metadata(src_dst);
            }

            "start-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StartTimer);
                // Return 0 (void)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "stop-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StopTimer { dst: dst_vreg });
            }

            "random int" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int does not accept flags in eBPF".into(),
                    ));
                }
                self.require_only_named_args("random int", &[])?;
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int accepts at most one range argument in eBPF".into(),
                    ));
                }
                if self.pipeline_input.is_some() || src_dst_had_value {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int does not accept pipeline input in eBPF".into(),
                    ));
                }

                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::GetPrandomU32 as u32,
                    args: Vec::new(),
                });

                if let Some((_, range_reg)) = self.positional_args.first().copied() {
                    let range = self
                        .get_metadata(range_reg)
                        .and_then(|meta| meta.bounded_range)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "random int range must be a compile-time bounded integer range"
                                    .into(),
                            )
                        })?;
                    let min = range.start;
                    let max = if range.inclusive {
                        range.end
                    } else {
                        range.end.checked_sub(1).ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "random int range end is too small".into(),
                            )
                        })?
                    };
                    if max < min {
                        return Err(CompileError::UnsupportedInstruction(
                            "random int range end must be >= start".into(),
                        ));
                    }
                    let span = (max as i128) - (min as i128) + 1;
                    let max_span = u32::MAX as i128 + 1;
                    if !(1..=max_span).contains(&span) {
                        return Err(CompileError::UnsupportedInstruction(
                            "random int eBPF ranges must cover at most 2^32 values".into(),
                        ));
                    }

                    let span_operand = self.large_const_operand(&MirType::I64, span as i64);
                    self.emit(MirInst::BinOp {
                        dst: dst_vreg,
                        op: BinOpKind::Mod,
                        lhs: MirValue::VReg(dst_vreg),
                        rhs: span_operand,
                    });
                    if min != 0 {
                        let min_operand = self.large_const_operand(&MirType::I64, min);
                        self.emit(MirInst::BinOp {
                            dst: dst_vreg,
                            op: BinOpKind::Add,
                            lhs: MirValue::VReg(dst_vreg),
                            rhs: min_operand,
                        });
                    }
                }

                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
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
                self.lower_probe_read_string(src_dst, dst_vreg, ptr_vreg, true, aligned_len)?;
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
                self.lower_probe_read_string(src_dst, dst_vreg, ptr_vreg, false, aligned_len)?;
            }

            "adjust-packet" => {
                self.require_only_named_args("adjust-packet", &["mode", "flags"])?;
                let mode = self.packet_adjust_mode_from_named_flags("adjust-packet")?;
                let helper =
                    self.packet_adjust_helper_for_current_program("adjust-packet", mode)?;

                if mode != PacketAdjustMode::Room {
                    if self.named_args.contains_key("mode") {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} does not accept --mode",
                            mode.flag_name()
                        )));
                    }
                    if self.named_args.contains_key("flags") {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} does not accept --flags",
                            mode.flag_name()
                        )));
                    }
                }

                let value_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} requires a {} from pipeline input or a first positional argument",
                            mode.flag_name(),
                            mode.value_name()
                        ))
                    })?;
                let ctx_vreg = self.materialize_context_pointer_arg();
                let args = match helper {
                    BpfHelper::XdpAdjustHead
                    | BpfHelper::XdpAdjustMeta
                    | BpfHelper::XdpAdjustTail
                    | BpfHelper::SkbPullData => {
                        vec![MirValue::VReg(ctx_vreg), MirValue::VReg(value_vreg)]
                    }
                    BpfHelper::SkbChangeHead | BpfHelper::SkbChangeTail => vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(value_vreg),
                        MirValue::Const(0),
                    ],
                    BpfHelper::SkbAdjustRoom => {
                        let mode_value = self
                            .optional_nonnegative_named_u64_arg("adjust-packet --room", "mode")?
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "adjust-packet --room requires --mode".into(),
                                )
                            })?;
                        let flags = self
                            .optional_nonnegative_named_u64_arg("adjust-packet --room", "flags")?
                            .unwrap_or(0);
                        vec![
                            MirValue::VReg(ctx_vreg),
                            MirValue::VReg(value_vreg),
                            MirValue::Const(mode_value as i64),
                            MirValue::Const(flags as i64),
                        ]
                    }
                    _ => unreachable!("packet adjust helper selection returned unexpected helper"),
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "adjust-message" => {
                self.require_only_named_args("adjust-message", &["flags"])?;
                let mode = self.message_adjust_mode_from_named_flags("adjust-message")?;
                let helper =
                    self.message_adjust_helper_for_current_program("adjust-message", mode)?;

                if matches!(mode, MessageAdjustMode::Apply | MessageAdjustMode::Cork)
                    && self.named_args.contains_key("flags")
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "adjust-message --{} does not accept --flags",
                        mode.flag_name()
                    )));
                }

                let first_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "adjust-message --{} requires {} from pipeline input or a first positional argument",
                            mode.flag_name(),
                            mode.first_value_name()
                        ))
                    })?;
                let ctx_vreg = self.materialize_context_pointer_arg();
                let args = match mode {
                    MessageAdjustMode::Apply | MessageAdjustMode::Cork => {
                        vec![MirValue::VReg(ctx_vreg), MirValue::VReg(first_vreg)]
                    }
                    MessageAdjustMode::Pull | MessageAdjustMode::Push | MessageAdjustMode::Pop => {
                        let second_name = mode
                            .second_value_name()
                            .expect("pull/push/pop require a second scalar");
                        let second_vreg = self
                            .positional_args
                            .get(1)
                            .map(|(vreg, _)| *vreg)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "adjust-message --{} requires a {} as the second positional argument",
                                    mode.flag_name(),
                                    second_name
                                ))
                            })?;
                        let flags = self
                            .optional_nonnegative_named_u64_arg("adjust-message", "flags")?
                            .unwrap_or(0);
                        vec![
                            MirValue::VReg(ctx_vreg),
                            MirValue::VReg(first_vreg),
                            MirValue::VReg(second_vreg),
                            MirValue::Const(flags as i64),
                        ]
                    }
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect" => {
                self.require_only_named_args("redirect", &["flags"])?;
                let helper = self.packet_redirect_helper_from_named_flags("redirect")?;
                if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper))
                {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let ifindex_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect requires an ifindex from pipeline input or a first positional argument"
                                .into(),
                        )
                    })?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect", "flags")?
                    .unwrap_or(0);
                self.validate_packet_redirect_flags(helper, flags)?;

                let args = match helper {
                    BpfHelper::Redirect | BpfHelper::RedirectPeer => {
                        vec![MirValue::VReg(ifindex_vreg), MirValue::Const(flags as i64)]
                    }
                    BpfHelper::RedirectNeigh => vec![
                        MirValue::VReg(ifindex_vreg),
                        MirValue::Const(0),
                        MirValue::Const(0),
                        MirValue::Const(flags as i64),
                    ],
                    _ => unreachable!(
                        "packet redirect helper selection returned non-redirect helper"
                    ),
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect-map" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "redirect-map does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("redirect-map", &["kind", "flags"])?;
                if let Some(message) = self
                    .probe_ctx
                    .and_then(|ctx| ctx.helper_call_error(BpfHelper::RedirectMap))
                {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "redirect-map requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "redirect-map")?;
                self.validate_generic_map_name(&map_name, "redirect-map")?;
                let map_kind = self.required_redirect_map_kind_arg("redirect-map")?;
                let key_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect-map requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect-map", "flags")?
                    .unwrap_or(0);

                let map_vreg = self.emit_typed_map_fd_load(map_name, map_kind);
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::RedirectMap as u32,
                    args: vec![
                        MirValue::VReg(map_vreg),
                        MirValue::VReg(key_vreg),
                        MirValue::Const(flags as i64),
                    ],
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect-socket" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "redirect-socket does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("redirect-socket", &["kind", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "redirect-socket requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "redirect-socket")?;
                self.validate_generic_map_name(&map_name, "redirect-socket")?;
                let map_kind = self.required_socket_map_kind_arg("redirect-socket")?;
                let helper =
                    self.socket_redirect_helper_for_current_program("redirect-socket", map_kind)?;
                let key_arg = self
                    .positional_args
                    .get(1)
                    .copied()
                    .map(|(vreg, reg)| (vreg, Some(reg)))
                    .or_else(|| self.pipeline_input.map(|vreg| (vreg, self.pipeline_input_reg)))
                    .or_else(|| src_dst_had_value.then_some((dst_vreg, Some(src_dst))))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect-socket requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect-socket", "flags")?
                    .unwrap_or(0);

                let ctx_vreg = self.materialize_context_pointer_arg();
                let map_vreg = self.emit_typed_map_fd_load(map_name, map_kind);
                let key_value = if helper.signature().arg_kind(2) == HelperArgKind::Pointer {
                    let (key_ptr_vreg, _) = self.materialize_map_value_probe_pointer(
                        key_arg.1,
                        key_arg.0,
                        "redirect-socket",
                    )?;
                    MirValue::VReg(key_ptr_vreg)
                } else {
                    MirValue::VReg(key_arg.0)
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args: vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(map_vreg),
                        key_value,
                        MirValue::Const(flags as i64),
                    ],
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "assign-socket" => {
                self.require_only_named_args("assign-socket", &["flags"])?;
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "assign-socket accepts at most one socket argument".into(),
                    ));
                }

                let Some(ctx) = self.probe_ctx else {
                    return Err(CompileError::UnsupportedInstruction(
                        "assign-socket requires a known attached program context".into(),
                    ));
                };
                if let Some(message) = ctx.helper_call_error(BpfHelper::SkAssign) {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let mut flags = self
                    .optional_nonnegative_named_u64_arg("assign-socket", "flags")?
                    .unwrap_or(0);
                for flag in &self.named_flags {
                    match flag.as_str() {
                        "replace" => flags |= BPF_SK_LOOKUP_F_REPLACE,
                        "no-reuseport" => flags |= BPF_SK_LOOKUP_F_NO_REUSEPORT,
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "assign-socket does not accept flag '{}'",
                                flag
                            )));
                        }
                    }
                }
                if let Some((2, message)) = ctx.helper_zero_arg_requirement(BpfHelper::SkAssign)
                    && flags != 0
                {
                    return Err(CompileError::UnsupportedInstruction(message.to_string()));
                }

                let sk_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "assign-socket requires a socket pointer or null from pipeline input or the first positional argument"
                                .into(),
                        )
                    })?;

                let ctx_vreg = self.materialize_context_pointer_arg();
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::SkAssign as u32,
                    args: vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(sk_vreg),
                        MirValue::Const(flags as i64),
                    ],
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
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

                let positional_args: Vec<_> =
                    self.positional_args.iter().skip(1).copied().collect();
                let has_explicit_context_arg = positional_args
                    .iter()
                    .any(|(_, arg_reg)| self.is_context_reg(*arg_reg));
                let mut args = Vec::new();
                let is_known_zero_arg = KfuncSignature::for_name_or_kernel_btf(&kfunc)
                    .map(|sig| sig.max_args == 0)
                    .unwrap_or(false);
                if let Some(input) = self.pipeline_input {
                    if has_explicit_context_arg {
                        // Match helper-call behavior: an explicit `$ctx` should
                        // not be duplicated by the ambient pipeline input.
                    } else {
                        let arg_vreg = if self
                            .pipeline_input_reg
                            .is_some_and(|reg| self.is_context_reg(reg))
                        {
                            self.materialize_context_pointer_arg()
                        } else {
                            input
                        };
                        args.push((arg_vreg, self.pipeline_input_reg));
                    }
                } else if src_dst_had_value && !is_known_zero_arg {
                    let arg_vreg = if self.is_context_reg(src_dst) {
                        self.materialize_context_pointer_arg()
                    } else {
                        dst_vreg
                    };
                    args.push((arg_vreg, Some(src_dst)));
                }

                for (arg_vreg, arg_reg) in positional_args {
                    let call_arg_vreg = if self.is_context_reg(arg_reg) {
                        self.materialize_context_pointer_arg()
                    } else {
                        arg_vreg
                    };
                    args.push((call_arg_vreg, Some(arg_reg)));
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

            "helper-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "helper-call does not accept flags".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "helper-call requires a literal helper name as the first positional argument"
                            .into(),
                    )
                })?;
                let helper_name = self.literal_string_arg(name_reg, "helper-call")?;
                let helper = BpfHelper::from_name(&helper_name).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "helper-call does not support helper '{}'",
                        helper_name
                    ))
                })?;
                let helper_id = helper as u32;
                let sig = HelperSignature::for_id(helper_id).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "helper-call does not have a modeled signature for '{}'",
                        helper.name()
                    ))
                })?;
                if helper.requires_callback_subprogram()
                    && !helper.supports_modeled_callback_subprogram()
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call '{}' requires callback subprogram pointer support, which is not modeled yet",
                        helper.name()
                    )));
                }
                self.require_only_named_args("helper-call", &["kind"])?;
                if self.named_args.contains_key("kind")
                    && !helper.helper_requires_explicit_map_kind(0)
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call --kind is only supported for helpers whose map family is ambiguous; '{}' already implies its map kind",
                        helper.name()
                    )));
                }

                let positional_args: Vec<_> =
                    self.positional_args.iter().skip(1).copied().collect();
                let has_explicit_context_arg = positional_args
                    .iter()
                    .any(|(_, arg_reg)| self.is_context_reg(*arg_reg));
                let mut args = Vec::new();
                let mut helper_arg_regs: Vec<(usize, RegId)> = Vec::new();
                let mut helper_map_args: Vec<(usize, MapRef, VReg)> = Vec::new();
                if let Some(input) = self.pipeline_input {
                    if has_explicit_context_arg {
                        // Real attached closures carry the program context as ambient
                        // pipeline input. If the caller already passed `$ctx`
                        // explicitly, don't prepend that ambient value again.
                    } else {
                        let arg_vreg = if self
                            .pipeline_input_reg
                            .is_some_and(|reg| self.is_context_reg(reg))
                        {
                            self.materialize_context_pointer_arg()
                        } else {
                            input
                        };
                        if let Some(input_reg) = self.pipeline_input_reg {
                            helper_arg_regs.push((args.len(), input_reg));
                        }
                        args.push(MirValue::VReg(arg_vreg));
                    }
                } else if src_dst_had_value && sig.max_args != 0 && self.positional_args.len() == 1
                {
                    let arg_vreg = if self.is_context_reg(src_dst) {
                        self.materialize_context_pointer_arg()
                    } else {
                        dst_vreg
                    };
                    helper_arg_regs.push((args.len(), src_dst));
                    args.push(MirValue::VReg(arg_vreg));
                }
                for (arg_vreg, arg_reg) in positional_args {
                    let helper_arg_idx = args.len();
                    if helper.supports_local_helper_map_fd(helper_arg_idx) {
                        let (arg, map_ref, map_vreg) =
                            self.materialize_helper_map_fd_arg(helper, helper_arg_idx, arg_reg)?;
                        helper_map_args.push((helper_arg_idx, map_ref, map_vreg));
                        args.push(arg);
                        continue;
                    }
                    if helper.supports_modeled_callback_subprogram()
                        && matches!(sig.arg_kind(helper_arg_idx), HelperArgKind::Subprogram)
                    {
                        let arg = self.lower_helper_callback_subprogram_arg(
                            helper,
                            helper_arg_idx,
                            arg_reg,
                        )?;
                        helper_arg_regs.push((helper_arg_idx, arg_reg));
                        args.push(arg);
                        continue;
                    }
                    let helper_arg_vreg = if self.is_context_reg(arg_reg) {
                        self.materialize_context_pointer_arg()
                    } else {
                        arg_vreg
                    };
                    helper_arg_regs.push((helper_arg_idx, arg_reg));
                    args.push(MirValue::VReg(helper_arg_vreg));
                }
                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF helper calls support at most 5 arguments".into(),
                    ));
                }

                self.record_storage_helper_value_schema(
                    helper,
                    dst_vreg,
                    &helper_map_args,
                    &helper_arg_regs,
                )?;

                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper_id,
                    args,
                });
                match sig.ret_kind {
                    HelperRetKind::Scalar => {
                        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                    }
                    HelperRetKind::PointerNonNull | HelperRetKind::PointerMaybeNull => {
                        let ret_ty = TypeInference::precise_helper_return_mir_type(helper)
                            .unwrap_or_else(|| {
                                let address_space = if matches!(helper, BpfHelper::KptrXchg)
                                    || helper_acquire_ref_kind(helper).is_some()
                                {
                                    AddressSpace::Kernel
                                } else {
                                    AddressSpace::Map
                                };
                                MirType::Ptr {
                                    pointee: Box::new(MirType::Unknown),
                                    address_space,
                                }
                            });
                        self.vreg_type_hints.insert(dst_vreg, ret_ty);
                    }
                }
            }

            "tail-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "tail-call does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("tail-call", &[])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "tail-call requires a literal program-array map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "tail-call")?;
                self.validate_generic_map_name(&map_name, "tail-call")?;
                let index_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "tail-call requires a target index from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;

                self.terminate(MirInst::TailCall {
                    prog_map: MapRef {
                        name: map_name,
                        kind: MapKind::ProgArray,
                    },
                    index: MirValue::VReg(index_vreg),
                });
                self.reset_call_result_metadata(src_dst);
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
                self.require_only_named_args("map-get", &["kind", "init", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-get requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-get")?;
                self.validate_generic_map_name(&map_name, "map-get")?;
                let map_kind = self.map_get_kind_arg("map-get")?;
                let map_ref = MapRef {
                    name: map_name.clone(),
                    kind: map_kind,
                };
                if map_kind.is_local_storage() {
                    self.lower_local_storage_map_get(
                        src_dst,
                        dst_vreg,
                        result_vreg,
                        src_dst_had_value,
                        map_ref,
                    )?;
                } else {
                    if self.named_args.contains_key("init") {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-get --init is only supported for local-storage map kinds".into(),
                        ));
                    }
                    if self.named_args.contains_key("flags") {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-get --flags is only supported for local-storage map kinds".into(),
                        ));
                    }
                    self.validate_generic_map_lookup_kind(map_kind, &map_name)?;
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
                    if let Some(value_ty @ (MirType::Array { .. } | MirType::Struct { .. })) =
                        stored_ty
                    {
                        let semantics = self.named_map_value_semantics(&map_ref).cloned();
                        let meta = self.get_or_create_metadata(src_dst);
                        meta.field_type = Some(MirType::Ptr {
                            pointee: Box::new(value_ty),
                            address_space: AddressSpace::Map,
                        });
                        if let Some(semantics) = semantics {
                            meta.annotated_semantics = Some(semantics);
                        }
                    }
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
                let (key_vreg, key_reg) = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, reg)| (*vreg, *reg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-put requires a key as the second positional argument".into(),
                        )
                    })?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("map-put", "flags")?
                    .unwrap_or(0);

                if map_kind.is_socket_map() {
                    self.lower_socket_map_put(
                        src_dst,
                        dst_vreg,
                        src_dst_had_value,
                        map_ref,
                        key_vreg,
                        key_reg,
                        flags,
                    )?;
                } else {
                    self.validate_generic_map_update_kind(map_kind, &map_name)?;
                    let value_vreg = self
                        .pipeline_input
                        .or_else(|| src_dst_had_value.then_some(dst_vreg))
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-put requires a value from pipeline input".into(),
                            )
                        })?;
                    let value_reg = self
                        .pipeline_input_reg
                        .or_else(|| src_dst_had_value.then_some(src_dst));
                    let stored_value_vreg = if let Some(value_reg) = value_reg {
                        self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
                    } else {
                        value_vreg
                    };

                    self.emit(MirInst::MapUpdate {
                        map: map_ref.clone(),
                        key: key_vreg,
                        val: stored_value_vreg,
                        flags,
                    });
                    self.record_named_map_value_schema_from_reg(&map_ref, value_reg, "map-put")?;

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    self.reset_call_result_metadata(src_dst);
                }
            }

            "map-push" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-push does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-push", &["kind", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-push requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-push")?;
                self.validate_generic_map_name(&map_name, "map-push")?;
                let map_kind = self.required_queue_stack_bloom_map_kind_arg("map-push")?;
                let map_ref = MapRef {
                    name: map_name,
                    kind: map_kind,
                };
                let flags = if let Some((_, reg)) = self.named_args.get("flags") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-push --flags must be a compile-time integer literal".into(),
                            )
                        })?;
                    u64::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction("map-push --flags must be >= 0".into())
                    })?
                } else {
                    0
                };
                let value_vreg = self
                    .pipeline_input
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-push requires a value from pipeline input".into(),
                        )
                    })?;
                let value_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                let stored_value_vreg = if let Some(value_reg) = value_reg {
                    self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
                } else {
                    value_vreg
                };
                self.record_named_map_value_schema_from_reg(&map_ref, value_reg, "map-push")?;

                self.emit(MirInst::MapPush {
                    map: map_ref,
                    val: stored_value_vreg,
                    flags,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "map-peek" => {
                self.lower_queue_stack_map_take(
                    src_dst,
                    dst_vreg,
                    "map-peek",
                    BpfHelper::MapPeekElem,
                )?;
            }

            "map-pop" => {
                self.lower_queue_stack_map_take(
                    src_dst,
                    dst_vreg,
                    "map-pop",
                    BpfHelper::MapPopElem,
                )?;
            }

            "map-contains" => {
                self.lower_map_contains(src_dst, dst_vreg, src_dst_had_value)?;
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
                let map_kind = self.map_delete_kind_arg("map-delete")?;
                let map_ref = MapRef {
                    name: map_name,
                    kind: map_kind,
                };
                if map_kind.is_local_storage() {
                    self.lower_local_storage_map_delete(
                        src_dst,
                        dst_vreg,
                        src_dst_had_value,
                        map_ref,
                    )?;
                } else {
                    self.validate_generic_map_delete_kind(map_kind, &map_ref.name)?;
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
                    let (type_vreg, type_reg) =
                        self.named_args.get("type").copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "global-define --type requires a compile-time type string".into(),
                            )
                        })?;
                    let _ = type_vreg;
                    let type_spec = self.literal_string_arg(type_reg, "global-define --type")?;
                    let constant_value = self
                        .pipeline_input_reg
                        .or_else(|| src_dst_had_value.then_some(src_dst))
                        .and_then(|reg| {
                            self.get_metadata(reg)
                                .and_then(|meta| meta.constant_value.clone())
                        });
                    if let Some(value) = constant_value.as_ref() {
                        self.define_named_program_global_from_type_spec_and_value(
                            &global_name,
                            &type_spec,
                            value,
                        )?;
                    } else if self.pipeline_input.is_some() || src_dst_had_value {
                        return Err(CompileError::UnsupportedInstruction(
                            "global-define --type with pipeline input requires a compile-time constant value".into(),
                        ));
                    } else {
                        self.define_named_program_global_from_type_spec(&global_name, &type_spec)?;
                    }

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
                if let Some(semantics) = self.named_program_global_semantics(&global_name).cloned()
                {
                    self.get_or_create_metadata(src_dst).annotated_semantics = Some(semantics);
                }
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

                    if let Some(reg) = input_reg {
                        self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
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
                    if let Some(reg) = input_reg {
                        self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
                    }
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
                    step: 1,
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
                    self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
                }
            }

            "get" => {
                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "get does not accept named flags or arguments in eBPF".into(),
                    ));
                }

                let mut input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
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
                            dst: result_vreg,
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
                    let mut base_runtime_ty = self
                        .typed_value_runtime_type(input_reg, input_vreg)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "get requires a list value or typed kernel/user pointer input"
                                    .into(),
                            )
                        })?;
                    if !matches!(base_runtime_ty, MirType::Ptr { .. })
                        && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
                    {
                        input_vreg =
                            self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
                        base_runtime_ty = self
                            .typed_value_runtime_type(input_reg, input_vreg)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "get requires a list value or typed kernel/user pointer input"
                                        .into(),
                                )
                            })?;
                    }

                    match &base_runtime_ty {
                        MirType::Ptr { .. } => {
                            let root_ctx_field = self
                                .get_metadata(input_reg)
                                .and_then(|meta| meta.root_ctx_field.clone());
                            self.lower_dynamic_typed_numeric_get(
                                src_dst,
                                input_vreg,
                                &base_runtime_ty,
                                idx,
                                root_ctx_field.as_ref(),
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
                        self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
                    }
                } else {
                    // For 'last', we need to loop to the end (not practical in eBPF)
                    // So we'll just return the input value for now
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    if let Some(reg) = input_reg {
                        self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
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

    fn record_named_map_value_schema_from_reg(
        &mut self,
        map_ref: &MapRef,
        value_reg: Option<RegId>,
        context: &str,
    ) -> Result<(), CompileError> {
        let value_ty = value_reg
            .and_then(|reg| self.get_metadata(reg))
            .and_then(|m| {
                m.field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(m))
            });
        let value_constant = value_reg
            .and_then(|reg| self.get_metadata(reg))
            .and_then(|m| m.constant_value.clone());
        let value_semantics = value_reg
            .map(|reg| self.tracked_value_semantics(reg, value_constant.as_ref()))
            .transpose()?
            .flatten();
        if let Some(value_ty) = value_ty {
            let stored_value_ty = self.stored_generic_map_value_type(&value_ty);
            if self.externally_seeded_map_value_types.contains(map_ref)
                && let Some(existing) = self.named_map_value_type(map_ref)
                && existing != &stored_value_ty
            {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} value type for '{}' conflicts with pinned map schema",
                    map_ref.name
                )));
            }
            self.register_named_map_value_type(map_ref, &stored_value_ty);
        }
        if let Some(value_semantics) = value_semantics {
            if self.externally_seeded_map_value_semantics.contains(map_ref)
                && let Some(existing) = self.named_map_value_semantics(map_ref)
                && existing != &value_semantics
            {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} value semantics for '{}' conflicts with pinned map schema",
                    map_ref.name
                )));
            }
            self.register_named_map_value_semantics(map_ref, &value_semantics);
        }
        Ok(())
    }

    fn local_storage_get_helper_for_kind(map_kind: MapKind) -> Option<BpfHelper> {
        match map_kind {
            MapKind::SkStorage => Some(BpfHelper::SkStorageGet),
            MapKind::InodeStorage => Some(BpfHelper::InodeStorageGet),
            MapKind::TaskStorage => Some(BpfHelper::TaskStorageGet),
            MapKind::CgrpStorage => Some(BpfHelper::CgrpStorageGet),
            _ => None,
        }
    }

    fn local_storage_delete_helper_for_kind(map_kind: MapKind) -> Option<BpfHelper> {
        match map_kind {
            MapKind::SkStorage => Some(BpfHelper::SkStorageDelete),
            MapKind::InodeStorage => Some(BpfHelper::InodeStorageDelete),
            MapKind::TaskStorage => Some(BpfHelper::TaskStorageDelete),
            MapKind::CgrpStorage => Some(BpfHelper::CgrpStorageDelete),
            _ => None,
        }
    }

    fn socket_map_update_helper_for_kind(map_kind: MapKind) -> Option<BpfHelper> {
        match map_kind {
            MapKind::SockMap => Some(BpfHelper::SockMapUpdate),
            MapKind::SockHash => Some(BpfHelper::SockHashUpdate),
            _ => None,
        }
    }

    fn lower_socket_map_put(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_ref: MapRef,
        key_vreg: VReg,
        key_reg: RegId,
        flags: u64,
    ) -> Result<(), CompileError> {
        let helper = Self::socket_map_update_helper_for_kind(map_ref.kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "map-put does not support socket map kind {:?}",
                map_ref.kind
            ))
        })?;
        let probe_ctx = self.probe_ctx.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-put --kind sockmap/sockhash requires a sock_ops program context".into(),
            )
        })?;
        if let Some(message) = probe_ctx.helper_call_error(helper) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        let ctx_vreg = self
            .pipeline_input
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-put --kind sockmap/sockhash requires a sock_ops context from pipeline input"
                        .into(),
                )
            })?;
        let ctx_reg = self
            .pipeline_input_reg
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let ctx_vreg = if ctx_reg.is_some_and(|reg| self.is_context_reg(reg)) {
            self.materialize_context_pointer_arg()
        } else {
            ctx_vreg
        };

        let (key_ptr_vreg, _key_ty) =
            self.materialize_map_value_probe_pointer(Some(key_reg), key_vreg, "map-put")?;
        let map_key_ty = if matches!(map_ref.kind, MapKind::SockMap) {
            MirType::U32
        } else {
            // Sockhash key layout is inferred from the helper key pointer.
            // Seeding it here can conflict with path-specific pointer metadata.
            MirType::Unknown
        };
        let map_vreg = self.emit_typed_map_fd_load(map_ref.name, map_ref.kind);
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(map_key_ty),
                val_ty: Box::new(MirType::U32),
            },
        );

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx_vreg),
                MirValue::VReg(map_vreg),
                MirValue::VReg(key_ptr_vreg),
                MirValue::Const(flags as i64),
            ],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn local_storage_object_vreg(&mut self, object_vreg: VReg, object_reg: Option<RegId>) -> VReg {
        if object_reg.is_some_and(|reg| self.is_context_reg(reg)) {
            self.materialize_context_pointer_arg()
        } else {
            object_vreg
        }
    }

    fn local_storage_map_value_hint(&self, map_ref: &MapRef) -> MirType {
        self.named_map_value_type(map_ref)
            .cloned()
            .unwrap_or(MirType::Unknown)
    }

    fn lower_local_storage_map_get(
        &mut self,
        src_dst: RegId,
        src_dst_value_vreg: VReg,
        result_vreg: VReg,
        src_dst_had_value: bool,
        map_ref: MapRef,
    ) -> Result<(), CompileError> {
        let helper = Self::local_storage_get_helper_for_kind(map_ref.kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "map-get does not support local-storage map kind {:?}",
                map_ref.kind
            ))
        })?;
        let object_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(src_dst_value_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-get local-storage requires an object pointer from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let object_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let object_vreg = self.local_storage_object_vreg(object_vreg, object_reg);

        let init_arg = if let Some((init_vreg, init_reg)) = self.named_args.get("init").copied() {
            let init_vreg = self.materialized_metadata_aggregate_vreg(init_reg, init_vreg)?;
            let (init_ptr_vreg, _) =
                self.materialize_map_value_probe_pointer(Some(init_reg), init_vreg, "map-get")?;
            self.record_named_map_value_schema_from_reg(&map_ref, Some(init_reg), "map-get")?;
            MirValue::VReg(init_ptr_vreg)
        } else {
            MirValue::Const(0)
        };
        let default_flags = if self.named_args.contains_key("init") {
            1
        } else {
            0
        };
        let flags = self
            .optional_nonnegative_named_u64_arg("map-get", "flags")?
            .unwrap_or(default_flags);

        let map_vreg = self.emit_typed_map_fd_load(map_ref.name.clone(), map_ref.kind);
        let value_ty = self.local_storage_map_value_hint(&map_ref);
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        );

        self.emit(MirInst::CallHelper {
            dst: result_vreg,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(map_vreg),
                MirValue::VReg(object_vreg),
                init_arg,
                MirValue::Const(flags as i64),
            ],
        });

        let result_pointee = if matches!(value_ty, MirType::Unknown) {
            MirType::U8
        } else {
            value_ty
        };
        let result_ty = MirType::Ptr {
            pointee: Box::new(result_pointee.clone()),
            address_space: AddressSpace::Map,
        };
        self.vreg_type_hints.insert(result_vreg, result_ty.clone());

        self.reset_call_result_metadata(src_dst);
        if !matches!(result_pointee, MirType::U8) {
            let semantics = self.named_map_value_semantics(&map_ref).cloned();
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = Some(result_ty);
            if let Some(semantics) = semantics {
                meta.annotated_semantics = Some(semantics);
            }
        }
        Ok(())
    }

    fn lower_local_storage_map_delete(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_ref: MapRef,
    ) -> Result<(), CompileError> {
        let helper = Self::local_storage_delete_helper_for_kind(map_ref.kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "map-delete does not support local-storage map kind {:?}",
                map_ref.kind
            ))
        })?;
        let object_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-delete local-storage requires an object pointer from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let object_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let object_vreg = self.local_storage_object_vreg(object_vreg, object_reg);

        let map_vreg = self.emit_typed_map_fd_load(map_ref.name, map_ref.kind);
        self.emit(MirInst::CallHelper {
            dst: dst_vreg,
            helper: helper as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(object_vreg)],
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_queue_stack_map_take(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        context: &str,
        helper: BpfHelper,
    ) -> Result<(), CompileError> {
        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} does not accept flags"
            )));
        }
        if self.pipeline_input.is_some() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} does not accept pipeline input"
            )));
        }
        self.require_only_named_args(context, &["kind"])?;

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} requires a literal map name as the first positional argument"
            ))
        })?;
        if self.positional_args.len() > 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} only accepts a map name positional argument"
            )));
        }

        let map_name = self.literal_string_arg(map_reg, context)?;
        self.validate_generic_map_name(&map_name, context)?;
        let map_kind = self.required_queue_stack_map_kind_arg(context)?;
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let stored_ty = self
            .named_map_value_type(&map_ref)
            .cloned()
            .filter(|ty| !matches!(ty, MirType::Unknown))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} requires known value layout for '{}'; establish it with a prior typed map-push or pinned schema",
                    map_ref.name
                ))
            })?;
        let stored_semantics = self.named_map_value_semantics(&map_ref).cloned();

        let map_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: map_ref,
        });
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::Unknown),
                val_ty: Box::new(stored_ty.clone()),
            },
        );

        let out_slot = self.func.alloc_stack_slot(
            align_to_eight(stored_ty.size().max(1)),
            stored_ty.align().max(1),
            StackSlotKind::Local,
        );
        self.record_stack_slot_type(out_slot, stored_ty.clone());

        let out_ptr_ty = MirType::Ptr {
            pointee: Box::new(stored_ty.clone()),
            address_space: AddressSpace::Stack,
        };
        let out_ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: out_ptr_vreg,
            src: MirValue::StackSlot(out_slot),
        });
        self.vreg_type_hints
            .insert(out_ptr_vreg, out_ptr_ty.clone());

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(out_ptr_vreg)],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);

        let has_value_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_value_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(has_value_vreg, MirType::Bool);

        let success_block = self.func.alloc_block();
        let empty_block = self.func.alloc_block();
        let continue_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_value_vreg,
            if_true: success_block,
            if_false: empty_block,
        });

        self.current_block = success_block;
        if matches!(stored_ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(out_slot),
            });
        } else {
            self.emit(MirInst::LoadSlot {
                dst: dst_vreg,
                slot: out_slot,
                offset: 0,
                ty: stored_ty.clone(),
            });
        }
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = empty_block;
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = continue_block;
        self.reset_call_result_metadata(src_dst);
        if matches!(stored_ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.vreg_type_hints.insert(dst_vreg, out_ptr_ty.clone());
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = Some(out_ptr_ty);
            if let Some(semantics) = stored_semantics {
                meta.annotated_semantics = Some(semantics);
            }
        } else {
            self.vreg_type_hints.insert(dst_vreg, stored_ty);
        }

        Ok(())
    }

    fn lower_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains does not accept flags".into(),
            ));
        }
        self.require_only_named_args(CONTEXT, &["kind"])?;

        match self.map_contains_kind_arg(CONTEXT)? {
            MapKind::BloomFilter => {
                self.lower_bloom_filter_map_contains(src_dst, dst_vreg, src_dst_had_value)
            }
            MapKind::CgroupArray => {
                self.lower_cgroup_array_map_contains(src_dst, dst_vreg, src_dst_had_value)
            }
            map_kind if map_kind.supports_generic_map_op(MapOpKind::Lookup) => {
                self.lower_generic_map_contains(src_dst, dst_vreg, src_dst_had_value, map_kind)
            }
            map_kind if map_kind.is_local_storage() => self.lower_local_storage_map_contains(
                src_dst,
                dst_vreg,
                src_dst_had_value,
                map_kind,
            ),
            other => Err(CompileError::UnsupportedInstruction(format!(
                "{CONTEXT} does not support map kind {:?}",
                other
            ))),
        }
    }

    fn lower_bloom_filter_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains does not accept flags".into(),
            ));
        }
        self.require_only_named_args(CONTEXT, &["kind"])?;

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        let map_kind = self.required_bloom_filter_map_kind_arg(CONTEXT)?;
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let value_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains requires a probe value from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let value_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let stored_value_vreg = if let Some(value_reg) = value_reg {
            self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
        } else {
            value_vreg
        };
        self.record_named_map_value_schema_from_reg(&map_ref, value_reg, CONTEXT)?;

        let (value_ptr_vreg, value_ty) =
            self.materialize_map_value_probe_pointer(value_reg, stored_value_vreg, CONTEXT)?;

        let map_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: map_ref,
        });
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::Unknown),
                val_ty: Box::new(value_ty),
            },
        );

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: BpfHelper::MapPeekElem as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(value_ptr_vreg)],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);

        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_generic_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_kind: MapKind,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        self.validate_generic_map_lookup_kind(map_kind, &map_name)?;

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
                    "map-contains requires a key from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let lookup_vreg = self.func.alloc_vreg();

        self.emit(MirInst::MapLookup {
            dst: lookup_vreg,
            map: map_ref.clone(),
            key: key_vreg,
        });
        let stored_ty = self.named_map_value_type(&map_ref).cloned();
        self.vreg_type_hints.insert(
            lookup_vreg,
            MirType::Ptr {
                pointee: Box::new(stored_ty.unwrap_or(MirType::U8)),
                address_space: AddressSpace::Map,
            },
        );
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_local_storage_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_kind: MapKind,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;

        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let lookup_vreg = self.func.alloc_vreg();
        self.lower_local_storage_map_get(
            src_dst,
            dst_vreg,
            lookup_vreg,
            src_dst_had_value,
            map_ref,
        )?;
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_cgroup_array_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        if self.positional_args.len() > 2 {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains --kind cgroup-array accepts at most a map name and cgroup index"
                    .into(),
            ));
        }

        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        let map_kind = self.map_contains_kind_arg(CONTEXT)?;
        if map_kind != MapKind::CgroupArray {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{CONTEXT} requires --kind cgroup-array for cgroup membership probes"
            )));
        }

        if self
            .positional_args
            .get(1)
            .is_some_and(|(_, reg)| self.is_context_reg(*reg))
        {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains --kind cgroup-array requires a scalar cgroup index, got context"
                    .into(),
            ));
        }
        let pipeline_index = match (self.pipeline_input, self.pipeline_input_reg) {
            (Some(vreg), Some(reg)) if !self.is_context_reg(reg) => Some(vreg),
            (Some(vreg), None) => Some(vreg),
            _ => None,
        };
        let src_dst_index = if src_dst_had_value && !self.is_context_reg(src_dst) {
            Some(dst_vreg)
        } else {
            None
        };
        let index_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(pipeline_index)
            .or(src_dst_index)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains --kind cgroup-array requires a cgroup index from pipeline input or a second positional argument"
                        .into(),
                )
            })?;

        let helper = self
            .probe_ctx
            .map_or(BpfHelper::CurrentTaskUnderCgroup, |ctx| {
                ctx.program_type().cgroup_array_membership_helper()
            });
        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper)) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let map_vreg = self.emit_typed_map_fd_load(map_name, MapKind::CgroupArray);
        let mut args = Vec::new();
        if matches!(helper, BpfHelper::SkbUnderCgroup) {
            let ctx_vreg = self.materialize_context_pointer_arg();
            args.push(MirValue::VReg(ctx_vreg));
        }
        args.push(MirValue::VReg(map_vreg));
        args.push(MirValue::VReg(index_vreg));

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args,
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(1),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn materialize_map_value_probe_pointer(
        &mut self,
        value_reg: Option<RegId>,
        value_vreg: VReg,
        context: &str,
    ) -> Result<(VReg, MirType), CompileError> {
        let value_ty = value_reg
            .and_then(|reg| self.get_metadata(reg))
            .and_then(|meta| {
                meta.field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(meta))
            })
            .or_else(|| self.vreg_type_hints.get(&value_vreg).cloned())
            .unwrap_or(MirType::U64);

        match value_ty {
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => Ok((value_vreg, pointee.as_ref().clone())),
            MirType::Ptr { address_space, .. } => Err(CompileError::UnsupportedInstruction(
                format!("{context} value pointer must be stack/map backed, got {address_space:?}"),
            )),
            value_ty @ (MirType::Array { .. } | MirType::Struct { .. }) => {
                let Some(value_reg) = value_reg else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} aggregate values must come from a typed stack/map-backed value"
                    )));
                };
                let ptr_vreg = self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?;
                Ok((ptr_vreg, self.stored_generic_map_value_type(&value_ty)))
            }
            value_ty
                if matches!(
                    value_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                        | MirType::Unknown
                ) =>
            {
                let slot = self.func.alloc_stack_slot(
                    align_to_eight(value_ty.size().max(1)),
                    value_ty.align().max(1),
                    StackSlotKind::Local,
                );
                self.record_stack_slot_type(slot, value_ty.clone());
                self.emit(MirInst::StoreSlot {
                    slot,
                    offset: 0,
                    val: MirValue::VReg(value_vreg),
                    ty: value_ty.clone(),
                });
                let ptr_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: ptr_vreg,
                    src: MirValue::StackSlot(slot),
                });
                self.vreg_type_hints.insert(
                    ptr_vreg,
                    MirType::Ptr {
                        pointee: Box::new(value_ty.clone()),
                        address_space: AddressSpace::Stack,
                    },
                );
                Ok((ptr_vreg, value_ty))
            }
            other => Err(CompileError::UnsupportedInstruction(format!(
                "{context} value must be scalar or stack/map-backed aggregate, got {other:?}"
            ))),
        }
    }

    fn materialize_helper_map_fd_arg(
        &mut self,
        helper: BpfHelper,
        arg_idx: usize,
        arg_reg: RegId,
    ) -> Result<(MirValue, MapRef, VReg), CompileError> {
        let map_name = match self.literal_string_arg(arg_reg, "helper-call") {
            Ok(name) => name,
            Err(_) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "helper-call arg{} for '{}' must be a literal map name",
                    arg_idx,
                    helper.name()
                )));
            }
        };
        let map_kind = if let Some(kind) = helper.helper_map_arg_kind(arg_idx) {
            kind
        } else {
            match helper.helper_explicit_map_kind_family(arg_idx) {
                Some(HelperExplicitMapKindFamily::QueueStack) => {
                    self.required_queue_stack_map_kind_arg("helper-call")?
                }
                Some(HelperExplicitMapKindFamily::QueueStackBloom) => {
                    self.required_queue_stack_bloom_map_kind_arg("helper-call")?
                }
                Some(HelperExplicitMapKindFamily::RedirectMap) => {
                    self.required_redirect_map_kind_arg("helper-call")?
                }
                Some(HelperExplicitMapKindFamily::PerCpuLookupMap) => {
                    self.required_per_cpu_lookup_map_kind_arg("helper-call")?
                }
                None => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "internal error: helper '{}' arg{} is not a map operand",
                        helper.name(),
                        arg_idx
                    )));
                }
            }
        };
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let map_vreg = self.emit_typed_map_fd_load(map_ref.name.clone(), map_ref.kind);
        Ok((MirValue::VReg(map_vreg), map_ref, map_vreg))
    }

    fn emit_typed_map_fd_load(&mut self, map_name: String, map_kind: MapKind) -> VReg {
        let map_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: MapRef {
                name: map_name,
                kind: map_kind,
            },
        });
        if matches!(map_kind, MapKind::SockMap) {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::U32),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::CgroupArray | MapKind::PerfEventArray | MapKind::ProgArray
        ) || map_kind.is_array_index_map()
        {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::U32),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::Hash
                | MapKind::LpmTrie
                | MapKind::LruHash
                | MapKind::PerCpuHash
                | MapKind::LruPerCpuHash
        ) {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::Unknown),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if map_kind.is_redirect_map() {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if map_kind.is_keyless_map() {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::Unknown),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::SkStorage
                | MapKind::InodeStorage
                | MapKind::TaskStorage
                | MapKind::CgrpStorage
        ) {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        }
        map_vreg
    }

    fn storage_helper_init_arg_idx(helper: BpfHelper) -> Option<usize> {
        match helper {
            BpfHelper::SkStorageGet
            | BpfHelper::TaskStorageGet
            | BpfHelper::InodeStorageGet
            | BpfHelper::CgrpStorageGet => Some(2),
            _ => None,
        }
    }

    fn storage_helper_init_value_type_from_reg(&self, value_reg: RegId) -> Option<MirType> {
        let value_ty = self.get_metadata(value_reg).and_then(|meta| {
            meta.field_type
                .clone()
                .or_else(|| Self::metadata_record_layout(meta))
        })?;
        match value_ty {
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => Some(pointee.as_ref().clone()),
            MirType::Array { .. } | MirType::Struct { .. } => Some(value_ty),
            _ => None,
        }
    }

    fn record_storage_helper_value_schema(
        &mut self,
        helper: BpfHelper,
        dst_vreg: VReg,
        helper_map_args: &[(usize, MapRef, VReg)],
        helper_arg_regs: &[(usize, RegId)],
    ) -> Result<(), CompileError> {
        let Some(init_arg_idx) = Self::storage_helper_init_arg_idx(helper) else {
            return Ok(());
        };
        let Some((_, map_ref, map_vreg)) = helper_map_args.iter().find(|(idx, _, _)| *idx == 0)
        else {
            return Ok(());
        };
        let Some((_, init_reg)) = helper_arg_regs.iter().find(|(idx, _)| *idx == init_arg_idx)
        else {
            return Ok(());
        };
        let Some(value_ty) = self.storage_helper_init_value_type_from_reg(*init_reg) else {
            return Ok(());
        };

        if self.externally_seeded_map_value_types.contains(map_ref)
            && let Some(existing) = self.named_map_value_type(map_ref)
            && existing != &value_ty
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "storage helper init value type for '{}' conflicts with pinned map schema",
                map_ref.name
            )));
        }

        self.register_named_map_value_type(map_ref, &value_ty);
        self.vreg_type_hints.insert(
            *map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        );
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(value_ty),
                address_space: AddressSpace::Map,
            },
        );
        Ok(())
    }
}
