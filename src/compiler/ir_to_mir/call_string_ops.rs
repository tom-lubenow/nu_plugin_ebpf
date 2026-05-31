use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_string_length(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "str length does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
        if let Some(len_vreg) = input_meta.as_ref().and_then(|meta| {
            meta.string_len_vreg.or_else(|| match &meta.constant_value {
                Some(nu_protocol::Value::String { val, .. }) => {
                    let const_len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: const_len_vreg,
                        src: MirValue::Const(val.len() as i64),
                    });
                    self.vreg_type_hints.insert(const_len_vreg, MirType::I64);
                    Some(const_len_vreg)
                }
                _ => None,
            })
        }) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(len_vreg),
            });
        } else {
            return Err(CompileError::UnsupportedInstruction(
                "str length requires a tracked string input in eBPF".into(),
            ));
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(super) fn lower_string_starts_with(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with does not accept named flags or arguments in eBPF".into(),
            ));
        }
        let (_, prefix_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with requires a string prefix argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with accepts exactly one prefix argument in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str starts-with requires tracked string input in eBPF".into(),
                )
            })?;
        let Some(input_slot) = input_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with requires tracked string input in eBPF".into(),
            ));
        };
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with could not determine input string capacity in eBPF".into(),
            )
        })?;

        let prefix = self.literal_string_arg(prefix_reg, "str starts-with")?;
        if prefix.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with does not support NUL bytes in the prefix in eBPF".into(),
            ));
        }
        let prefix_meta = self.get_metadata(prefix_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with requires a tracked string prefix in eBPF".into(),
            )
        })?;
        let Some(prefix_slot) = prefix_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with requires a tracked string prefix in eBPF".into(),
            ));
        };
        let prefix_len = prefix.len();

        if prefix_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if prefix_len > input_slot_size.saturating_sub(1) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            self.emit(MirInst::StrCmp {
                dst: result_vreg,
                lhs: input_slot,
                lhs_offset: 0,
                rhs: prefix_slot,
                rhs_offset: 0,
                len: prefix_len,
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    pub(super) fn lower_string_ends_with(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with does not accept named flags or arguments in eBPF".into(),
            ));
        }
        let (_, suffix_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a string suffix argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with accepts exactly one suffix argument in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str ends-with requires tracked string input in eBPF".into(),
                )
            })?;
        let Some(input_slot) = input_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with requires tracked string input in eBPF".into(),
            ));
        };
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with could not determine input string capacity in eBPF".into(),
            )
        })?;
        let input_len = Self::exact_string_len(&input_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a compile-time known input string length in eBPF".into(),
            )
        })?;

        let suffix = self.literal_string_arg(suffix_reg, "str ends-with")?;
        if suffix.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with does not support NUL bytes in the suffix in eBPF".into(),
            ));
        }
        let suffix_meta = self.get_metadata(suffix_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a tracked string suffix in eBPF".into(),
            )
        })?;
        let Some(suffix_slot) = suffix_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with requires a tracked string suffix in eBPF".into(),
            ));
        };
        let suffix_len = suffix.len();

        if suffix_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if suffix_len > input_len || input_len > input_slot_size.saturating_sub(1) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            self.emit(MirInst::StrCmp {
                dst: result_vreg,
                lhs: input_slot,
                lhs_offset: input_len - suffix_len,
                rhs: suffix_slot,
                rhs_offset: 0,
                len: suffix_len,
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    pub(super) fn lower_string_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str contains does not accept named flags or arguments in eBPF".into(),
            ));
        }
        let (_, needle_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str contains requires a string substring argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str contains accepts exactly one substring argument in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str contains requires tracked string input in eBPF".into(),
                )
            })?;
        let Some(input_slot) = input_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str contains requires tracked string input in eBPF".into(),
            ));
        };
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str contains could not determine input string capacity in eBPF".into(),
            )
        })?;
        let input_len = Self::exact_string_len(&input_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str contains requires a compile-time known input string length in eBPF".into(),
            )
        })?;

        let needle = self.literal_string_arg(needle_reg, "str contains")?;
        if needle.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "str contains does not support NUL bytes in the substring in eBPF".into(),
            ));
        }
        let needle_meta = self.get_metadata(needle_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str contains requires a tracked string substring in eBPF".into(),
            )
        })?;
        let Some(needle_slot) = needle_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str contains requires a tracked string substring in eBPF".into(),
            ));
        };
        let needle_len = needle.len();

        if needle_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if needle_len > input_len || input_len > input_slot_size.saturating_sub(1) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            let found_block = self.func.alloc_block();
            let not_found_block = self.func.alloc_block();
            let continuation_block = self.func.alloc_block();
            let last_offset = input_len - needle_len;

            for offset in 0..=last_offset {
                let next_block = if offset == last_offset {
                    not_found_block
                } else {
                    self.func.alloc_block()
                };
                let candidate_vreg = self.func.alloc_vreg();
                self.emit(MirInst::StrCmp {
                    dst: candidate_vreg,
                    lhs: input_slot,
                    lhs_offset: offset,
                    rhs: needle_slot,
                    rhs_offset: 0,
                    len: needle_len,
                });
                self.vreg_type_hints.insert(candidate_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: candidate_vreg,
                    if_true: found_block,
                    if_false: next_block,
                });
                self.current_block = next_block;
            }

            self.current_block = found_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = not_found_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = continuation_block;
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    fn exact_string_len(meta: &RegMetadata) -> Option<usize> {
        match &meta.constant_value {
            Some(nu_protocol::Value::String { val, .. }) => Some(val.len()),
            Some(nu_protocol::Value::Glob { val, .. }) => Some(val.len()),
            Some(nu_protocol::Value::Binary { val, .. }) => Some(val.len()),
            _ => meta.literal_string.as_ref().map(|val| val.len()),
        }
    }
}
