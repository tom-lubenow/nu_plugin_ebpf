use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Compile a single LIR instruction
    pub(super) fn compile_instruction(&mut self, inst: &LirInst) -> Result<(), CompileError> {
        match inst {
            LirInst::Copy { dst, src } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                            self.instructions
                                .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                        } else {
                            // Large constant - split into two parts
                            let low = *c as i32;
                            let high = (*c >> 32) as i32;
                            self.instructions.push(EbpfInsn::mov64_imm(dst_reg, low));
                            if high != 0 {
                                self.instructions
                                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, high));
                                self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R0, 32));
                                self.instructions
                                    .push(EbpfInsn::or64_reg(dst_reg, EbpfReg::R0));
                            }
                        }
                    }
                    MirValue::StackSlot(slot) => {
                        let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                        self.instructions
                            .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R10));
                        self.instructions
                            .push(EbpfInsn::add64_imm(dst_reg, offset as i32));
                    }
                }
            }

            LirInst::ParallelMove { moves } => {
                #[derive(Clone, Copy, PartialEq, Eq, Hash)]
                enum Loc {
                    Reg(EbpfReg),
                    Stack(i16),
                }

                #[derive(Clone, Copy)]
                struct Move {
                    dst: Loc,
                    src: Loc,
                }

                let mut pending: Vec<Move> = Vec::new();
                let mut reg_sources: HashSet<EbpfReg> = HashSet::new();
                let mut has_stack = false;

                for (dst_vreg, src_vreg) in moves {
                    let dst_loc = if let Some(&phys) = self.vreg_to_phys.get(dst_vreg) {
                        Loc::Reg(phys)
                    } else if let Some(&offset) = self.vreg_spills.get(dst_vreg) {
                        Loc::Stack(offset)
                    } else {
                        Loc::Reg(EbpfReg::R0)
                    };

                    let src_loc = if let Some(&phys) = self.vreg_to_phys.get(src_vreg) {
                        Loc::Reg(phys)
                    } else if let Some(&offset) = self.vreg_spills.get(src_vreg) {
                        Loc::Stack(offset)
                    } else {
                        Loc::Reg(EbpfReg::R0)
                    };

                    if matches!(dst_loc, Loc::Stack(_)) || matches!(src_loc, Loc::Stack(_)) {
                        has_stack = true;
                    }
                    if let Loc::Reg(reg) = src_loc {
                        reg_sources.insert(reg);
                    }

                    if dst_loc != src_loc {
                        pending.push(Move {
                            dst: dst_loc,
                            src: src_loc,
                        });
                    }
                }

                if pending.is_empty() {
                    return Ok(());
                }

                let cycle_temp = self.parallel_move_cycle_offset.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "ParallelMove requires a temp stack slot".into(),
                    )
                })?;
                let scratch_temp = self.parallel_move_scratch_offset;

                let mut scratch_reg = None;
                if has_stack {
                    scratch_reg = pending
                        .iter()
                        .filter_map(|m| match m.dst {
                            Loc::Reg(reg) if !reg_sources.contains(&reg) => Some(reg),
                            _ => None,
                        })
                        .next();

                    if scratch_reg.is_none() {
                        scratch_reg = pending
                            .iter()
                            .find_map(|m| match m.dst {
                                Loc::Reg(reg) => Some(reg),
                                _ => None,
                            })
                            .or_else(|| {
                                pending.iter().find_map(|m| match m.src {
                                    Loc::Reg(reg) => Some(reg),
                                    _ => None,
                                })
                            });

                        if let Some(reg) = scratch_reg {
                            if reg_sources.contains(&reg) {
                                let scratch_temp = scratch_temp.ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(
                                        "ParallelMove requires a scratch temp slot".into(),
                                    )
                                })?;
                                self.instructions.push(EbpfInsn::stxdw(
                                    EbpfReg::R10,
                                    scratch_temp,
                                    reg,
                                ));
                                for mv in &mut pending {
                                    if mv.src == Loc::Reg(reg) {
                                        mv.src = Loc::Stack(scratch_temp);
                                    }
                                }
                                reg_sources.remove(&reg);
                            }
                        } else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ParallelMove with stack slots requires at least one register"
                                    .into(),
                            ));
                        }
                    }
                }

                let temp_loc = Loc::Stack(cycle_temp);

                while !pending.is_empty() {
                    let dsts: HashSet<Loc> = pending.iter().map(|m| m.dst).collect();
                    let ready_idx = pending.iter().position(|m| !dsts.contains(&m.src));

                    if let Some(idx) = ready_idx {
                        let mv = pending.remove(idx);
                        match (mv.dst, mv.src) {
                            (Loc::Reg(dst), Loc::Reg(src)) => {
                                if dst != src {
                                    self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                                }
                            }
                            (Loc::Reg(dst), Loc::Stack(src_off)) => {
                                self.instructions
                                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R10, src_off));
                            }
                            (Loc::Stack(dst_off), Loc::Reg(src)) => {
                                self.instructions
                                    .push(EbpfInsn::stxdw(EbpfReg::R10, dst_off, src));
                            }
                            (Loc::Stack(dst_off), Loc::Stack(src_off)) => {
                                let temp_reg = scratch_reg.ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(
                                        "ParallelMove stack-to-stack needs a scratch register"
                                            .into(),
                                    )
                                })?;
                                self.instructions.push(EbpfInsn::ldxdw(
                                    temp_reg,
                                    EbpfReg::R10,
                                    src_off,
                                ));
                                self.instructions.push(EbpfInsn::stxdw(
                                    EbpfReg::R10,
                                    dst_off,
                                    temp_reg,
                                ));
                            }
                        }
                        continue;
                    }

                    // Cycle: break by saving one source to temp
                    let src = pending[0].src;
                    match (temp_loc, src) {
                        (Loc::Reg(temp), Loc::Reg(src_reg)) => {
                            self.instructions.push(EbpfInsn::mov64_reg(temp, src_reg));
                        }
                        (Loc::Reg(temp), Loc::Stack(off)) => {
                            self.instructions
                                .push(EbpfInsn::ldxdw(temp, EbpfReg::R10, off));
                        }
                        (Loc::Stack(temp_off), Loc::Reg(src_reg)) => {
                            self.instructions.push(EbpfInsn::stxdw(
                                EbpfReg::R10,
                                temp_off,
                                src_reg,
                            ));
                        }
                        (Loc::Stack(temp_off), Loc::Stack(src_off)) => {
                            let temp_reg = scratch_reg.ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "ParallelMove stack source requires a scratch register".into(),
                                )
                            })?;
                            self.instructions.push(EbpfInsn::ldxdw(
                                temp_reg,
                                EbpfReg::R10,
                                src_off,
                            ));
                            self.instructions.push(EbpfInsn::stxdw(
                                EbpfReg::R10,
                                temp_off,
                                temp_reg,
                            ));
                        }
                    }
                    pending[0].src = temp_loc;
                }
            }

            LirInst::Load {
                dst,
                ptr,
                offset,
                ty,
            } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let ptr_reg = self.ensure_reg(*ptr)?;
                let size = ty.size();
                let offset = i16::try_from(*offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "load offset {} out of range",
                        offset
                    ))
                })?;
                self.emit_load(dst_reg, ptr_reg, offset, size)?;
            }

            LirInst::Store {
                ptr,
                offset,
                val,
                ty,
            } => {
                let ptr_reg = self.ensure_reg(*ptr)?;
                let size = ty.size();
                let offset = i16::try_from(*offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "store offset {} out of range",
                        offset
                    ))
                })?;
                let val_reg = self.value_to_reg(val)?;
                self.emit_store(ptr_reg, offset, val_reg, size)?;
            }

            LirInst::LoadSlot {
                dst,
                slot,
                offset,
                ty,
            } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let size = ty.size();
                let offset = self.slot_offset_i16(*slot, *offset)?;
                self.emit_load(dst_reg, EbpfReg::R10, offset, size)?;
            }

            LirInst::StoreSlot {
                slot,
                offset,
                val,
                ty,
            } => {
                let size = ty.size();
                let offset = self.slot_offset_i16(*slot, *offset)?;
                let val_reg = self.value_to_reg(val)?;
                self.emit_store(EbpfReg::R10, offset, val_reg, size)?;
            }

            LirInst::BinOp { dst, op, lhs, rhs } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let lhs_vreg = match lhs {
                    MirValue::VReg(v) => Some(*v),
                    _ => None,
                };
                let rhs_vreg = match rhs {
                    MirValue::VReg(v) => Some(*v),
                    _ => None,
                };
                let mut rhs_reg = match rhs {
                    MirValue::VReg(v) => Some(self.ensure_reg(*v)?),
                    _ => None,
                };

                if let (Some(rhs_reg_value), Some(rhs_vreg)) = (rhs_reg, rhs_vreg) {
                    if rhs_reg_value == dst_reg && lhs_vreg != Some(rhs_vreg) {
                        // Preserve RHS before we clobber dst_reg with LHS.
                        if dst_reg != EbpfReg::R0 {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, rhs_reg_value));
                            rhs_reg = Some(EbpfReg::R0);
                        }
                    }
                }

                // Load LHS into dst
                match lhs {
                    MirValue::VReg(v) => {
                        let src = self.ensure_reg(*v)?;
                        if dst_reg != src {
                            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop LHS".into(),
                        ));
                    }
                }

                // Apply operation with RHS
                match rhs {
                    MirValue::VReg(v) => {
                        let rhs_reg = rhs_reg.unwrap_or(self.ensure_reg(*v)?);
                        self.emit_binop_reg(dst_reg, *op, rhs_reg)?;
                    }
                    MirValue::Const(c) => {
                        self.emit_binop_imm(dst_reg, *op, *c as i32)?;
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop RHS".into(),
                        ));
                    }
                }
            }

            LirInst::UnaryOp { dst, op, src } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in unary op".into(),
                        ));
                    }
                }

                match op {
                    UnaryOpKind::Not => {
                        // Logical not: 0 -> 1, non-zero -> 0
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, 1));
                        self.instructions.push(EbpfInsn::and64_imm(dst_reg, 1));
                    }
                    UnaryOpKind::BitNot => {
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, -1));
                    }
                    UnaryOpKind::Neg => {
                        self.instructions.push(EbpfInsn::neg64(dst_reg));
                    }
                }
            }

            LirInst::LoadCtxField { dst, field, slot } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                self.compile_load_ctx_field(dst_reg, field, *slot)?;
            }

            LirInst::EmitEvent { data, size } => {
                self.needs_ringbuf = true;
                let data_reg = self.ensure_reg(*data)?;
                self.compile_emit_event(data_reg, *size)?;
            }

            LirInst::EmitRecord { fields } => {
                self.needs_ringbuf = true;
                self.compile_emit_record(fields)?;
            }

            LirInst::MapLookup { dst, map, key } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let key_reg = self.ensure_reg(*key)?;
                self.compile_generic_map_lookup(*dst, dst_reg, map, *key, key_reg)?;
            }

            LirInst::MapUpdate {
                map,
                key,
                val,
                flags,
            } => {
                if map.name == COUNTER_MAP_NAME {
                    self.register_counter_map_kind(COUNTER_MAP_NAME, map.kind)?;
                    let key_reg = self.ensure_reg(*key)?;
                    self.compile_counter_map_update(&map.name, key_reg)?;
                } else if map.name == STRING_COUNTER_MAP_NAME {
                    self.register_counter_map_kind(STRING_COUNTER_MAP_NAME, map.kind)?;
                    let key_reg = self.ensure_reg(*key)?;
                    self.compile_counter_map_update(&map.name, key_reg)?;
                } else {
                    let key_reg = self.ensure_reg(*key)?;
                    let val_reg = self.ensure_reg(*val)?;
                    self.compile_generic_map_update(map, *key, key_reg, *val, val_reg, *flags)?;
                }
            }

            LirInst::MapDelete { map, key } => {
                let key_reg = self.ensure_reg(*key)?;
                self.compile_generic_map_delete(map, *key, key_reg)?;
            }

            LirInst::ReadStr {
                dst,
                ptr,
                user_space,
                max_len,
            } => {
                let ptr_reg = self.ensure_reg(*ptr)?;
                let offset = self.slot_offsets.get(dst).copied().unwrap_or(0);
                self.compile_read_str(offset, ptr_reg, *user_space, *max_len)?;
            }

            LirInst::Jump { target } => {
                let jump_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0)); // Placeholder
                self.pending_jumps.push((jump_idx, *target));
            }

            LirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                let cond_reg = self.ensure_reg(*cond)?;

                // JNE (jump if not equal to 0) to if_true
                let jne_idx = self.instructions.len();
                // JNE dst, imm, offset
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
                    cond_reg.as_u8(),
                    0,
                    0, // Placeholder
                    0, // Compare against 0
                ));
                self.pending_jumps.push((jne_idx, *if_true));

                // Fall through or jump to if_false
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *if_false));
            }

            LirInst::Return { val } => {
                match val {
                    Some(MirValue::VReg(v)) => {
                        let src = self.ensure_reg(*v)?;
                        if src != EbpfReg::R0 {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, src));
                        }
                    }
                    Some(MirValue::Const(c)) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                    }
                    Some(MirValue::StackSlot(_)) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in return".into(),
                        ));
                    }
                    None => {
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                    }
                }
                self.restore_callee_saved();
                self.instructions.push(EbpfInsn::exit());
            }

            LirInst::Histogram { value } => {
                self.needs_histogram_map = true;
                let value_reg = self.ensure_reg(*value)?;
                self.compile_histogram(value_reg)?;
            }

            LirInst::StartTimer => {
                self.needs_timestamp_map = true;
                self.compile_start_timer()?;
            }

            LirInst::StopTimer { dst } => {
                self.needs_timestamp_map = true;
                let dst_reg = self.alloc_dst_reg(*dst)?;
                self.compile_stop_timer(dst_reg)?;
            }

            LirInst::LoopHeader {
                counter,
                limit,
                body,
                exit,
            } => {
                // Bounded loop header for eBPF verifier compliance
                // counter < limit ? jump to body : jump to exit
                let counter_reg = self.ensure_reg(*counter)?;

                // Compare counter against limit
                // JSLT: jump if counter < limit (signed)
                let jlt_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
                    counter_reg.as_u8(),
                    0,
                    0, // Placeholder - will be fixed up
                    *limit as i32,
                ));
                self.pending_jumps.push((jlt_idx, *body));

                // Fall through to exit
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *exit));
            }

            LirInst::LoopBack {
                counter,
                step,
                header,
            } => {
                // Increment counter and jump back to header
                let counter_reg = self.ensure_reg(*counter)?;

                // Add step to counter
                self.instructions
                    .push(EbpfInsn::add64_imm(counter_reg, *step as i32));

                // Jump back to loop header
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *header));
            }

            LirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Tail call requires prog array map, got {:?} for '{}'",
                        prog_map.kind, prog_map.name
                    )));
                }
                self.tail_call_maps.insert(prog_map.name.clone());
                self.compile_tail_call(&prog_map.name, index)?;
                // Tail call helper does not return on success. If it does return, tail call failed;
                // terminate the current function with a default 0.
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                self.restore_callee_saved();
                self.instructions.push(EbpfInsn::exit());
            }

            LirInst::CallSubfn { subfn, args, .. } => {
                self.compile_call_subfn(*subfn, args)?;
            }

            LirInst::CallKfunc {
                kfunc,
                btf_id,
                args,
                ..
            } => {
                self.compile_call_kfunc(kfunc, *btf_id, args)?;
            }

            LirInst::CallHelper { helper, args, .. } => {
                self.compile_call_helper(*helper, args)?;
            }

            // Phi nodes should be eliminated before codegen via SSA destruction
            LirInst::Phi { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Phi nodes must be eliminated before codegen (SSA destruction)".into(),
                ));
            }

            LirInst::ListNew { .. }
            | LirInst::ListPush { .. }
            | LirInst::ListLen { .. }
            | LirInst::ListGet { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "List operations must be lowered before codegen".into(),
                ));
            }

            LirInst::StringAppend {
                dst_buffer,
                dst_len,
                val,
                val_type,
            } => {
                self.compile_string_append(*dst_buffer, *dst_len, val, val_type)?;
            }

            LirInst::IntToString {
                dst_buffer,
                dst_len,
                val,
            } => {
                self.compile_int_to_string(*dst_buffer, *dst_len, *val)?;
            }

            // Instructions reserved for future features
            LirInst::StrCmp { .. } | LirInst::RecordStore { .. } => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "MIR instruction {:?} not yet implemented",
                    inst
                )));
            }

            LirInst::Placeholder => {
                // Placeholder should never reach codegen - it's replaced during lowering
                return Err(CompileError::UnsupportedInstruction(
                    "Placeholder terminator reached codegen (block not properly terminated)".into(),
                ));
            }
        }

        Ok(())
    }
}
