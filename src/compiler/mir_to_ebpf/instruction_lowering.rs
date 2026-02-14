use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Compile a single LIR instruction
    pub(super) fn compile_instruction(&mut self, inst: &LirInst) -> Result<(), CompileError> {
        match inst {
            LirInst::Copy { dst, src } => {
                self.compile_copy(*dst, src)?;
            }

            LirInst::ParallelMove { moves } => {
                self.compile_parallel_move(moves)?;
            }

            LirInst::Load {
                dst,
                ptr,
                offset,
                ty,
            } => {
                self.compile_load_inst(*dst, *ptr, *offset, ty)?;
            }

            LirInst::Store {
                ptr,
                offset,
                val,
                ty,
            } => {
                self.compile_store_inst(*ptr, *offset, val, ty)?;
            }

            LirInst::LoadSlot {
                dst,
                slot,
                offset,
                ty,
            } => {
                self.compile_load_slot_inst(*dst, *slot, *offset, ty)?;
            }

            LirInst::StoreSlot {
                slot,
                offset,
                val,
                ty,
            } => {
                self.compile_store_slot_inst(*slot, *offset, val, ty)?;
            }

            LirInst::BinOp { dst, op, lhs, rhs } => {
                self.compile_binop(*dst, *op, lhs, rhs)?;
            }

            LirInst::UnaryOp { dst, op, src } => {
                self.compile_unary(*dst, *op, src)?;
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
                self.compile_jump(*target);
            }

            LirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                self.compile_branch(*cond, *if_true, *if_false)?;
            }

            LirInst::Return { val } => {
                self.compile_return(val)?;
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
                self.compile_loop_header(*counter, *limit, *body, *exit)?;
            }

            LirInst::LoopBack {
                counter,
                step,
                header,
            } => {
                self.compile_loop_back(*counter, *step, *header)?;
            }

            LirInst::TailCall { prog_map, index } => {
                self.compile_tail_call_inst(prog_map, index)?;
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
