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
                self.compile_load_ctx_field_inst(*dst, field, *slot)?;
            }

            LirInst::EmitEvent { data, size } => {
                self.compile_emit_event_inst(*data, *size)?;
            }

            LirInst::EmitRecord { fields } => {
                self.compile_emit_record_inst(fields)?;
            }

            LirInst::MapLookup { dst, map, key } => {
                self.compile_map_lookup_inst(*dst, map, *key)?;
            }

            LirInst::MapUpdate {
                map,
                key,
                val,
                flags,
            } => {
                self.compile_map_update_inst(map, *key, *val, *flags)?;
            }

            LirInst::MapDelete { map, key } => {
                self.compile_map_delete_inst(map, *key)?;
            }

            LirInst::ReadStr {
                dst,
                ptr,
                user_space,
                max_len,
            } => {
                self.compile_read_str_inst(*dst, *ptr, *user_space, *max_len)?;
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
                self.compile_histogram_inst(*value)?;
            }

            LirInst::StartTimer => {
                self.compile_start_timer_inst()?;
            }

            LirInst::StopTimer { dst } => {
                self.compile_stop_timer_inst(*dst)?;
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
                self.compile_string_append_inst(*dst_buffer, *dst_len, val, val_type)?;
            }

            LirInst::IntToString {
                dst_buffer,
                dst_len,
                val,
            } => {
                self.compile_int_to_string_inst(*dst_buffer, *dst_len, *val)?;
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
