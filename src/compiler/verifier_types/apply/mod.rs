use super::*;
use crate::compiler::mir::SubfunctionId;
use crate::compiler::{ProbeContext, ProgramTypeInfo};

mod access;
mod calls;
mod core;
mod flow;
mod maps;

use access::*;
use calls::*;
use core::*;
use flow::pointer_arith_result;
use maps::*;

pub(super) fn check_uses_initialized(
    inst: &MirInst,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    flow::check_uses_initialized(inst, state, errors);
}

pub(super) fn apply_inst(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionReturnSummary>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            apply_copy_inst(*dst, src, types, slot_sizes, state);
        }
        MirInst::Load {
            dst, ptr, offset, ..
        } => {
            apply_load_inst(*dst, *ptr, *offset, types, state, errors);
        }
        MirInst::Store {
            ptr, offset, ty, ..
        } => {
            apply_store_inst(*ptr, *offset, ty, state, errors);
        }
        MirInst::LoadSlot {
            dst,
            slot,
            offset,
            ty,
        } => {
            apply_load_slot_inst(*dst, *slot, *offset, ty, types, slot_sizes, state, errors);
        }
        MirInst::StoreSlot {
            slot, offset, ty, ..
        } => {
            apply_store_slot_inst(*slot, *offset, ty, slot_sizes, errors);
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
            apply_binop_inst(*dst, *op, lhs, rhs, slot_sizes, state);
        }
        MirInst::UnaryOp { dst, op, src } => {
            apply_unary_inst(*dst, *op, src, state);
        }
        MirInst::CallHelper { dst, helper, args } => {
            apply_call_helper_inst(
                *dst, *helper, args, types, slot_sizes, program, probe_ctx, state, errors,
            );
        }
        MirInst::LoadMapFd { dst, .. } => {
            apply_typed_dst_inst(*dst, types, state);
        }
        MirInst::LoadSubprogram { dst, .. } => {
            apply_typed_dst_inst(*dst, types, state);
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            apply_call_kfunc_inst(*dst, kfunc, args, types, probe_ctx, state, errors);
        }
        MirInst::CallSubfn { dst, subfn, args } => {
            apply_call_subfn_inst(
                *dst,
                *subfn,
                args,
                types,
                slot_sizes,
                subfn_summaries,
                state,
                errors,
            );
        }
        MirInst::StrCmp { dst, .. } | MirInst::StopTimer { dst, .. } => {
            apply_typed_dst_inst(*dst, types, state);
        }
        MirInst::LoopHeader {
            counter: dst,
            start,
            step,
            limit,
            ..
        } => {
            apply_loop_header_inst(*dst, *start, *step, *limit, types, state);
        }
        MirInst::Phi { dst, args } => {
            apply_phi_inst(*dst, args, types, state);
        }
        MirInst::MapLookup { dst, map, key } => {
            apply_map_lookup_inst(*dst, map, *key, types, state, errors);
        }
        MirInst::LoadGlobal { dst, ty, .. } => {
            apply_global_load_inst(*dst, ty, state);
        }
        MirInst::ListNew { dst, buffer, .. } => {
            apply_list_new_inst(*dst, *buffer, slot_sizes, state);
        }
        MirInst::ListLen { dst, list } => {
            apply_list_len_inst(*dst, *list, types, state, errors);
        }
        MirInst::ListGet { dst, list, idx } => {
            apply_list_get_inst(*dst, *list, idx, types, state, errors);
        }
        MirInst::LoadCtxField { dst, field, slot } => {
            apply_load_ctx_field_inst(
                *dst, field, *slot, probe_ctx, types, slot_sizes, state, errors,
            );
        }
        MirInst::StoreCtxField { target, val, ty } => {
            apply_store_ctx_field_inst(target, val, ty, probe_ctx, state, slot_sizes, errors);
        }
        MirInst::ReadStr {
            ptr, user_space, ..
        } => {
            apply_read_str_inst(*ptr, *user_space, state, errors);
        }
        MirInst::EmitEvent { data, size } => {
            apply_emit_event_inst(*data, *size, types, state, errors);
        }
        MirInst::EmitRecord { fields } => {
            apply_emit_record_inst(fields, types, state, errors);
        }
        MirInst::MapUpdate {
            map,
            key,
            val,
            flags,
        } => {
            apply_map_update_inst(map, *key, *val, *flags, types, state, errors);
        }
        MirInst::MapDelete { map, key } => {
            apply_map_delete_inst(map, *key, types, state, errors);
        }
        MirInst::MapPush { map, val, flags } => {
            apply_map_push_inst(map, *val, *flags, types, state, errors);
        }
        MirInst::Histogram { value } => {
            apply_histogram_inst(*value, state, errors);
        }
        MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { list, item } => {
            apply_list_push_inst(*list, *item, state, errors);
        }
        MirInst::StringAppend {
            dst_len,
            val,
            val_type,
            ..
        } => {
            apply_string_append_inst(*dst_len, val, val_type, state, errors);
        }
        MirInst::IntToString { dst_len, val, .. } => {
            apply_int_to_string_inst(*dst_len, *val, state, errors);
        }
        MirInst::RecordStore { val, ty, .. } => {
            apply_record_store_inst(val, ty, types, state, errors);
        }
    }
}
