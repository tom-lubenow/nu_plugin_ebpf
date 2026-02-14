use super::*;

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
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            apply_copy_inst(*dst, src, slot_sizes, state);
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
            apply_call_helper_inst(*dst, *helper, args, types, slot_sizes, state, errors);
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            apply_call_kfunc_inst(*dst, kfunc, args, types, state, errors);
        }
        MirInst::CallSubfn { dst, args, .. } => {
            apply_call_subfn_inst(*dst, args, types, state, errors);
        }
        MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. } => {
            apply_typed_dst_inst(*dst, types, state);
        }
        MirInst::Phi { dst, args } => {
            apply_phi_inst(*dst, args, types, state);
        }
        MirInst::MapLookup { dst, map, key } => {
            apply_map_lookup_inst(*dst, map, *key, types, state, errors);
        }
        MirInst::ListNew { dst, buffer, .. } => {
            apply_list_new_inst(*dst, *buffer, slot_sizes, state);
        }
        MirInst::ListLen { dst, list } => {
            apply_list_len_inst(*dst, *list, types, state, errors);
        }
        MirInst::ListGet { dst, list, .. } => {
            apply_list_get_inst(*dst, *list, types, state, errors);
        }
        MirInst::LoadCtxField { dst, field, slot } => {
            apply_load_ctx_field_inst(*dst, field, *slot, types, slot_sizes, state);
        }
        MirInst::ReadStr {
            ptr, user_space, ..
        } => {
            apply_read_str_inst(*ptr, *user_space, state, errors);
        }
        MirInst::EmitEvent { data, size } => {
            apply_emit_event_inst(*data, *size, state, errors);
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
        MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { list, .. } => {
            apply_list_push_inst(*list, state, errors);
        }
        MirInst::StringAppend { dst_len, .. } | MirInst::IntToString { dst_len, .. } => {
            apply_string_len_write_inst(*dst_len, state, errors);
        }
        MirInst::RecordStore { val, ty, .. } => {
            apply_record_store_inst(val, ty, state, errors);
        }
    }
}
