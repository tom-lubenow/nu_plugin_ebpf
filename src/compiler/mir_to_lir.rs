//! MIR -> LIR lowering
//!
//! This pass introduces explicit parallel moves for ABI argument setup and
//! marks precolored registers for fixed physical assignments.

use std::collections::HashMap;

use crate::compiler::CompileError;

use super::instruction::{EbpfReg, KfuncSignature, unknown_kfunc_signature_message};
use super::lir::{LirBlock, LirFunction, LirInst, LirProgram};
use super::mir::{MirFunction, MirInst, MirProgram, MirValue, VReg};

const ABI_REGS: [EbpfReg; 6] = [
    EbpfReg::R0,
    EbpfReg::R1,
    EbpfReg::R2,
    EbpfReg::R3,
    EbpfReg::R4,
    EbpfReg::R5,
];

struct PhysRegs {
    map: HashMap<EbpfReg, VReg>,
}

impl PhysRegs {
    fn new(func: &mut LirFunction) -> Self {
        let mut map = HashMap::new();
        for reg in ABI_REGS {
            let vreg = VReg(func.vreg_count);
            func.vreg_count += 1;
            func.precolored.insert(vreg, reg);
            map.insert(reg, vreg);
        }
        Self { map }
    }

    fn get(&self, reg: EbpfReg) -> VReg {
        *self
            .map
            .get(&reg)
            .unwrap_or_else(|| panic!("Missing physical vreg for {:?}", reg))
    }
}

pub fn lower_mir_to_lir(program: &MirProgram) -> LirProgram {
    lower_mir_to_lir_checked(program)
        .expect("MIR-to-LIR lowering failed; use lower_mir_to_lir_checked to handle errors")
}

pub fn lower_mir_to_lir_checked(program: &MirProgram) -> Result<LirProgram, CompileError> {
    let main = lower_function(&program.main)?;
    let mut lir = LirProgram::new(main);
    for subfn in &program.subfunctions {
        lir.subfunctions.push(lower_function(subfn)?);
    }
    Ok(lir)
}

fn lower_function(mir: &MirFunction) -> Result<LirFunction, CompileError> {
    if mir.param_count > 5 {
        return Err(CompileError::UnsupportedInstruction(format!(
            "BPF subfunctions support at most 5 arguments, got {}",
            mir.param_count
        )));
    }

    let mut func = LirFunction::new();
    func.name = mir.name.clone();
    func.entry = mir.entry;
    func.vreg_count = mir.vreg_count;
    func.stack_slots = mir.stack_slots.clone();
    func.maps_used = mir.maps_used.clone();
    func.param_count = mir.param_count;

    // Allocate precolored ABI registers (R0-R5)
    let phys = PhysRegs::new(&mut func);

    // Pre-create blocks with matching IDs
    for block in &mir.blocks {
        let id = block.id;
        if func.blocks.iter().any(|b| b.id == id) {
            continue;
        }
        func.blocks.push(LirBlock::new(id));
    }

    for block in &mir.blocks {
        let mut out = Vec::new();
        for inst in &block.instructions {
            lower_inst(inst, &phys, &mut out, &mut func)?;
        }
        let mut term_out = Vec::new();
        lower_inst(&block.terminator, &phys, &mut term_out, &mut func)?;
        let terminator = if term_out.len() == 1 {
            term_out.remove(0)
        } else {
            // Terminators should lower to a single instruction
            LirInst::Placeholder
        };

        let lir_block = func.block_mut(block.id);
        lir_block.instructions = out;
        lir_block.terminator = terminator;
    }

    Ok(func)
}

fn lower_inst(
    inst: &MirInst,
    phys: &PhysRegs,
    out: &mut Vec<LirInst>,
    func: &mut LirFunction,
) -> Result<(), CompileError> {
    match inst {
        MirInst::Copy { dst, src } => out.push(LirInst::Copy {
            dst: *dst,
            src: src.clone(),
        }),
        MirInst::Load {
            dst,
            ptr,
            offset,
            ty,
        } => {
            out.push(LirInst::Load {
                dst: *dst,
                ptr: *ptr,
                offset: *offset,
                ty: ty.clone(),
            });
        }
        MirInst::Store {
            ptr,
            offset,
            val,
            ty,
        } => {
            out.push(LirInst::Store {
                ptr: *ptr,
                offset: *offset,
                val: val.clone(),
                ty: ty.clone(),
            });
        }
        MirInst::LoadSlot {
            dst,
            slot,
            offset,
            ty,
        } => {
            out.push(LirInst::LoadSlot {
                dst: *dst,
                slot: *slot,
                offset: *offset,
                ty: ty.clone(),
            });
        }
        MirInst::StoreSlot {
            slot,
            offset,
            val,
            ty,
        } => {
            out.push(LirInst::StoreSlot {
                slot: *slot,
                offset: *offset,
                val: val.clone(),
                ty: ty.clone(),
            });
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
            out.push(LirInst::BinOp {
                dst: *dst,
                op: *op,
                lhs: lhs.clone(),
                rhs: rhs.clone(),
            });
        }
        MirInst::UnaryOp { dst, op, src } => {
            out.push(LirInst::UnaryOp {
                dst: *dst,
                op: *op,
                src: src.clone(),
            });
        }
        MirInst::CallHelper { dst, helper, args } => {
            if args.len() > 5 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "BPF helpers support at most 5 arguments, got {}",
                    args.len()
                )));
            }
            let mut moves = Vec::new();
            let mut arg_regs = Vec::new();
            for (idx, arg) in args.iter().enumerate() {
                let reg = match idx {
                    0 => EbpfReg::R1,
                    1 => EbpfReg::R2,
                    2 => EbpfReg::R3,
                    3 => EbpfReg::R4,
                    4 => EbpfReg::R5,
                    _ => unreachable!("helper args already bounded to at most 5"),
                };
                let dst_reg = phys.get(reg);
                let src_vreg = match arg {
                    MirValue::VReg(vreg) => *vreg,
                    _ => {
                        let tmp = func.alloc_vreg();
                        out.push(LirInst::Copy {
                            dst: tmp,
                            src: arg.clone(),
                        });
                        tmp
                    }
                };
                moves.push((dst_reg, src_vreg));
                arg_regs.push(dst_reg);
            }
            if !moves.is_empty() {
                out.push(LirInst::ParallelMove { moves });
            }
            let ret_reg = phys.get(EbpfReg::R0);
            out.push(LirInst::CallHelper {
                helper: *helper,
                args: arg_regs,
                ret: ret_reg,
            });
            out.push(LirInst::Copy {
                dst: *dst,
                src: MirValue::VReg(ret_reg),
            });
        }
        MirInst::CallKfunc {
            dst,
            kfunc,
            btf_id,
            args,
        } => {
            let sig = KfuncSignature::for_name_or_kernel_btf(kfunc).ok_or_else(|| {
                CompileError::UnsupportedInstruction(unknown_kfunc_signature_message(kfunc))
            })?;
            if args.len() < sig.min_args || args.len() > sig.max_args {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "kfunc '{}' expects {}..={} arguments, got {}",
                    kfunc,
                    sig.min_args,
                    sig.max_args,
                    args.len()
                )));
            }
            if args.len() > 5 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "kfunc '{}' exceeds BPF call argument limit: {}",
                    kfunc,
                    args.len()
                )));
            }

            let mut moves = Vec::new();
            let mut arg_regs = Vec::new();
            for (idx, arg) in args.iter().enumerate() {
                let reg = match idx {
                    0 => EbpfReg::R1,
                    1 => EbpfReg::R2,
                    2 => EbpfReg::R3,
                    3 => EbpfReg::R4,
                    4 => EbpfReg::R5,
                    _ => unreachable!("kfunc args already bounded to at most 5"),
                };
                let dst_reg = phys.get(reg);
                moves.push((dst_reg, *arg));
                arg_regs.push(dst_reg);
            }
            if !moves.is_empty() {
                out.push(LirInst::ParallelMove { moves });
            }
            let ret_reg = phys.get(EbpfReg::R0);
            out.push(LirInst::CallKfunc {
                kfunc: kfunc.clone(),
                btf_id: *btf_id,
                args: arg_regs,
                ret: ret_reg,
            });
            out.push(LirInst::Copy {
                dst: *dst,
                src: MirValue::VReg(ret_reg),
            });
        }
        MirInst::CallSubfn { dst, subfn, args } => {
            if args.len() > 5 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "BPF subfunctions support at most 5 arguments, got {}",
                    args.len()
                )));
            }
            let mut moves = Vec::new();
            let mut arg_regs = Vec::new();
            for (idx, arg) in args.iter().enumerate() {
                let reg = match idx {
                    0 => EbpfReg::R1,
                    1 => EbpfReg::R2,
                    2 => EbpfReg::R3,
                    3 => EbpfReg::R4,
                    4 => EbpfReg::R5,
                    _ => unreachable!("subfunction args already bounded to at most 5"),
                };
                let dst_reg = phys.get(reg);
                moves.push((dst_reg, *arg));
                arg_regs.push(dst_reg);
            }
            if !moves.is_empty() {
                out.push(LirInst::ParallelMove { moves });
            }
            let ret_reg = phys.get(EbpfReg::R0);
            out.push(LirInst::CallSubfn {
                subfn: *subfn,
                args: arg_regs,
                ret: ret_reg,
            });
            out.push(LirInst::Copy {
                dst: *dst,
                src: MirValue::VReg(ret_reg),
            });
        }
        MirInst::TailCall { prog_map, index } => {
            out.push(LirInst::TailCall {
                prog_map: prog_map.clone(),
                index: index.clone(),
            });
        }
        MirInst::MapLookup { dst, map, key } => {
            out.push(LirInst::MapLookup {
                dst: *dst,
                map: map.clone(),
                key: *key,
            });
        }
        MirInst::MapUpdate {
            map,
            key,
            val,
            flags,
        } => {
            out.push(LirInst::MapUpdate {
                map: map.clone(),
                key: *key,
                val: *val,
                flags: *flags,
            });
        }
        MirInst::MapDelete { map, key } => {
            out.push(LirInst::MapDelete {
                map: map.clone(),
                key: *key,
            });
        }
        MirInst::Histogram { value } => out.push(LirInst::Histogram { value: *value }),
        MirInst::StartTimer => out.push(LirInst::StartTimer),
        MirInst::StopTimer { dst } => out.push(LirInst::StopTimer { dst: *dst }),
        MirInst::EmitEvent { data, size } => {
            out.push(LirInst::EmitEvent {
                data: *data,
                size: *size,
            });
        }
        MirInst::EmitRecord { fields } => {
            out.push(LirInst::EmitRecord {
                fields: fields.clone(),
            });
        }
        MirInst::LoadCtxField { dst, field, slot } => {
            out.push(LirInst::LoadCtxField {
                dst: *dst,
                field: field.clone(),
                slot: *slot,
            });
        }
        MirInst::ReadStr {
            dst,
            ptr,
            user_space,
            max_len,
        } => {
            out.push(LirInst::ReadStr {
                dst: *dst,
                ptr: *ptr,
                user_space: *user_space,
                max_len: *max_len,
            });
        }
        MirInst::StrCmp { dst, lhs, rhs, len } => {
            out.push(LirInst::StrCmp {
                dst: *dst,
                lhs: *lhs,
                rhs: *rhs,
                len: *len,
            });
        }
        MirInst::StringAppend {
            dst_buffer,
            dst_len,
            val,
            val_type,
        } => {
            out.push(LirInst::StringAppend {
                dst_buffer: *dst_buffer,
                dst_len: *dst_len,
                val: val.clone(),
                val_type: val_type.clone(),
            });
        }
        MirInst::IntToString {
            dst_buffer,
            dst_len,
            val,
        } => {
            out.push(LirInst::IntToString {
                dst_buffer: *dst_buffer,
                dst_len: *dst_len,
                val: *val,
            });
        }
        MirInst::RecordStore {
            buffer,
            field_offset,
            val,
            ty,
        } => {
            out.push(LirInst::RecordStore {
                buffer: *buffer,
                field_offset: *field_offset,
                val: val.clone(),
                ty: ty.clone(),
            });
        }
        MirInst::ListNew {
            dst,
            buffer,
            max_len,
        } => {
            out.push(LirInst::ListNew {
                dst: *dst,
                buffer: *buffer,
                max_len: *max_len,
            });
        }
        MirInst::ListPush { list, item } => {
            out.push(LirInst::ListPush {
                list: *list,
                item: *item,
            });
        }
        MirInst::ListLen { dst, list } => out.push(LirInst::ListLen {
            dst: *dst,
            list: *list,
        }),
        MirInst::ListGet { dst, list, idx } => {
            out.push(LirInst::ListGet {
                dst: *dst,
                list: *list,
                idx: idx.clone(),
            });
        }
        MirInst::Jump { target } => out.push(LirInst::Jump { target: *target }),
        MirInst::Branch {
            cond,
            if_true,
            if_false,
        } => {
            out.push(LirInst::Branch {
                cond: *cond,
                if_true: *if_true,
                if_false: *if_false,
            });
        }
        MirInst::Return { val } => out.push(LirInst::Return { val: val.clone() }),
        MirInst::LoopHeader {
            counter,
            limit,
            body,
            exit,
        } => {
            out.push(LirInst::LoopHeader {
                counter: *counter,
                limit: *limit,
                body: *body,
                exit: *exit,
            });
        }
        MirInst::LoopBack {
            counter,
            step,
            header,
        } => {
            out.push(LirInst::LoopBack {
                counter: *counter,
                step: *step,
                header: *header,
            });
        }
        MirInst::Phi { dst, args } => out.push(LirInst::Phi {
            dst: *dst,
            args: args.clone(),
        }),
        MirInst::Placeholder => out.push(LirInst::Placeholder),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
