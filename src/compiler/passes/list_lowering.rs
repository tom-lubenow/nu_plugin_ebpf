use std::collections::{HashMap, VecDeque};

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{
    BinOpKind, BlockId, MirFunction, MirInst, MirType, MirValue, StackSlotId, StackSlotKind, VReg,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListInfo {
    slot: StackSlotId,
    max_len: usize,
}

pub struct ListLowering;

impl ListLowering {
    fn list_cap_for_slot(func: &MirFunction, slot: StackSlotId) -> Option<usize> {
        func.stack_slots
            .iter()
            .find(|s| s.id == slot)
            .and_then(|s| {
                if matches!(s.kind, StackSlotKind::ListBuffer) {
                    let elems = s.size / 8;
                    Some(elems.saturating_sub(1))
                } else {
                    None
                }
            })
    }

    fn compute_list_info(func: &MirFunction) -> HashMap<VReg, ListInfo> {
        let mut info: HashMap<VReg, ListInfo> = HashMap::new();
        let mut changed = true;
        let max_iters = func.vreg_count.max(1);

        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;

            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    match inst {
                        MirInst::ListNew {
                            dst,
                            buffer,
                            max_len,
                        } => {
                            let cap = Self::list_cap_for_slot(func, *buffer)
                                .map(|slot_cap| (*max_len).min(slot_cap))
                                .unwrap_or(*max_len);
                            let new_info = ListInfo {
                                slot: *buffer,
                                max_len: cap,
                            };
                            let entry = info.entry(*dst).or_insert(new_info);
                            if *entry != new_info {
                                *entry = new_info;
                                changed = true;
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::StackSlot(slot),
                        } => {
                            if let Some(cap) = Self::list_cap_for_slot(func, *slot) {
                                let new_info = ListInfo {
                                    slot: *slot,
                                    max_len: cap,
                                };
                                let entry = info.entry(*dst).or_insert(new_info);
                                if *entry != new_info {
                                    *entry = new_info;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::VReg(src),
                        } => {
                            if let Some(meta) = info.get(src).copied() {
                                let entry = info.entry(*dst).or_insert(meta);
                                if *entry != meta {
                                    *entry = meta;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Phi { dst, args } => {
                            let mut meta: Option<ListInfo> = None;
                            let mut consistent = true;
                            for (_, vreg) in args {
                                match (meta, info.get(vreg).copied()) {
                                    (None, Some(m)) => meta = Some(m),
                                    (Some(existing), Some(m)) if existing == m => {}
                                    _ => {
                                        consistent = false;
                                        break;
                                    }
                                }
                            }
                            if consistent {
                                if let Some(m) = meta {
                                    let entry = info.entry(*dst).or_insert(m);
                                    if *entry != m {
                                        *entry = m;
                                        changed = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        info
    }

    fn split_block_at(func: &mut MirFunction, block_id: BlockId, split_idx: usize) -> BlockId {
        let (old_term, rest) = {
            let block = func.block_mut(block_id);
            let old_term = block.terminator.clone();
            let tail = block.instructions.split_off(split_idx);
            let rest: Vec<MirInst> = tail.into_iter().skip(1).collect();
            block.terminator = MirInst::Placeholder;
            (old_term, rest)
        };

        let cont_id = func.alloc_block();
        {
            let cont_block = func.block_mut(cont_id);
            cont_block.instructions = rest;
            cont_block.terminator = old_term;
        }

        cont_id
    }
}

impl MirPass for ListLowering {
    fn name(&self) -> &str {
        "list_lowering"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let list_info = Self::compute_list_info(func);
        let mut changed = false;
        let mut worklist: VecDeque<BlockId> = func.blocks.iter().map(|b| b.id).collect();

        while let Some(block_id) = worklist.pop_front() {
            let mut idx = 0;
            loop {
                let inst = { func.block(block_id).instructions.get(idx).cloned() };
                let Some(inst) = inst else {
                    break;
                };

                match inst {
                    MirInst::ListNew { dst, buffer, .. } => {
                        let replacement = vec![
                            MirInst::Copy {
                                dst,
                                src: MirValue::StackSlot(buffer),
                            },
                            MirInst::StoreSlot {
                                slot: buffer,
                                offset: 0,
                                val: MirValue::Const(0),
                                ty: MirType::U64,
                            },
                        ];
                        let block = func.block_mut(block_id);
                        block.instructions.splice(idx..=idx, replacement);
                        idx += 2;
                        changed = true;
                    }
                    MirInst::ListLen { dst, list } => {
                        let replacement = vec![MirInst::Load {
                            dst,
                            ptr: list,
                            offset: 0,
                            ty: MirType::U64,
                        }];
                        let block = func.block_mut(block_id);
                        block.instructions.splice(idx..=idx, replacement);
                        idx += 1;
                        changed = true;
                    }
                    MirInst::ListPush { list, item } => {
                        let Some(meta) = list_info.get(&list).copied() else {
                            idx += 1;
                            continue;
                        };

                        if meta.max_len == 0 {
                            func.block_mut(block_id).instructions.remove(idx);
                            changed = true;
                            continue;
                        }

                        let len_vreg = func.alloc_vreg();
                        let cond_vreg = func.alloc_vreg();
                        let base_ptr = func.alloc_vreg();
                        let offset_mul = func.alloc_vreg();
                        let offset_add = func.alloc_vreg();
                        let elem_ptr = func.alloc_vreg();
                        let new_len = func.alloc_vreg();

                        let cont_id = Self::split_block_at(func, block_id, idx);
                        let push_id = func.alloc_block();

                        {
                            let block = func.block_mut(block_id);
                            block.instructions.push(MirInst::LoadSlot {
                                dst: len_vreg,
                                slot: meta.slot,
                                offset: 0,
                                ty: MirType::U64,
                            });
                            block.instructions.push(MirInst::BinOp {
                                dst: cond_vreg,
                                op: BinOpKind::Lt,
                                lhs: MirValue::VReg(len_vreg),
                                rhs: MirValue::Const(meta.max_len as i64),
                            });
                            block.terminator = MirInst::Branch {
                                cond: cond_vreg,
                                if_true: push_id,
                                if_false: cont_id,
                            };
                        }

                        {
                            let block = func.block_mut(push_id);
                            block.instructions.push(MirInst::Copy {
                                dst: base_ptr,
                                src: MirValue::StackSlot(meta.slot),
                            });
                            block.instructions.push(MirInst::BinOp {
                                dst: offset_mul,
                                op: BinOpKind::Mul,
                                lhs: MirValue::VReg(len_vreg),
                                rhs: MirValue::Const(8),
                            });
                            block.instructions.push(MirInst::BinOp {
                                dst: offset_add,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(offset_mul),
                                rhs: MirValue::Const(8),
                            });
                            block.instructions.push(MirInst::BinOp {
                                dst: elem_ptr,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(base_ptr),
                                rhs: MirValue::VReg(offset_add),
                            });
                            block.instructions.push(MirInst::Store {
                                ptr: elem_ptr,
                                offset: 0,
                                val: MirValue::VReg(item),
                                ty: MirType::I64,
                            });
                            block.instructions.push(MirInst::BinOp {
                                dst: new_len,
                                op: BinOpKind::Add,
                                lhs: MirValue::VReg(len_vreg),
                                rhs: MirValue::Const(1),
                            });
                            block.instructions.push(MirInst::StoreSlot {
                                slot: meta.slot,
                                offset: 0,
                                val: MirValue::VReg(new_len),
                                ty: MirType::U64,
                            });
                            block.terminator = MirInst::Jump { target: cont_id };
                        }

                        worklist.push_back(cont_id);
                        changed = true;
                        break;
                    }
                    MirInst::ListGet {
                        dst,
                        list,
                        idx: idx_value,
                    } => {
                        let Some(meta) = list_info.get(&list).copied() else {
                            idx += 1;
                            continue;
                        };

                        if meta.max_len == 0 {
                            func.block_mut(block_id).instructions[idx] = MirInst::Copy {
                                dst,
                                src: MirValue::Const(0),
                            };
                            idx += 1;
                            changed = true;
                            continue;
                        }

                        match idx_value {
                            MirValue::Const(i) => {
                                if i < 0 || i >= meta.max_len as i64 {
                                    func.block_mut(block_id).instructions[idx] = MirInst::Copy {
                                        dst,
                                        src: MirValue::Const(0),
                                    };
                                    idx += 1;
                                    changed = true;
                                    continue;
                                }

                                let len_vreg = func.alloc_vreg();
                                let cond_vreg = func.alloc_vreg();

                                let cont_id = Self::split_block_at(func, block_id, idx);
                                let in_bounds = func.alloc_block();
                                let out_bounds = func.alloc_block();

                                {
                                    let block = func.block_mut(block_id);
                                    block.instructions.push(MirInst::LoadSlot {
                                        dst: len_vreg,
                                        slot: meta.slot,
                                        offset: 0,
                                        ty: MirType::U64,
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: cond_vreg,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::Const(i),
                                        rhs: MirValue::VReg(len_vreg),
                                    });
                                    block.terminator = MirInst::Branch {
                                        cond: cond_vreg,
                                        if_true: in_bounds,
                                        if_false: out_bounds,
                                    };
                                }

                                let offset = i
                                    .checked_mul(8)
                                    .and_then(|v| v.checked_add(8))
                                    .and_then(|v| i32::try_from(v).ok());

                                {
                                    let block = func.block_mut(in_bounds);
                                    if let Some(offset) = offset {
                                        block.instructions.push(MirInst::LoadSlot {
                                            dst,
                                            slot: meta.slot,
                                            offset,
                                            ty: MirType::I64,
                                        });
                                    } else {
                                        block.instructions.push(MirInst::Copy {
                                            dst,
                                            src: MirValue::Const(0),
                                        });
                                    }
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                {
                                    let block = func.block_mut(out_bounds);
                                    block.instructions.push(MirInst::Copy {
                                        dst,
                                        src: MirValue::Const(0),
                                    });
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                worklist.push_back(cont_id);
                                changed = true;
                                break;
                            }
                            MirValue::StackSlot(slot) => {
                                let idx_vreg = func.alloc_vreg();
                                let len_vreg = func.alloc_vreg();
                                let idx_ge_zero = func.alloc_vreg();
                                let idx_lt_len = func.alloc_vreg();
                                let idx_lt_cap = func.alloc_vreg();
                                let cond_tmp = func.alloc_vreg();
                                let cond = func.alloc_vreg();
                                let base_ptr = func.alloc_vreg();
                                let offset_mul = func.alloc_vreg();
                                let offset_add = func.alloc_vreg();
                                let elem_ptr = func.alloc_vreg();

                                let cont_id = Self::split_block_at(func, block_id, idx);
                                let in_bounds = func.alloc_block();
                                let out_bounds = func.alloc_block();

                                {
                                    let block = func.block_mut(block_id);
                                    block.instructions.push(MirInst::LoadSlot {
                                        dst: idx_vreg,
                                        slot,
                                        offset: 0,
                                        ty: MirType::I64,
                                    });
                                    block.instructions.push(MirInst::LoadSlot {
                                        dst: len_vreg,
                                        slot: meta.slot,
                                        offset: 0,
                                        ty: MirType::U64,
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_ge_zero,
                                        op: BinOpKind::Ge,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(0),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_lt_len,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::VReg(len_vreg),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_lt_cap,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(meta.max_len as i64),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: cond_tmp,
                                        op: BinOpKind::And,
                                        lhs: MirValue::VReg(idx_ge_zero),
                                        rhs: MirValue::VReg(idx_lt_len),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: cond,
                                        op: BinOpKind::And,
                                        lhs: MirValue::VReg(cond_tmp),
                                        rhs: MirValue::VReg(idx_lt_cap),
                                    });
                                    block.terminator = MirInst::Branch {
                                        cond,
                                        if_true: in_bounds,
                                        if_false: out_bounds,
                                    };
                                }

                                {
                                    let block = func.block_mut(in_bounds);
                                    block.instructions.push(MirInst::Copy {
                                        dst: base_ptr,
                                        src: MirValue::StackSlot(meta.slot),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: offset_mul,
                                        op: BinOpKind::Mul,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(8),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: offset_add,
                                        op: BinOpKind::Add,
                                        lhs: MirValue::VReg(offset_mul),
                                        rhs: MirValue::Const(8),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: elem_ptr,
                                        op: BinOpKind::Add,
                                        lhs: MirValue::VReg(base_ptr),
                                        rhs: MirValue::VReg(offset_add),
                                    });
                                    block.instructions.push(MirInst::Load {
                                        dst,
                                        ptr: elem_ptr,
                                        offset: 0,
                                        ty: MirType::I64,
                                    });
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                {
                                    let block = func.block_mut(out_bounds);
                                    block.instructions.push(MirInst::Copy {
                                        dst,
                                        src: MirValue::Const(0),
                                    });
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                worklist.push_back(cont_id);
                                changed = true;
                                break;
                            }
                            MirValue::VReg(idx_vreg) => {
                                let len_vreg = func.alloc_vreg();
                                let idx_ge_zero = func.alloc_vreg();
                                let idx_lt_len = func.alloc_vreg();
                                let idx_lt_cap = func.alloc_vreg();
                                let cond_tmp = func.alloc_vreg();
                                let cond = func.alloc_vreg();
                                let base_ptr = func.alloc_vreg();
                                let offset_mul = func.alloc_vreg();
                                let offset_add = func.alloc_vreg();
                                let elem_ptr = func.alloc_vreg();

                                let cont_id = Self::split_block_at(func, block_id, idx);
                                let in_bounds = func.alloc_block();
                                let out_bounds = func.alloc_block();

                                {
                                    let block = func.block_mut(block_id);
                                    block.instructions.push(MirInst::LoadSlot {
                                        dst: len_vreg,
                                        slot: meta.slot,
                                        offset: 0,
                                        ty: MirType::U64,
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_ge_zero,
                                        op: BinOpKind::Ge,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(0),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_lt_len,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::VReg(len_vreg),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: idx_lt_cap,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(meta.max_len as i64),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: cond_tmp,
                                        op: BinOpKind::And,
                                        lhs: MirValue::VReg(idx_ge_zero),
                                        rhs: MirValue::VReg(idx_lt_len),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: cond,
                                        op: BinOpKind::And,
                                        lhs: MirValue::VReg(cond_tmp),
                                        rhs: MirValue::VReg(idx_lt_cap),
                                    });
                                    block.terminator = MirInst::Branch {
                                        cond,
                                        if_true: in_bounds,
                                        if_false: out_bounds,
                                    };
                                }

                                {
                                    let block = func.block_mut(in_bounds);
                                    block.instructions.push(MirInst::Copy {
                                        dst: base_ptr,
                                        src: MirValue::StackSlot(meta.slot),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: offset_mul,
                                        op: BinOpKind::Mul,
                                        lhs: MirValue::VReg(idx_vreg),
                                        rhs: MirValue::Const(8),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: offset_add,
                                        op: BinOpKind::Add,
                                        lhs: MirValue::VReg(offset_mul),
                                        rhs: MirValue::Const(8),
                                    });
                                    block.instructions.push(MirInst::BinOp {
                                        dst: elem_ptr,
                                        op: BinOpKind::Add,
                                        lhs: MirValue::VReg(base_ptr),
                                        rhs: MirValue::VReg(offset_add),
                                    });
                                    block.instructions.push(MirInst::Load {
                                        dst,
                                        ptr: elem_ptr,
                                        offset: 0,
                                        ty: MirType::I64,
                                    });
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                {
                                    let block = func.block_mut(out_bounds);
                                    block.instructions.push(MirInst::Copy {
                                        dst,
                                        src: MirValue::Const(0),
                                    });
                                    block.terminator = MirInst::Jump { target: cont_id };
                                }

                                worklist.push_back(cont_id);
                                changed = true;
                                break;
                            }
                        }
                    }
                    MirInst::EmitEvent { data, size } => {
                        if let Some(meta) = list_info.get(&data).copied() {
                            let tmp_ptr = func.alloc_vreg();
                            let replacement = vec![
                                MirInst::Copy {
                                    dst: tmp_ptr,
                                    src: MirValue::StackSlot(meta.slot),
                                },
                                MirInst::EmitEvent {
                                    data: tmp_ptr,
                                    size,
                                },
                            ];
                            let block = func.block_mut(block_id);
                            block.instructions.splice(idx..=idx, replacement);
                            idx += 2;
                            changed = true;
                        } else {
                            idx += 1;
                        }
                    }
                    _ => idx += 1,
                }
            }
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::cfg::CFG;
    use crate::compiler::mir::{MirFunction, MirInst, MirValue, StackSlotKind};

    fn collect_insts(func: &MirFunction) -> Vec<&MirInst> {
        let mut insts = Vec::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                insts.push(inst);
            }
            insts.push(&block.terminator);
        }
        insts
    }

    #[test]
    fn test_list_push_is_lowered() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
        let list = func.alloc_vreg();
        let item = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::ListNew {
            dst: list,
            buffer: slot,
            max_len: 2,
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: item,
            src: MirValue::Const(7),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::ListPush { list, item });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let cfg = CFG::build(&func);
        let mut func = func;
        let pass = ListLowering;
        assert!(pass.run(&mut func, &cfg));

        let insts = collect_insts(&func);
        assert!(
            !insts.iter().any(|inst| matches!(inst, MirInst::ListPush { .. })),
            "ListPush should be lowered"
        );
        assert!(
            insts.iter().any(|inst| matches!(inst, MirInst::Branch { .. })),
            "ListPush lowering should insert a bounds branch"
        );
        assert!(
            insts.iter().any(|inst| matches!(inst, MirInst::Store { .. })),
            "ListPush lowering should emit stores"
        );
    }

    #[test]
    fn test_list_get_const_is_lowered() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);
        let list = func.alloc_vreg();
        let out = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::ListNew {
            dst: list,
            buffer: slot,
            max_len: 3,
        });
        func.block_mut(entry).instructions.push(MirInst::ListGet {
            dst: out,
            list,
            idx: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let cfg = CFG::build(&func);
        let mut func = func;
        let pass = ListLowering;
        assert!(pass.run(&mut func, &cfg));

        let insts = collect_insts(&func);
        assert!(
            !insts.iter().any(|inst| matches!(inst, MirInst::ListGet { .. })),
            "ListGet should be lowered"
        );
        assert!(
            insts.iter()
                .any(|inst| matches!(inst, MirInst::LoadSlot { offset: 16, .. })),
            "ListGet constant index should load from constant offset"
        );
    }

    #[test]
    fn test_emit_event_list_ptr_is_rematerialized() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);
        let list = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::ListNew {
            dst: list,
            buffer: slot,
            max_len: 3,
        });
        func.block_mut(entry).instructions.push(MirInst::EmitEvent {
            data: list,
            size: 24,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let cfg = CFG::build(&func);
        let mut func = func;
        let pass = ListLowering;
        assert!(pass.run(&mut func, &cfg));

        let insts = collect_insts(&func);
        let mut emit_data = None;
        for inst in &insts {
            if let MirInst::EmitEvent { data, .. } = inst {
                emit_data = Some(*data);
            }
        }
        let Some(data_vreg) = emit_data else {
            panic!("EmitEvent missing after lowering");
        };
        assert_ne!(
            data_vreg, list,
            "EmitEvent should use a rematerialized list pointer"
        );
        assert!(
            insts.iter().any(|inst| matches!(
                inst,
                MirInst::Copy {
                    dst,
                    src: MirValue::StackSlot(s),
                } if *dst == data_vreg && *s == slot
            )),
            "EmitEvent should be preceded by Copy from list stack slot"
        );
    }
}
