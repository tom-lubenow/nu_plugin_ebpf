use std::collections::{HashMap, VecDeque};

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{
    BinOpKind, BlockId, MirFunction, MirInst, MirType, MirValue, StackSlotId, StackSlotKind, VReg,
};

mod rewrite;
#[cfg(test)]
mod tests;

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
