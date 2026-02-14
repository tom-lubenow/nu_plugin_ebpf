use super::*;
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
