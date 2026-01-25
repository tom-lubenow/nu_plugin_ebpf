//! Low-Level IR (LIR)
//!
//! LIR is the post-SSA, register-aware form used for allocation and codegen.
//! It makes calling conventions and register clobbers explicit and provides
//! parallel move groups for correct argument/return shuffles.

use std::collections::HashMap;
use std::fmt;

use super::instruction::EbpfReg;
use super::mir::{
    BinOpKind, BlockId, CtxField, MapRef, MirType, MirValue, RecordFieldDef, StackSlot,
    StackSlotId, StackSlotKind, StringAppendType, SubfunctionId, UnaryOpKind, VReg,
};

/// A complete LIR program
#[derive(Debug, Clone)]
pub struct LirProgram {
    pub main: LirFunction,
    pub subfunctions: Vec<LirFunction>,
}

impl LirProgram {
    pub fn new(main: LirFunction) -> Self {
        Self {
            main,
            subfunctions: Vec::new(),
        }
    }
}

/// LIR basic block
#[derive(Debug, Clone)]
pub struct LirBlock {
    pub id: BlockId,
    pub instructions: Vec<LirInst>,
    pub terminator: LirInst,
}

impl LirBlock {
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            terminator: LirInst::Placeholder,
        }
    }

    pub fn successors(&self) -> Vec<BlockId> {
        match &self.terminator {
            LirInst::Jump { target } => vec![*target],
            LirInst::Branch {
                if_true, if_false, ..
            } => vec![*if_true, *if_false],
            LirInst::LoopHeader { body, exit, .. } => vec![*body, *exit],
            LirInst::LoopBack { header, .. } => vec![*header],
            LirInst::Return { .. } | LirInst::TailCall { .. } => vec![],
            LirInst::Placeholder => vec![],
            _ => panic!("Invalid terminator: {:?}", self.terminator),
        }
    }
}

/// A complete LIR function
#[derive(Debug, Clone)]
pub struct LirFunction {
    pub name: Option<String>,
    pub blocks: Vec<LirBlock>,
    pub entry: BlockId,
    pub vreg_count: u32,
    pub stack_slots: Vec<StackSlot>,
    pub maps_used: Vec<MapRef>,
    pub param_count: usize,
    /// Precolored vregs with fixed physical registers
    pub precolored: HashMap<VReg, EbpfReg>,
}

impl LirFunction {
    pub fn new() -> Self {
        Self {
            name: None,
            blocks: Vec::new(),
            entry: BlockId(0),
            vreg_count: 0,
            stack_slots: Vec::new(),
            maps_used: Vec::new(),
            param_count: 0,
            precolored: HashMap::new(),
        }
    }

    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new()
        }
    }

    pub fn alloc_vreg(&mut self) -> VReg {
        let vreg = VReg(self.vreg_count);
        self.vreg_count += 1;
        vreg
    }

    pub fn alloc_stack_slot(
        &mut self,
        size: usize,
        align: usize,
        kind: StackSlotKind,
    ) -> StackSlotId {
        let id = StackSlotId(self.stack_slots.len() as u32);
        self.stack_slots.push(StackSlot {
            id,
            size,
            align,
            kind,
            offset: None,
        });
        id
    }

    pub fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(LirBlock::new(id));
        id
    }

    pub fn block_mut(&mut self, id: BlockId) -> &mut LirBlock {
        self.blocks
            .iter_mut()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    pub fn block(&self, id: BlockId) -> &LirBlock {
        self.blocks
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    pub fn has_block(&self, id: BlockId) -> bool {
        self.blocks.iter().any(|b| b.id == id)
    }
}

/// LIR instruction set
#[derive(Debug, Clone)]
pub enum LirInst {
    // Data movement
    Copy { dst: VReg, src: MirValue },
    Load {
        dst: VReg,
        ptr: VReg,
        offset: i32,
        ty: MirType,
    },
    Store {
        ptr: VReg,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },
    LoadSlot {
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        ty: MirType,
    },
    StoreSlot {
        slot: StackSlotId,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    // Arithmetic
    BinOp {
        dst: VReg,
        op: BinOpKind,
        lhs: MirValue,
        rhs: MirValue,
    },
    UnaryOp {
        dst: VReg,
        op: UnaryOpKind,
        src: MirValue,
    },

    // Parallel moves (for ABI shuffles)
    ParallelMove {
        moves: Vec<(VReg, VReg)>, // (dst, src)
    },

    // BPF helpers / calls
    CallHelper {
        dst: VReg,
        helper: u32,
        args: Vec<MirValue>,
    },
    CallSubfn {
        subfn: SubfunctionId,
        args: Vec<VReg>, // precolored R1-R5 vregs
        ret: VReg,       // precolored R0 vreg
    },
    TailCall { prog_map: MapRef, index: MirValue },

    MapLookup { dst: VReg, map: MapRef, key: VReg },
    MapUpdate {
        map: MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    },
    MapDelete { map: MapRef, key: VReg },

    Histogram { value: VReg },
    StartTimer,
    StopTimer { dst: VReg },
    EmitEvent { data: VReg, size: usize },
    EmitRecord { fields: Vec<RecordFieldDef> },

    LoadCtxField {
        dst: VReg,
        field: CtxField,
        slot: Option<StackSlotId>,
    },
    ReadStr {
        dst: StackSlotId,
        ptr: VReg,
        user_space: bool,
        max_len: usize,
    },
    StrCmp {
        dst: VReg,
        lhs: StackSlotId,
        rhs: StackSlotId,
        len: usize,
    },
    StringAppend {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: MirValue,
        val_type: StringAppendType,
    },
    IntToString {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    },

    RecordStore {
        buffer: StackSlotId,
        field_offset: usize,
        val: MirValue,
        ty: MirType,
    },

    ListNew {
        dst: VReg,
        buffer: StackSlotId,
        max_len: usize,
    },
    ListPush { list: VReg, item: VReg },
    ListLen { dst: VReg, list: VReg },
    ListGet { dst: VReg, list: VReg, idx: MirValue },

    // Control flow
    Jump { target: BlockId },
    Branch {
        cond: VReg,
        if_true: BlockId,
        if_false: BlockId,
    },
    Return { val: Option<MirValue> },

    // Loop headers/backedges (lowered during codegen)
    LoopHeader {
        counter: VReg,
        limit: i64,
        body: BlockId,
        exit: BlockId,
    },
    LoopBack {
        counter: VReg,
        step: i64,
        header: BlockId,
    },

    // SSA remnants / placeholders
    Phi { dst: VReg, args: Vec<(BlockId, VReg)> },
    Placeholder,
}

impl LirInst {
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            LirInst::Jump { .. }
                | LirInst::Branch { .. }
                | LirInst::Return { .. }
                | LirInst::TailCall { .. }
        )
    }

    pub fn defs(&self) -> Vec<VReg> {
        match self {
            LirInst::Copy { dst, .. }
            | LirInst::Load { dst, .. }
            | LirInst::LoadSlot { dst, .. }
            | LirInst::BinOp { dst, .. }
            | LirInst::UnaryOp { dst, .. }
            | LirInst::CallHelper { dst, .. }
            | LirInst::CallSubfn { ret: dst, .. }
            | LirInst::MapLookup { dst, .. }
            | LirInst::LoadCtxField { dst, .. }
            | LirInst::StrCmp { dst, .. }
            | LirInst::StopTimer { dst, .. }
            | LirInst::LoopHeader { counter: dst, .. }
            | LirInst::ListNew { dst, .. }
            | LirInst::ListLen { dst, .. }
            | LirInst::ListGet { dst, .. }
            | LirInst::Phi { dst, .. } => vec![*dst],
            LirInst::ParallelMove { moves } => moves.iter().map(|(dst, _)| *dst).collect(),
            _ => Vec::new(),
        }
    }

    pub fn uses(&self) -> Vec<VReg> {
        let mut uses = Vec::new();
        let add_value = |uses: &mut Vec<VReg>, v: &MirValue| {
            if let MirValue::VReg(r) = v {
                uses.push(*r);
            }
        };

        match self {
            LirInst::Copy { src, .. } => add_value(&mut uses, src),
            LirInst::Load { ptr, .. } => uses.push(*ptr),
            LirInst::Store { ptr, val, .. } => {
                uses.push(*ptr);
                add_value(&mut uses, val);
            }
            LirInst::LoadSlot { .. } => {}
            LirInst::StoreSlot { val, .. } => add_value(&mut uses, val),
            LirInst::BinOp { lhs, rhs, .. } => {
                add_value(&mut uses, lhs);
                add_value(&mut uses, rhs);
            }
            LirInst::UnaryOp { src, .. } => add_value(&mut uses, src),
            LirInst::ParallelMove { moves } => {
                for (_, src) in moves {
                    uses.push(*src);
                }
            }
            LirInst::CallHelper { args, .. } => {
                for arg in args {
                    add_value(&mut uses, arg);
                }
            }
            LirInst::CallSubfn { args, .. } => {
                uses.extend(args.iter().copied());
            }
            LirInst::MapLookup { key, .. } => uses.push(*key),
            LirInst::MapUpdate { key, val, .. } => {
                uses.push(*key);
                uses.push(*val);
            }
            LirInst::MapDelete { key, .. } => uses.push(*key),
            LirInst::Histogram { value, .. } => uses.push(*value),
            LirInst::StartTimer => {}
            LirInst::StopTimer { .. } => {}
            LirInst::EmitEvent { data, .. } => uses.push(*data),
            LirInst::EmitRecord { fields } => {
                for field in fields {
                    uses.push(field.value);
                }
            }
            LirInst::LoadCtxField { .. } => {}
            LirInst::ReadStr { ptr, .. } => uses.push(*ptr),
            LirInst::StrCmp { .. } => {}
            LirInst::RecordStore { val, .. } => add_value(&mut uses, val),
            LirInst::ListNew { .. } => {}
            LirInst::ListPush { list, item } => {
                uses.push(*list);
                uses.push(*item);
            }
            LirInst::ListLen { list, .. } => uses.push(*list),
            LirInst::ListGet { list, idx, .. } => {
                uses.push(*list);
                add_value(&mut uses, idx);
            }
            LirInst::Jump { .. } => {}
            LirInst::Branch { cond, .. } => uses.push(*cond),
            LirInst::Return { val } => {
                if let Some(v) = val {
                    add_value(&mut uses, v);
                }
            }
            LirInst::TailCall { index, .. } => add_value(&mut uses, index),
            LirInst::LoopHeader { counter, .. } => uses.push(*counter),
            LirInst::LoopBack { counter, .. } => uses.push(*counter),
            LirInst::Placeholder => {}
            LirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    uses.push(*vreg);
                }
            }
            LirInst::StringAppend { dst_len, val, .. } => {
                uses.push(*dst_len);
                add_value(&mut uses, val);
            }
            LirInst::IntToString { dst_len, val, .. } => {
                uses.push(*dst_len);
                uses.push(*val);
            }
        }
        uses
    }

    pub fn move_pairs(&self) -> Vec<(VReg, VReg)> {
        match self {
            LirInst::Copy {
                dst,
                src: MirValue::VReg(src),
            } => vec![(*dst, *src)],
            LirInst::ParallelMove { moves } => moves.clone(),
            _ => Vec::new(),
        }
    }

    pub fn call_clobbers(&self) -> &'static [EbpfReg] {
        if matches!(
            self,
            LirInst::CallHelper { .. }
                | LirInst::CallSubfn { .. }
                | LirInst::TailCall { .. }
                | LirInst::MapLookup { .. }
                | LirInst::MapUpdate { .. }
                | LirInst::MapDelete { .. }
                | LirInst::EmitEvent { .. }
                | LirInst::EmitRecord { .. }
                | LirInst::ReadStr { .. }
                | LirInst::Histogram { .. }
                | LirInst::StartTimer
                | LirInst::StopTimer { .. }
                | LirInst::LoadCtxField { .. }
        ) {
            &CALLER_SAVED
        } else {
            &[]
        }
    }

    pub fn scratch_clobbers(&self) -> &'static [EbpfReg] {
        match self {
            LirInst::ListPush { .. } => &SCRATCH_LIST_PUSH,
            LirInst::ListGet {
                idx: MirValue::VReg(_),
                ..
            } => &SCRATCH_LIST_GET,
            LirInst::StringAppend { val_type, .. } => match val_type {
                StringAppendType::Integer => &SCRATCH_STRING_APPEND_INT,
                StringAppendType::Literal { .. } | StringAppendType::StringSlot { .. } => {
                    &SCRATCH_STRING_APPEND
                }
            },
            LirInst::IntToString { .. } => &SCRATCH_INT_TO_STRING,
            LirInst::Histogram { .. } => &SCRATCH_HISTOGRAM,
            _ => &[],
        }
    }
}

const CALLER_SAVED: [EbpfReg; 5] = [
    EbpfReg::R1,
    EbpfReg::R2,
    EbpfReg::R3,
    EbpfReg::R4,
    EbpfReg::R5,
];
const SCRATCH_LIST_PUSH: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];
const SCRATCH_LIST_GET: [EbpfReg; 1] = [EbpfReg::R1];
const SCRATCH_STRING_APPEND: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];
const SCRATCH_STRING_APPEND_INT: [EbpfReg; 5] = [
    EbpfReg::R1,
    EbpfReg::R2,
    EbpfReg::R3,
    EbpfReg::R4,
    EbpfReg::R5,
];
const SCRATCH_INT_TO_STRING: [EbpfReg; 3] = [EbpfReg::R1, EbpfReg::R3, EbpfReg::R4];
const SCRATCH_HISTOGRAM: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];

impl fmt::Display for LirInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
