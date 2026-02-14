//! MIR to eBPF bytecode lowering
//!
//! This module converts MIR (Mid-Level IR) to eBPF bytecode.
//! It handles:
//! - Type inference and validation
//! - Graph coloring register allocation (Chaitin-Briggs)
//! - Stack layout and spilling
//! - Control flow (basic block linearization, jump resolution)
//! - BPF helper calls and map operations
//!
//! ## Pipeline
//!
//! 1. Build CFG from MIR
//! 2. Compute liveness information
//! 3. Run type inference (validates types, catches errors early)
//! 4. Graph coloring register allocation with coalescing
//! 5. Layout stack slots (including spill slots)
//! 6. Compile blocks in reverse post-order
//! 7. Fix up jumps and emit bytecode

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::compiler::CompileError;
use crate::compiler::cfg::CFG;
use crate::compiler::elf::{
    BpfFieldType, BpfMapDef, EbpfMap, EventSchema, MapRelocation, ProbeContext, SchemaField,
    SubfunctionSymbol,
};
use crate::compiler::graph_coloring::{
    ColoringResult, GraphColoringAllocator, compute_loop_depths,
};
use crate::compiler::hindley_milner::HMType;
use crate::compiler::instruction::{
    BpfHelper, EbpfInsn, EbpfReg, HelperSignature, KfuncSignature, opcode,
};
use crate::compiler::lir::{LirBlock, LirFunction, LirInst, LirProgram};
use crate::compiler::mir::{
    BinOpKind, BlockId, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME, MapKind,
    MirProgram, MirType, MirTypeHints, MirValue, RINGBUF_MAP_NAME, RecordFieldDef,
    STRING_COUNTER_MAP_NAME, StackSlot, StackSlotId, StackSlotKind, StringAppendType,
    SubfunctionId, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, UnaryOpKind, VReg,
};
use crate::compiler::mir_to_lir::lower_mir_to_lir_checked;
use crate::compiler::passes::{ListLowering, MirPass, SsaDestruction};
use crate::compiler::type_infer::{TypeInference, infer_subfunction_schemes};
use crate::compiler::vcc;
use crate::compiler::verifier_types;
use crate::kernel_btf::KernelBtf;

mod aggregations;
mod calls;
mod control_flow;
mod helper_calls;
mod instruction_lowering;
mod maps;
mod ops;
mod parallel_moves;
mod string_lowering;
mod value_ops;

/// Result of MIR to eBPF compilation
pub struct MirCompileResult {
    /// The compiled bytecode
    pub bytecode: Vec<u8>,
    /// Size of the main function in bytes
    pub main_size: usize,
    /// Maps needed by the program
    pub maps: Vec<EbpfMap>,
    /// Relocations for map references
    pub relocations: Vec<MapRelocation>,
    /// Subfunction symbols for BPF-to-BPF relocation
    pub subfunction_symbols: Vec<SubfunctionSymbol>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
}

#[derive(Debug, Clone, Default)]
struct ProgramVregTypes {
    main: HashMap<VReg, MirType>,
    subfunctions: Vec<HashMap<VReg, MirType>>,
}

#[derive(Debug, Clone, Copy)]
struct MapLayoutSpec {
    kind: MapKind,
    key_size: u32,
    value_size: u32,
    value_size_defaulted: bool,
}

#[derive(Debug, Clone, Copy)]
enum MapOperandLayout {
    Scalar { size: usize },
    Pointer { size: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RematExpr {
    Const(i64),
    StackAddr { slot: StackSlotId, addend: i32 },
}

/// MIR to eBPF compiler
pub struct MirToEbpfCompiler<'a> {
    /// LIR program to compile
    lir: &'a LirProgram,
    /// Probe context for field offsets
    probe_ctx: Option<&'a ProbeContext>,
    /// eBPF instructions
    instructions: Vec<EbpfInsn>,
    /// Virtual register to physical register mapping (from graph coloring)
    vreg_to_phys: HashMap<VReg, EbpfReg>,
    /// Virtual registers spilled to stack (from graph coloring)
    vreg_spills: HashMap<VReg, i16>,
    /// Spilled vregs that can be rematerialized at use sites
    vreg_remat: HashMap<VReg, RematExpr>,
    /// Stack slot offsets
    slot_offsets: HashMap<StackSlotId, i16>,
    /// Temporary stack slot for parallel move cycle breaking
    parallel_move_cycle_offset: Option<i16>,
    /// Temporary stack slot for saving a scratch register during parallel moves
    parallel_move_scratch_offset: Option<i16>,
    /// Current stack offset (grows downward from R10)
    stack_offset: i16,
    /// Block start offsets (instruction index)
    block_offsets: HashMap<BlockId, usize>,
    /// Pending jump fixups (instruction index -> target block)
    pending_jumps: Vec<(usize, BlockId)>,
    /// Map relocations
    relocations: Vec<MapRelocation>,
    /// Needs ring buffer map
    needs_ringbuf: bool,
    /// Counter map kind (numeric keys)
    counter_map_kind: Option<MapKind>,
    /// String counter map kind
    string_counter_map_kind: Option<MapKind>,
    /// Needs histogram map
    needs_histogram_map: bool,
    /// Needs timestamp map
    needs_timestamp_map: bool,
    /// Needs kernel stack trace map
    needs_kstack_map: bool,
    /// Needs user stack trace map
    needs_ustack_map: bool,
    /// Names of program array maps used for tail calls
    tail_call_maps: BTreeSet<String>,
    /// Generic maps inferred from map operations
    generic_map_specs: BTreeMap<String, MapLayoutSpec>,
    /// MIR vreg types for the current function being compiled
    current_types: HashMap<VReg, MirType>,
    /// MIR vreg types for all functions in this program
    program_types: ProgramVregTypes,
    /// Event schema for structured output
    event_schema: Option<EventSchema>,
    /// Available physical registers for allocation
    available_regs: Vec<EbpfReg>,
    /// Subfunction calls (instruction index, subfunction ID)
    subfn_calls: Vec<(usize, SubfunctionId)>,
    /// Subfunction start offsets (instruction index where each subfunction begins)
    subfn_offsets: HashMap<SubfunctionId, usize>,
    /// Callee-saved register spill offsets for current function
    callee_saved_offsets: HashMap<EbpfReg, i16>,
}

impl<'a> MirToEbpfCompiler<'a> {
    /// Create a new compiler
    pub fn new(lir: &'a LirProgram, probe_ctx: Option<&'a ProbeContext>) -> Self {
        Self::new_with_types(lir, probe_ctx, ProgramVregTypes::default())
    }

    fn new_with_types(
        lir: &'a LirProgram,
        probe_ctx: Option<&'a ProbeContext>,
        program_types: ProgramVregTypes,
    ) -> Self {
        Self {
            lir,
            probe_ctx,
            instructions: Vec::new(),
            vreg_to_phys: HashMap::new(),
            vreg_spills: HashMap::new(),
            vreg_remat: HashMap::new(),
            slot_offsets: HashMap::new(),
            parallel_move_cycle_offset: None,
            parallel_move_scratch_offset: None,
            stack_offset: 0,
            block_offsets: HashMap::new(),
            pending_jumps: Vec::new(),
            relocations: Vec::new(),
            needs_ringbuf: false,
            counter_map_kind: None,
            string_counter_map_kind: None,
            needs_histogram_map: false,
            needs_timestamp_map: false,
            needs_kstack_map: false,
            needs_ustack_map: false,
            tail_call_maps: BTreeSet::new(),
            generic_map_specs: BTreeMap::new(),
            current_types: HashMap::new(),
            program_types,
            event_schema: None,
            // Allow use of caller-saved regs; R9 remains reserved for the context pointer.
            available_regs: vec![
                EbpfReg::R1,
                EbpfReg::R2,
                EbpfReg::R3,
                EbpfReg::R4,
                EbpfReg::R5,
                EbpfReg::R6,
                EbpfReg::R7,
                EbpfReg::R8,
            ],
            subfn_calls: Vec::new(),
            subfn_offsets: HashMap::new(),
            callee_saved_offsets: HashMap::new(),
        }
    }

    /// Compile the MIR program to eBPF
    pub fn compile(mut self) -> Result<MirCompileResult, CompileError> {
        // Compile the main function
        self.current_types = self.program_types.main.clone();
        self.prepare_function_state(
            &self.lir.main,
            self.available_regs.clone(),
            self.lir.main.precolored.clone(),
        )?;
        let main_func = self.lir.main.clone();
        self.compile_function(&main_func)?;

        // Fix up jumps in main function
        self.fixup_jumps()?;
        let main_insns = self.instructions.len();

        // Compile all subfunctions (BPF-to-BPF calls)
        // Each subfunction is appended after the main function
        self.compile_subfunctions()?;

        // Fix up subfunction call offsets
        self.fixup_subfn_calls()?;

        let subfunction_symbols = if self.subfn_offsets.is_empty() {
            Vec::new()
        } else {
            let mut offsets: Vec<(SubfunctionId, usize)> = self
                .subfn_offsets
                .iter()
                .map(|(id, &offset)| (*id, offset))
                .collect();
            offsets.sort_by_key(|(_, offset)| *offset);

            let total = self.instructions.len();
            let mut symbols = Vec::new();
            for (idx, (subfn_id, offset)) in offsets.iter().enumerate() {
                let end = offsets
                    .get(idx + 1)
                    .map(|(_, next_offset)| *next_offset)
                    .unwrap_or(total);
                let size = end.saturating_sub(*offset);
                let name = self
                    .lir
                    .subfunctions
                    .get(subfn_id.0 as usize)
                    .and_then(|func| func.name.clone())
                    .unwrap_or_else(|| format!("subfn_{}", subfn_id.0));
                symbols.push(SubfunctionSymbol {
                    name,
                    offset: offset * 8,
                    size: size * 8,
                });
            }
            symbols
        };

        // Build bytecode from instructions
        let mut bytecode = Vec::with_capacity(self.instructions.len() * 8);
        for insn in &self.instructions {
            bytecode.extend_from_slice(&insn.encode());
        }
        let main_size = main_insns * 8;

        // Build maps
        let mut maps = Vec::new();
        if self.needs_ringbuf {
            maps.push(EbpfMap {
                name: RINGBUF_MAP_NAME.to_string(),
                def: BpfMapDef::ring_buffer(256 * 1024),
            });
        }
        if let Some(kind) = self.counter_map_kind {
            maps.push(EbpfMap {
                name: COUNTER_MAP_NAME.to_string(),
                def: self.build_counter_map_def(COUNTER_MAP_NAME, kind)?,
            });
        }
        if let Some(kind) = self.string_counter_map_kind {
            maps.push(EbpfMap {
                name: STRING_COUNTER_MAP_NAME.to_string(),
                def: self.build_counter_map_def(STRING_COUNTER_MAP_NAME, kind)?,
            });
        }
        if self.needs_histogram_map {
            maps.push(EbpfMap {
                name: HISTOGRAM_MAP_NAME.to_string(),
                def: BpfMapDef::histogram_hash(),
            });
        }
        if self.needs_timestamp_map {
            maps.push(EbpfMap {
                name: TIMESTAMP_MAP_NAME.to_string(),
                def: BpfMapDef::timestamp_hash(),
            });
        }
        if self.needs_kstack_map {
            maps.push(EbpfMap {
                name: KSTACK_MAP_NAME.to_string(),
                def: BpfMapDef::stack_trace_map(),
            });
        }
        if self.needs_ustack_map {
            maps.push(EbpfMap {
                name: USTACK_MAP_NAME.to_string(),
                def: BpfMapDef::stack_trace_map(),
            });
        }
        for map_name in &self.tail_call_maps {
            if maps.iter().any(|m| m.name == *map_name) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "tail call map '{}' conflicts with an existing map name",
                    map_name
                )));
            }
            maps.push(EbpfMap {
                name: map_name.clone(),
                def: BpfMapDef::prog_array(1024),
            });
        }
        for (map_name, spec) in &self.generic_map_specs {
            if maps.iter().any(|m| m.name == *map_name) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map '{}' conflicts with an existing map name",
                    map_name
                )));
            }
            maps.push(EbpfMap {
                name: map_name.clone(),
                def: self.build_generic_map_def(*spec)?,
            });
        }

        Ok(MirCompileResult {
            bytecode,
            main_size,
            maps,
            relocations: self.relocations,
            subfunction_symbols,
            event_schema: self.event_schema,
        })
    }

    /// Run graph coloring register allocation for a function
    fn allocate_registers_for_function(
        &self,
        func: &LirFunction,
        available_regs: Vec<EbpfReg>,
        precolored: HashMap<VReg, EbpfReg>,
    ) -> ColoringResult {
        // Run graph coloring allocation
        let mut allocator = GraphColoringAllocator::new(available_regs);
        if !precolored.is_empty() {
            allocator.set_precolored(precolored);
        }
        let loop_depths = compute_loop_depths(func);
        allocator.allocate(func, Some(&loop_depths))
    }

    /// Layout stack slots and assign offsets for a function
    fn layout_stack_for_function(
        &self,
        func: &LirFunction,
        alloc: &ColoringResult,
    ) -> Result<
        (
            HashMap<StackSlotId, i16>,
            HashMap<VReg, i16>,
            i16,
            Option<i16>,
            Option<i16>,
        ),
        CompileError,
    > {
        let mut slots: Vec<StackSlot> = func.stack_slots.clone();
        let spill_base = slots.len() as u32;

        for (idx, slot) in alloc.spill_slots.iter().enumerate() {
            let mut slot = slot.clone();
            slot.id = StackSlotId(spill_base + idx as u32);
            slots.push(slot);
        }

        // Subfunction entry parameter shuffles are also parallel moves and may
        // contain cycles (e.g. R1 <-> R2), so they need the same temp slot.
        let needs_parallel_moves = Self::function_has_parallel_moves(func) || func.param_count > 0;
        let needs_scratch = needs_parallel_moves && Self::parallel_move_needs_scratch(func, alloc);
        let temp_slot_ids = if needs_parallel_moves {
            let base = spill_base + alloc.spill_slots.len() as u32;
            let cycle_id = StackSlotId(base);
            slots.push(StackSlot {
                id: cycle_id,
                size: 8,
                align: 8,
                kind: StackSlotKind::Spill,
                offset: None,
            });
            let scratch_id = if needs_scratch {
                let scratch_id = StackSlotId(base + 1);
                slots.push(StackSlot {
                    id: scratch_id,
                    size: 8,
                    align: 8,
                    kind: StackSlotKind::Spill,
                    offset: None,
                });
                Some(scratch_id)
            } else {
                None
            };
            Some((cycle_id, scratch_id))
        } else {
            None
        };

        // Sort slots by alignment (largest first) for better packing
        slots.sort_by(|a, b| b.align.cmp(&a.align).then(b.size.cmp(&a.size)));

        let mut stack_offset: i16 = 0;
        let mut slot_offsets: HashMap<StackSlotId, i16> = HashMap::new();

        for slot in slots {
            let aligned_size = slot.size.div_ceil(slot.align) * slot.align;
            stack_offset -= aligned_size as i16;
            if stack_offset < -512 {
                return Err(CompileError::StackOverflow);
            }
            slot_offsets.insert(slot.id, stack_offset);
        }

        let mut vreg_spills: HashMap<VReg, i16> = HashMap::new();
        for (vreg, slot_id) in &alloc.spills {
            let new_slot_id = StackSlotId(spill_base + slot_id.0);
            if let Some(&offset) = slot_offsets.get(&new_slot_id) {
                vreg_spills.insert(*vreg, offset);
            }
        }

        let (parallel_move_cycle_offset, parallel_move_scratch_offset) =
            if let Some((cycle_id, scratch_id)) = temp_slot_ids {
                let cycle = slot_offsets.get(&cycle_id).copied();
                let scratch = scratch_id.and_then(|id| slot_offsets.get(&id).copied());
                (cycle, scratch)
            } else {
                (None, None)
            };

        Ok((
            slot_offsets,
            vreg_spills,
            stack_offset,
            parallel_move_cycle_offset,
            parallel_move_scratch_offset,
        ))
    }

    fn function_has_parallel_moves(func: &LirFunction) -> bool {
        for block in &func.blocks {
            if block
                .instructions
                .iter()
                .any(|inst| matches!(inst, LirInst::ParallelMove { .. }))
            {
                return true;
            }
            if matches!(block.terminator, LirInst::ParallelMove { .. }) {
                return true;
            }
        }
        false
    }

    fn parallel_move_needs_scratch(func: &LirFunction, alloc: &ColoringResult) -> bool {
        #[derive(Clone, Copy)]
        enum Loc {
            Reg(EbpfReg),
            Stack,
        }

        let vreg_loc = |vreg: VReg| -> Loc {
            if alloc.spills.contains_key(&vreg) {
                return Loc::Stack;
            }
            if let Some(&reg) = alloc.coloring.get(&vreg) {
                return Loc::Reg(reg);
            }
            Loc::Reg(EbpfReg::R0)
        };

        for block in &func.blocks {
            let insts = block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator));
            for inst in insts {
                if let LirInst::ParallelMove { moves } = inst {
                    let mut reg_sources = HashSet::new();
                    let mut reg_dests = Vec::new();
                    let mut has_stack = false;

                    for (dst, src) in moves {
                        let dst_loc = vreg_loc(*dst);
                        let src_loc = vreg_loc(*src);
                        if matches!(dst_loc, Loc::Stack) || matches!(src_loc, Loc::Stack) {
                            has_stack = true;
                        }
                        if let Loc::Reg(reg) = src_loc {
                            reg_sources.insert(reg);
                        }
                        if let Loc::Reg(reg) = dst_loc {
                            reg_dests.push(reg);
                        }
                    }

                    if has_stack {
                        let safe = reg_dests.iter().any(|r| !reg_sources.contains(r));
                        if !safe {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn prepare_function_state(
        &mut self,
        func: &LirFunction,
        available_regs: Vec<EbpfReg>,
        precolored: HashMap<VReg, EbpfReg>,
    ) -> Result<ColoringResult, CompileError> {
        let alloc = self.allocate_registers_for_function(func, available_regs, precolored);
        let (
            slot_offsets,
            vreg_spills,
            stack_offset,
            parallel_move_cycle_offset,
            parallel_move_scratch_offset,
        ) = self.layout_stack_for_function(func, &alloc)?;
        let remat_spills = self.compute_rematerializable_spills(func, &alloc.spills);

        self.vreg_to_phys = alloc.coloring.clone();
        self.vreg_spills = vreg_spills;
        self.vreg_remat = remat_spills;
        self.slot_offsets = slot_offsets;
        self.stack_offset = stack_offset;
        self.parallel_move_cycle_offset = parallel_move_cycle_offset;
        self.parallel_move_scratch_offset = parallel_move_scratch_offset;
        self.callee_saved_offsets.clear();

        Ok(alloc)
    }

    fn compute_rematerializable_spills(
        &self,
        func: &LirFunction,
        spills: &HashMap<VReg, StackSlotId>,
    ) -> HashMap<VReg, RematExpr> {
        if spills.is_empty() {
            return HashMap::new();
        }

        let mut def_count: HashMap<VReg, usize> = HashMap::new();
        let mut single_defs: HashMap<VReg, LirInst> = HashMap::new();

        for block in &func.blocks {
            for inst in block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
            {
                for dst in inst.defs() {
                    let count = def_count.entry(dst).or_insert(0);
                    *count += 1;
                    if *count == 1 {
                        single_defs.insert(dst, inst.clone());
                    } else {
                        single_defs.remove(&dst);
                    }
                }
            }
        }

        let mut known: HashMap<VReg, RematExpr> = HashMap::new();
        loop {
            let mut changed = false;
            for (&vreg, inst) in &single_defs {
                if known.contains_key(&vreg) {
                    continue;
                }
                if let Some(expr) = Self::derive_remat_expr(inst, &known) {
                    known.insert(vreg, expr);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        spills
            .keys()
            .filter_map(|vreg| known.get(vreg).copied().map(|expr| (*vreg, expr)))
            .collect()
    }

    fn derive_remat_expr(inst: &LirInst, known: &HashMap<VReg, RematExpr>) -> Option<RematExpr> {
        match inst {
            LirInst::Copy { src, .. } => Self::remat_expr_for_value(src, known),
            LirInst::UnaryOp { op, src, .. } => {
                let RematExpr::Const(value) = Self::remat_expr_for_value(src, known)? else {
                    return None;
                };
                Self::remat_const(Self::eval_const_unary(*op, value))
            }
            LirInst::BinOp { op, lhs, rhs, .. } => {
                let lhs_expr = Self::remat_expr_for_value(lhs, known)?;
                let rhs_expr = Self::remat_expr_for_value(rhs, known)?;
                match (lhs_expr, rhs_expr) {
                    (RematExpr::Const(lhs), RematExpr::Const(rhs)) => {
                        let value = Self::eval_const_binop(*op, lhs, rhs)?;
                        Self::remat_const(value)
                    }
                    (RematExpr::StackAddr { slot, addend }, RematExpr::Const(rhs)) => {
                        let rhs = i32::try_from(rhs).ok()?;
                        match op {
                            BinOpKind::Add => Some(RematExpr::StackAddr {
                                slot,
                                addend: addend.checked_add(rhs)?,
                            }),
                            BinOpKind::Sub => Some(RematExpr::StackAddr {
                                slot,
                                addend: addend.checked_sub(rhs)?,
                            }),
                            _ => None,
                        }
                    }
                    (RematExpr::Const(lhs), RematExpr::StackAddr { slot, addend }) => {
                        let lhs = i32::try_from(lhs).ok()?;
                        match op {
                            BinOpKind::Add => Some(RematExpr::StackAddr {
                                slot,
                                addend: lhs.checked_add(addend)?,
                            }),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn remat_expr_for_value(
        value: &MirValue,
        known: &HashMap<VReg, RematExpr>,
    ) -> Option<RematExpr> {
        match value {
            MirValue::Const(v) => Self::remat_const(*v),
            MirValue::StackSlot(slot) => Some(RematExpr::StackAddr {
                slot: *slot,
                addend: 0,
            }),
            MirValue::VReg(vreg) => known.get(vreg).copied(),
        }
    }

    fn remat_const(value: i64) -> Option<RematExpr> {
        i32::try_from(value).ok()?;
        Some(RematExpr::Const(value))
    }

    fn eval_const_binop(op: BinOpKind, lhs: i64, rhs: i64) -> Option<i64> {
        match op {
            BinOpKind::Add => Some(lhs.wrapping_add(rhs)),
            BinOpKind::Sub => Some(lhs.wrapping_sub(rhs)),
            BinOpKind::Mul => Some(lhs.wrapping_mul(rhs)),
            BinOpKind::Div => {
                if rhs == 0 {
                    None
                } else {
                    Some(lhs.wrapping_div(rhs))
                }
            }
            BinOpKind::Mod => {
                if rhs == 0 {
                    None
                } else {
                    Some(lhs.wrapping_rem(rhs))
                }
            }
            BinOpKind::And => Some(lhs & rhs),
            BinOpKind::Or => Some(lhs | rhs),
            BinOpKind::Xor => Some(lhs ^ rhs),
            BinOpKind::Shl => Some(lhs << (rhs & 63)),
            BinOpKind::Shr => Some(lhs >> (rhs & 63)),
            BinOpKind::Eq => Some(if lhs == rhs { 1 } else { 0 }),
            BinOpKind::Ne => Some(if lhs != rhs { 1 } else { 0 }),
            BinOpKind::Lt => Some(if lhs < rhs { 1 } else { 0 }),
            BinOpKind::Le => Some(if lhs <= rhs { 1 } else { 0 }),
            BinOpKind::Gt => Some(if lhs > rhs { 1 } else { 0 }),
            BinOpKind::Ge => Some(if lhs >= rhs { 1 } else { 0 }),
        }
    }

    fn eval_const_unary(op: UnaryOpKind, src: i64) -> i64 {
        match op {
            UnaryOpKind::Not => {
                if src == 0 {
                    1
                } else {
                    0
                }
            }
            UnaryOpKind::BitNot => !src,
            UnaryOpKind::Neg => src.wrapping_neg(),
        }
    }

    fn emit_callee_save_prologue(&mut self) -> Result<(), CompileError> {
        let mut regs: Vec<EbpfReg> = self
            .vreg_to_phys
            .values()
            .copied()
            .filter(|reg| matches!(reg, EbpfReg::R6 | EbpfReg::R7 | EbpfReg::R8 | EbpfReg::R9))
            .collect();
        regs.sort_by_key(|reg| reg.as_u8());
        regs.dedup();

        for reg in regs {
            self.check_stack_space(8)?;
            self.stack_offset -= 8;
            let offset = self.stack_offset;
            self.callee_saved_offsets.insert(reg, offset);
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, reg));
        }

        Ok(())
    }

    fn restore_callee_saved(&mut self) {
        if self.callee_saved_offsets.is_empty() {
            return;
        }
        let mut regs: Vec<EbpfReg> = self.callee_saved_offsets.keys().copied().collect();
        regs.sort_by_key(|reg| reg.as_u8());
        for reg in regs {
            if let Some(&offset) = self.callee_saved_offsets.get(&reg) {
                self.instructions
                    .push(EbpfInsn::ldxdw(reg, EbpfReg::R10, offset));
            }
        }
    }

    fn emit_param_moves(&mut self, func: &LirFunction) -> Result<(), CompileError> {
        if func.param_count == 0 {
            return Ok(());
        }

        let arg_regs = [
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
        ];

        if func.param_count > arg_regs.len() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "Function has {} params; BPF supports at most {}",
                func.param_count,
                arg_regs.len()
            )));
        }

        let cycle_temp = self.parallel_move_cycle_offset.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Parameter move lowering requires a temp stack slot".into(),
            )
        })?;

        let mut reg_moves: HashMap<EbpfReg, EbpfReg> = HashMap::new();

        for i in 0..func.param_count {
            let vreg = VReg(i as u32);
            let src = arg_regs[i];
            if let Some(&dst) = self.vreg_to_phys.get(&vreg) {
                if dst != src {
                    reg_moves.insert(src, dst);
                }
            } else if let Some(&offset) = self.vreg_spills.get(&vreg) {
                self.instructions
                    .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src));
            }
        }

        while !reg_moves.is_empty() {
            let sources: HashSet<EbpfReg> = reg_moves.keys().copied().collect();
            let mut ready = Vec::new();

            for (&src, &dst) in &reg_moves {
                if !sources.contains(&dst) {
                    ready.push(src);
                }
            }

            if !ready.is_empty() {
                for src in ready {
                    if let Some(dst) = reg_moves.remove(&src) {
                        self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                    }
                }
                continue;
            }

            // Cycle: spill one source to stack, rotate the cycle, then reload.
            let (&start_src, &start_dst) = reg_moves.iter().next().expect("cycle");
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, cycle_temp, start_src));
            reg_moves.remove(&start_src);

            let mut src = start_dst;
            while src != start_src {
                let dst = reg_moves.remove(&src).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Failed to lower cyclic parameter moves".into(),
                    )
                })?;
                self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                src = dst;
            }

            self.instructions
                .push(EbpfInsn::ldxdw(start_dst, EbpfReg::R10, cycle_temp));
        }

        Ok(())
    }

    /// Compile a LIR function
    fn compile_function(&mut self, func: &LirFunction) -> Result<(), CompileError> {
        // Register allocation uses Chaitin-Briggs graph coloring for optimal results.

        // Use block order as listed; LIR is already low-level.
        let block_order: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();

        // Emit function prologue: save R1 (context pointer) to R9
        // R1 contains the probe context (pt_regs for kprobe, etc.)
        // We save it to R9 which is callee-saved and not used by our register allocator
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R9, EbpfReg::R1));

        // Compile each block in CFG order
        for block_id in block_order {
            let block = func.block(block_id).clone();
            self.compile_block(&block)?;
        }

        Ok(())
    }

    /// Compile a basic block
    fn compile_block(&mut self, block: &LirBlock) -> Result<(), CompileError> {
        // Record block start offset
        self.block_offsets.insert(block.id, self.instructions.len());

        // Compile instructions
        for inst in &block.instructions {
            self.compile_instruction_with_spills(inst)?;
        }

        // Compile terminator
        self.compile_instruction_with_spills(&block.terminator)?;

        Ok(())
    }

    fn compile_instruction_with_spills(&mut self, inst: &LirInst) -> Result<(), CompileError> {
        self.compile_instruction(inst)?;
        self.store_spilled_defs(inst);
        Ok(())
    }

    fn store_spilled_defs(&mut self, inst: &LirInst) {
        if matches!(inst, LirInst::ParallelMove { .. }) {
            return;
        }
        for dst in inst.defs() {
            let Some(&offset) = self.vreg_spills.get(&dst) else {
                continue;
            };
            if self.vreg_remat.contains_key(&dst) {
                continue;
            }
            let src_reg = self.vreg_to_phys.get(&dst).copied().unwrap_or(EbpfReg::R0);
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src_reg));
        }
    }

    /// Check if we have enough stack space
    fn check_stack_space(&self, needed: i16) -> Result<(), CompileError> {
        if self.stack_offset - needed < -512 {
            Err(CompileError::StackOverflow)
        } else {
            Ok(())
        }
    }

    /// Fix up pending jumps after all blocks are compiled
    fn fixup_jumps(&mut self) -> Result<(), CompileError> {
        for (insn_idx, target_block) in &self.pending_jumps {
            let target_offset = self
                .block_offsets
                .get(target_block)
                .copied()
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "Jump target block {:?} not found",
                        target_block
                    ))
                })?;

            // Calculate relative offset (target - source - 1)
            let rel_offset = (target_offset as i64 - *insn_idx as i64 - 1) as i16;

            // Update the jump instruction's offset field
            self.instructions[*insn_idx].offset = rel_offset;
        }
        Ok(())
    }

    /// Compile all subfunctions (BPF-to-BPF function calls)
    ///
    /// Each subfunction is appended after the main function.
    /// Subfunctions use the standard BPF calling convention:
    /// - R1-R5: arguments (up to 5)
    /// - R0: return value
    /// - Callee-saved: R6-R9, R10 (frame pointer)
    fn compile_subfunctions(&mut self) -> Result<(), CompileError> {
        // Clone subfunctions to avoid borrowing issues
        let subfunctions: Vec<_> = self.lir.subfunctions.clone();

        for (idx, subfn) in subfunctions.iter().enumerate() {
            let subfn_id = SubfunctionId(idx as u32);
            self.current_types = self
                .program_types
                .subfunctions
                .get(idx)
                .cloned()
                .unwrap_or_default();

            // Record the start offset of this subfunction
            let start_offset = self.instructions.len();
            self.subfn_offsets.insert(subfn_id, start_offset);

            // Store temporary register/stack state
            let saved_vreg_to_phys = std::mem::take(&mut self.vreg_to_phys);
            let saved_vreg_spills = std::mem::take(&mut self.vreg_spills);
            let saved_vreg_remat = std::mem::take(&mut self.vreg_remat);
            let saved_slot_offsets = std::mem::take(&mut self.slot_offsets);
            let saved_stack_offset = self.stack_offset;
            let saved_block_offsets = std::mem::take(&mut self.block_offsets);
            let saved_pending_jumps = std::mem::take(&mut self.pending_jumps);
            let saved_callee_saved = std::mem::take(&mut self.callee_saved_offsets);

            // Prepare allocation and stack layout for this subfunction
            if subfn.param_count > 5 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Subfunction {:?} has {} params; BPF supports at most 5",
                    subfn_id, subfn.param_count
                )));
            }
            self.prepare_function_state(
                subfn,
                self.available_regs.clone(),
                subfn.precolored.clone(),
            )?;

            // Emit callee-saved prologue for subfunction
            self.emit_callee_save_prologue()?;
            self.emit_param_moves(subfn)?;

            // Compile subfunction blocks
            // Note: subfunctions receive args in R1-R5 and save any used callee-saved regs.
            let block_order: Vec<BlockId> = subfn.blocks.iter().map(|b| b.id).collect();

            for block_id in block_order {
                let block = subfn.block(block_id).clone();
                self.compile_block(&block)?;
            }

            // Fix up jumps within this subfunction
            self.fixup_jumps()?;

            // Restore main function's register/stack state
            self.vreg_to_phys = saved_vreg_to_phys;
            self.vreg_spills = saved_vreg_spills;
            self.vreg_remat = saved_vreg_remat;
            self.slot_offsets = saved_slot_offsets;
            self.stack_offset = saved_stack_offset;
            self.block_offsets = saved_block_offsets;
            self.pending_jumps = saved_pending_jumps;
            self.callee_saved_offsets = saved_callee_saved;
        }

        Ok(())
    }

    /// Fix up subfunction call offsets
    ///
    /// BPF-to-BPF calls use relative offsets in the imm field.
    /// The offset is from the instruction after the call to the start of the target function.
    fn fixup_subfn_calls(&mut self) -> Result<(), CompileError> {
        for (call_idx, subfn_id) in &self.subfn_calls {
            let subfn_offset = self.subfn_offsets.get(subfn_id).copied().ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "Subfunction {:?} not found",
                    subfn_id
                ))
            })?;

            // Calculate relative offset (target - source - 1)
            // For BPF calls, the offset is relative to the instruction after the call
            let rel_offset = (subfn_offset as i64 - *call_idx as i64 - 1) as i32;

            // Update the call instruction's imm field
            self.instructions[*call_idx].imm = rel_offset;
        }
        Ok(())
    }

    // === Register Allocation (Graph Coloring) ===
    //
    // Register allocation is performed upfront via graph coloring (Chaitin-Briggs).
    // At this point, vreg_to_phys contains the coloring and vreg_spills contains
    // spill slot offsets for vregs that couldn't be colored.

    /// Get the physical register for a virtual register
    /// Returns the pre-computed coloring, or handles spilled vregs
    fn alloc_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        // Check if this vreg was assigned a physical register by graph coloring
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        // If the vreg was spilled, we need a temporary register
        // Use R0 as a scratch register for spilled values
        // (R0 is the return value register, safe to clobber mid-computation)
        Ok(EbpfReg::R0)
    }

    /// Allocate a register for a destination vreg
    fn alloc_dst_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        self.alloc_reg(vreg)
    }

    fn emit_remat_expr(&mut self, dst: EbpfReg, expr: RematExpr) -> Result<(), CompileError> {
        match expr {
            RematExpr::Const(value) => {
                let imm = i32::try_from(value).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "rematerialized constant {} out of i32 range",
                        value
                    ))
                })?;
                self.instructions.push(EbpfInsn::mov64_imm(dst, imm));
            }
            RematExpr::StackAddr { slot, addend } => {
                let base = self.slot_offsets.get(&slot).copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "stack slot {:?} not found for rematerialization",
                        slot
                    ))
                })?;
                let total = i32::from(base).checked_add(addend).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "rematerialized stack address offset overflow for {:?}",
                        slot
                    ))
                })?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions.push(EbpfInsn::add64_imm(dst, total));
            }
        }
        Ok(())
    }

    /// Ensure a virtual register is in a physical register
    /// If the vreg is spilled, emit a reload instruction
    fn ensure_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        // Check if this vreg has a physical register
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        if let Some(expr) = self.vreg_remat.get(&vreg).copied() {
            let scratch = EbpfReg::R0;
            self.emit_remat_expr(scratch, expr)?;
            return Ok(scratch);
        }

        // The vreg is spilled - reload it to a scratch register
        if let Some(&offset) = self.vreg_spills.get(&vreg) {
            // Use R0 as scratch for reloads
            let scratch = EbpfReg::R0;
            self.instructions
                .push(EbpfInsn::ldxdw(scratch, EbpfReg::R10, offset));
            return Ok(scratch);
        }

        // Vreg wasn't allocated - this shouldn't happen with proper graph coloring
        // Fall back to R0 as scratch
        Ok(EbpfReg::R0)
    }
}

/// Compile a MIR program to eBPF
pub fn compile_mir_to_ebpf(
    mir: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
) -> Result<MirCompileResult, CompileError> {
    compile_mir_to_ebpf_with_hints(mir, probe_ctx, None)
}

pub fn compile_mir_to_ebpf_with_hints(
    mir: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
    type_hints: Option<&MirTypeHints>,
) -> Result<MirCompileResult, CompileError> {
    let mut program = mir.clone();
    let list_lowering = ListLowering;
    let ssa_destruct = SsaDestruction;
    let cfg = CFG::build(&program.main);
    let _ = list_lowering.run(&mut program.main, &cfg);
    let cfg = CFG::build(&program.main);
    let _ = ssa_destruct.run(&mut program.main, &cfg);
    for subfn in &mut program.subfunctions {
        let cfg = CFG::build(subfn);
        let _ = list_lowering.run(subfn, &cfg);
        let cfg = CFG::build(subfn);
        let _ = ssa_destruct.run(subfn, &cfg);
    }

    let program_types = verify_mir_program(&program, probe_ctx, type_hints)?;
    let lir_program = lower_mir_to_lir_checked(&program)?;

    let compiler = MirToEbpfCompiler::new_with_types(&lir_program, probe_ctx, program_types);
    compiler.compile()
}

fn verify_mir_program(
    program: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
    type_hints: Option<&MirTypeHints>,
) -> Result<ProgramVregTypes, CompileError> {
    let subfn_schemes = match infer_subfunction_schemes(&program.subfunctions, probe_ctx.cloned()) {
        Ok(schemes) => schemes,
        Err(errors) => {
            if let Some(err) = errors.into_iter().next() {
                return Err(crate::compiler::CompileError::TypeError(err));
            }
            HashMap::new()
        }
    };

    let mut all_funcs = Vec::with_capacity(1 + program.subfunctions.len());
    all_funcs.push((&program.main, type_hints.map(|h| &h.main)));
    for (idx, subfn) in program.subfunctions.iter().enumerate() {
        let hints = type_hints.and_then(|h| h.subfunctions.get(idx));
        all_funcs.push((subfn, hints));
    }

    let mut program_types = ProgramVregTypes::default();

    for (idx, (func, hints)) in all_funcs.into_iter().enumerate() {
        let mut type_infer = TypeInference::new_with_env(
            probe_ctx.cloned(),
            Some(&subfn_schemes),
            Some(HMType::I64),
            hints,
        );
        let types = match type_infer.infer(func) {
            Ok(types) => types,
            Err(errors) => {
                if let Some(err) = errors.into_iter().next() {
                    return Err(crate::compiler::CompileError::TypeError(err));
                }
                HashMap::new()
            }
        };
        if let Err(errors) = verifier_types::verify_mir(func, &types) {
            if let Some(err) = errors.into_iter().next() {
                return Err(CompileError::VerifierTypeError(err));
            }
        }
        if let Err(errors) = vcc::verify_mir(func, &types) {
            let message = errors
                .iter()
                .map(|err| err.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CompileError::VccError(message));
        }
        if idx == 0 {
            program_types.main = types;
        } else {
            program_types.subfunctions.push(types);
        }
    }

    Ok(program_types)
}

#[cfg(test)]
mod tests;
