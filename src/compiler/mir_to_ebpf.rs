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
mod helper_calls;
mod maps;

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

    /// Compile a single LIR instruction
    fn compile_instruction(&mut self, inst: &LirInst) -> Result<(), CompileError> {
        match inst {
            LirInst::Copy { dst, src } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                            self.instructions
                                .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                        } else {
                            // Large constant - split into two parts
                            let low = *c as i32;
                            let high = (*c >> 32) as i32;
                            self.instructions.push(EbpfInsn::mov64_imm(dst_reg, low));
                            if high != 0 {
                                self.instructions
                                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, high));
                                self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R0, 32));
                                self.instructions
                                    .push(EbpfInsn::or64_reg(dst_reg, EbpfReg::R0));
                            }
                        }
                    }
                    MirValue::StackSlot(slot) => {
                        let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                        self.instructions
                            .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R10));
                        self.instructions
                            .push(EbpfInsn::add64_imm(dst_reg, offset as i32));
                    }
                }
            }

            LirInst::ParallelMove { moves } => {
                #[derive(Clone, Copy, PartialEq, Eq, Hash)]
                enum Loc {
                    Reg(EbpfReg),
                    Stack(i16),
                }

                #[derive(Clone, Copy)]
                struct Move {
                    dst: Loc,
                    src: Loc,
                }

                let mut pending: Vec<Move> = Vec::new();
                let mut reg_sources: HashSet<EbpfReg> = HashSet::new();
                let mut has_stack = false;

                for (dst_vreg, src_vreg) in moves {
                    let dst_loc = if let Some(&phys) = self.vreg_to_phys.get(dst_vreg) {
                        Loc::Reg(phys)
                    } else if let Some(&offset) = self.vreg_spills.get(dst_vreg) {
                        Loc::Stack(offset)
                    } else {
                        Loc::Reg(EbpfReg::R0)
                    };

                    let src_loc = if let Some(&phys) = self.vreg_to_phys.get(src_vreg) {
                        Loc::Reg(phys)
                    } else if let Some(&offset) = self.vreg_spills.get(src_vreg) {
                        Loc::Stack(offset)
                    } else {
                        Loc::Reg(EbpfReg::R0)
                    };

                    if matches!(dst_loc, Loc::Stack(_)) || matches!(src_loc, Loc::Stack(_)) {
                        has_stack = true;
                    }
                    if let Loc::Reg(reg) = src_loc {
                        reg_sources.insert(reg);
                    }

                    if dst_loc != src_loc {
                        pending.push(Move {
                            dst: dst_loc,
                            src: src_loc,
                        });
                    }
                }

                if pending.is_empty() {
                    return Ok(());
                }

                let cycle_temp = self.parallel_move_cycle_offset.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "ParallelMove requires a temp stack slot".into(),
                    )
                })?;
                let scratch_temp = self.parallel_move_scratch_offset;

                let mut scratch_reg = None;
                if has_stack {
                    scratch_reg = pending
                        .iter()
                        .filter_map(|m| match m.dst {
                            Loc::Reg(reg) if !reg_sources.contains(&reg) => Some(reg),
                            _ => None,
                        })
                        .next();

                    if scratch_reg.is_none() {
                        scratch_reg = pending
                            .iter()
                            .find_map(|m| match m.dst {
                                Loc::Reg(reg) => Some(reg),
                                _ => None,
                            })
                            .or_else(|| {
                                pending.iter().find_map(|m| match m.src {
                                    Loc::Reg(reg) => Some(reg),
                                    _ => None,
                                })
                            });

                        if let Some(reg) = scratch_reg {
                            if reg_sources.contains(&reg) {
                                let scratch_temp = scratch_temp.ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(
                                        "ParallelMove requires a scratch temp slot".into(),
                                    )
                                })?;
                                self.instructions.push(EbpfInsn::stxdw(
                                    EbpfReg::R10,
                                    scratch_temp,
                                    reg,
                                ));
                                for mv in &mut pending {
                                    if mv.src == Loc::Reg(reg) {
                                        mv.src = Loc::Stack(scratch_temp);
                                    }
                                }
                                reg_sources.remove(&reg);
                            }
                        } else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ParallelMove with stack slots requires at least one register"
                                    .into(),
                            ));
                        }
                    }
                }

                let temp_loc = Loc::Stack(cycle_temp);

                while !pending.is_empty() {
                    let dsts: HashSet<Loc> = pending.iter().map(|m| m.dst).collect();
                    let ready_idx = pending.iter().position(|m| !dsts.contains(&m.src));

                    if let Some(idx) = ready_idx {
                        let mv = pending.remove(idx);
                        match (mv.dst, mv.src) {
                            (Loc::Reg(dst), Loc::Reg(src)) => {
                                if dst != src {
                                    self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                                }
                            }
                            (Loc::Reg(dst), Loc::Stack(src_off)) => {
                                self.instructions
                                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R10, src_off));
                            }
                            (Loc::Stack(dst_off), Loc::Reg(src)) => {
                                self.instructions
                                    .push(EbpfInsn::stxdw(EbpfReg::R10, dst_off, src));
                            }
                            (Loc::Stack(dst_off), Loc::Stack(src_off)) => {
                                let temp_reg = scratch_reg.ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(
                                        "ParallelMove stack-to-stack needs a scratch register"
                                            .into(),
                                    )
                                })?;
                                self.instructions.push(EbpfInsn::ldxdw(
                                    temp_reg,
                                    EbpfReg::R10,
                                    src_off,
                                ));
                                self.instructions.push(EbpfInsn::stxdw(
                                    EbpfReg::R10,
                                    dst_off,
                                    temp_reg,
                                ));
                            }
                        }
                        continue;
                    }

                    // Cycle: break by saving one source to temp
                    let src = pending[0].src;
                    match (temp_loc, src) {
                        (Loc::Reg(temp), Loc::Reg(src_reg)) => {
                            self.instructions.push(EbpfInsn::mov64_reg(temp, src_reg));
                        }
                        (Loc::Reg(temp), Loc::Stack(off)) => {
                            self.instructions
                                .push(EbpfInsn::ldxdw(temp, EbpfReg::R10, off));
                        }
                        (Loc::Stack(temp_off), Loc::Reg(src_reg)) => {
                            self.instructions.push(EbpfInsn::stxdw(
                                EbpfReg::R10,
                                temp_off,
                                src_reg,
                            ));
                        }
                        (Loc::Stack(temp_off), Loc::Stack(src_off)) => {
                            let temp_reg = scratch_reg.ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "ParallelMove stack source requires a scratch register".into(),
                                )
                            })?;
                            self.instructions.push(EbpfInsn::ldxdw(
                                temp_reg,
                                EbpfReg::R10,
                                src_off,
                            ));
                            self.instructions.push(EbpfInsn::stxdw(
                                EbpfReg::R10,
                                temp_off,
                                temp_reg,
                            ));
                        }
                    }
                    pending[0].src = temp_loc;
                }
            }

            LirInst::Load {
                dst,
                ptr,
                offset,
                ty,
            } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let ptr_reg = self.ensure_reg(*ptr)?;
                let size = ty.size();
                let offset = i16::try_from(*offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "load offset {} out of range",
                        offset
                    ))
                })?;
                self.emit_load(dst_reg, ptr_reg, offset, size)?;
            }

            LirInst::Store {
                ptr,
                offset,
                val,
                ty,
            } => {
                let ptr_reg = self.ensure_reg(*ptr)?;
                let size = ty.size();
                let offset = i16::try_from(*offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "store offset {} out of range",
                        offset
                    ))
                })?;
                let val_reg = self.value_to_reg(val)?;
                self.emit_store(ptr_reg, offset, val_reg, size)?;
            }

            LirInst::LoadSlot {
                dst,
                slot,
                offset,
                ty,
            } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let size = ty.size();
                let offset = self.slot_offset_i16(*slot, *offset)?;
                self.emit_load(dst_reg, EbpfReg::R10, offset, size)?;
            }

            LirInst::StoreSlot {
                slot,
                offset,
                val,
                ty,
            } => {
                let size = ty.size();
                let offset = self.slot_offset_i16(*slot, *offset)?;
                let val_reg = self.value_to_reg(val)?;
                self.emit_store(EbpfReg::R10, offset, val_reg, size)?;
            }

            LirInst::BinOp { dst, op, lhs, rhs } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                let lhs_vreg = match lhs {
                    MirValue::VReg(v) => Some(*v),
                    _ => None,
                };
                let rhs_vreg = match rhs {
                    MirValue::VReg(v) => Some(*v),
                    _ => None,
                };
                let mut rhs_reg = match rhs {
                    MirValue::VReg(v) => Some(self.ensure_reg(*v)?),
                    _ => None,
                };

                if let (Some(rhs_reg_value), Some(rhs_vreg)) = (rhs_reg, rhs_vreg) {
                    if rhs_reg_value == dst_reg && lhs_vreg != Some(rhs_vreg) {
                        // Preserve RHS before we clobber dst_reg with LHS.
                        if dst_reg != EbpfReg::R0 {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, rhs_reg_value));
                            rhs_reg = Some(EbpfReg::R0);
                        }
                    }
                }

                // Load LHS into dst
                match lhs {
                    MirValue::VReg(v) => {
                        let src = self.ensure_reg(*v)?;
                        if dst_reg != src {
                            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop LHS".into(),
                        ));
                    }
                }

                // Apply operation with RHS
                match rhs {
                    MirValue::VReg(v) => {
                        let rhs_reg = rhs_reg.unwrap_or(self.ensure_reg(*v)?);
                        self.emit_binop_reg(dst_reg, *op, rhs_reg)?;
                    }
                    MirValue::Const(c) => {
                        self.emit_binop_imm(dst_reg, *op, *c as i32)?;
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop RHS".into(),
                        ));
                    }
                }
            }

            LirInst::UnaryOp { dst, op, src } => {
                let dst_reg = self.alloc_dst_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in unary op".into(),
                        ));
                    }
                }

                match op {
                    UnaryOpKind::Not => {
                        // Logical not: 0 -> 1, non-zero -> 0
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, 1));
                        self.instructions.push(EbpfInsn::and64_imm(dst_reg, 1));
                    }
                    UnaryOpKind::BitNot => {
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, -1));
                    }
                    UnaryOpKind::Neg => {
                        self.instructions.push(EbpfInsn::neg64(dst_reg));
                    }
                }
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
                let jump_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0)); // Placeholder
                self.pending_jumps.push((jump_idx, *target));
            }

            LirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                let cond_reg = self.ensure_reg(*cond)?;

                // JNE (jump if not equal to 0) to if_true
                let jne_idx = self.instructions.len();
                // JNE dst, imm, offset
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
                    cond_reg.as_u8(),
                    0,
                    0, // Placeholder
                    0, // Compare against 0
                ));
                self.pending_jumps.push((jne_idx, *if_true));

                // Fall through or jump to if_false
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *if_false));
            }

            LirInst::Return { val } => {
                match val {
                    Some(MirValue::VReg(v)) => {
                        let src = self.ensure_reg(*v)?;
                        if src != EbpfReg::R0 {
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, src));
                        }
                    }
                    Some(MirValue::Const(c)) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                    }
                    Some(MirValue::StackSlot(_)) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in return".into(),
                        ));
                    }
                    None => {
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                    }
                }
                self.restore_callee_saved();
                self.instructions.push(EbpfInsn::exit());
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
                // Bounded loop header for eBPF verifier compliance
                // counter < limit ? jump to body : jump to exit
                let counter_reg = self.ensure_reg(*counter)?;

                // Compare counter against limit
                // JSLT: jump if counter < limit (signed)
                let jlt_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
                    counter_reg.as_u8(),
                    0,
                    0, // Placeholder - will be fixed up
                    *limit as i32,
                ));
                self.pending_jumps.push((jlt_idx, *body));

                // Fall through to exit
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *exit));
            }

            LirInst::LoopBack {
                counter,
                step,
                header,
            } => {
                // Increment counter and jump back to header
                let counter_reg = self.ensure_reg(*counter)?;

                // Add step to counter
                self.instructions
                    .push(EbpfInsn::add64_imm(counter_reg, *step as i32));

                // Jump back to loop header
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *header));
            }

            LirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Tail call requires prog array map, got {:?} for '{}'",
                        prog_map.kind, prog_map.name
                    )));
                }
                self.tail_call_maps.insert(prog_map.name.clone());
                self.compile_tail_call(&prog_map.name, index)?;
                // Tail call helper does not return on success. If it does return, tail call failed;
                // terminate the current function with a default 0.
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                self.restore_callee_saved();
                self.instructions.push(EbpfInsn::exit());
            }

            LirInst::CallSubfn { subfn, args, .. } => {
                // BPF-to-BPF function call
                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF subfunctions support at most 5 arguments".into(),
                    ));
                }

                // Emit call instruction with placeholder offset
                let call_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::call_local(subfn.0 as i32));

                // Track this call for relocation
                self.subfn_calls.push((call_idx, *subfn));
            }

            LirInst::CallKfunc {
                kfunc,
                btf_id,
                args,
                ..
            } => {
                let sig = KfuncSignature::for_name(kfunc).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "unknown kfunc '{}' (typed signature required)",
                        kfunc
                    ))
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
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF kfunc calls support at most 5 arguments".into(),
                    ));
                }

                let resolved_btf_id = if let Some(btf_id) = btf_id {
                    *btf_id
                } else {
                    KernelBtf::get()
                        .resolve_kfunc_btf_id(kfunc)
                        .map_err(|err| {
                            CompileError::UnsupportedInstruction(format!(
                                "failed to resolve kfunc '{}' BTF ID: {}",
                                kfunc, err
                            ))
                        })?
                };

                if resolved_btf_id > i32::MAX as u32 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "kfunc '{}' BTF ID {} is out of supported range",
                        kfunc, resolved_btf_id
                    )));
                }

                self.instructions
                    .push(EbpfInsn::call_kfunc(resolved_btf_id as i32));
            }

            LirInst::CallHelper { helper, args, .. } => {
                if let Some(sig) = HelperSignature::for_id(*helper) {
                    if args.len() < sig.min_args || args.len() > sig.max_args {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "helper {} expects {}..={} arguments, got {}",
                            helper,
                            sig.min_args,
                            sig.max_args,
                            args.len()
                        )));
                    }
                } else if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF helpers support at most 5 arguments".into(),
                    ));
                }
                self.instructions
                    .push(EbpfInsn::new(opcode::CALL, 0, 0, 0, *helper as i32));
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
                // Get destination buffer offset
                let dst_offset = self.slot_offsets.get(dst_buffer).copied().unwrap_or(0);
                let len_reg = self.ensure_reg(*dst_len)?;

                match val_type {
                    StringAppendType::Literal { bytes } => {
                        // Append literal string bytes to buffer
                        // Each byte is stored at dst_buffer + dst_len + i
                        let effective_len = bytes
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|idx| idx + 1)
                            .unwrap_or(0);
                        for (i, byte) in bytes.iter().enumerate() {
                            // R0 = dst_len + i (offset within buffer)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, len_reg));
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R0, i as i32));

                            // R1 = R10 + dst_offset (buffer base)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));

                            // R1 = R1 + R0 (buffer + offset)
                            self.instructions
                                .push(EbpfInsn::add64_reg(EbpfReg::R1, EbpfReg::R0));

                            // R2 = byte value
                            self.instructions
                                .push(EbpfInsn::mov64_imm(EbpfReg::R2, *byte as i32));

                            // Store byte: [R1] = R2
                            self.instructions
                                .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R2));
                        }

                        if effective_len > 0 {
                            // Update length: dst_len += effective_len
                            self.instructions
                                .push(EbpfInsn::add64_imm(len_reg, effective_len as i32));
                        }
                    }

                    StringAppendType::StringSlot { slot, max_len } => {
                        // Copy bytes from source slot to destination
                        let src_offset = self.slot_offsets.get(slot).copied().unwrap_or(0);

                        // Bounded loop to copy up to max_len bytes
                        // For eBPF verifier, we unroll small loops
                        let copy_len = (*max_len).min(64); // Cap at 64 bytes to limit instruction count
                        for i in 0..copy_len {
                            // Load byte from source: R0 = [R10 + src_offset + i]
                            self.instructions.push(EbpfInsn::ldxb(
                                EbpfReg::R0,
                                EbpfReg::R10,
                                src_offset + i as i16,
                            ));

                            // Check for null terminator
                            let skip_offset = 8i16; // Skip remaining instructions if null
                            self.instructions
                                .push(EbpfInsn::jeq_imm(EbpfReg::R0, 0, skip_offset));

                            // R1 = dst_len (current position in dest)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R1, len_reg));

                            // R2 = R10 + dst_offset (dest buffer base)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R2, dst_offset as i32));

                            // R2 = R2 + R1 (dest buffer + offset)
                            self.instructions
                                .push(EbpfInsn::add64_reg(EbpfReg::R2, EbpfReg::R1));

                            // Store byte: [R2] = R0
                            self.instructions
                                .push(EbpfInsn::stxb(EbpfReg::R2, 0, EbpfReg::R0));

                            // Increment length
                            self.instructions.push(EbpfInsn::add64_imm(len_reg, 1));
                        }
                    }

                    StringAppendType::Integer => {
                        // Integer to string conversion then append
                        // Strategy:
                        // 1. Allocate 24-byte temp buffer for digit extraction
                        // 2. Extract digits in reverse order (at temp+19 down)
                        // 3. Copy digits in correct order to dst_buffer at dst_len
                        // 4. Update dst_len

                        // Get the integer value register
                        let val_reg = match val {
                            MirValue::VReg(v) => self.ensure_reg(*v)?,
                            MirValue::Const(c) => {
                                // Load constant into R0
                                self.instructions
                                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                                EbpfReg::R0
                            }
                            MirValue::StackSlot(_) => {
                                return Err(CompileError::UnsupportedInstruction(
                                    "Stack slot as integer value not supported".into(),
                                ));
                            }
                        };

                        // Allocate temporary buffer for digit extraction (24 bytes)
                        self.check_stack_space(24)?;
                        self.stack_offset -= 24;
                        let temp_offset = self.stack_offset;

                        // Check for zero special case
                        // We need to preserve val_reg, so copy to R3
                        self.instructions
                            .push(EbpfInsn::mov64_reg(EbpfReg::R3, val_reg));

                        // R4 = digit count
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

                        // Check if value is 0
                        let non_zero_skip = 5i16;
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                        self.instructions.push(EbpfInsn::jne_reg(
                            EbpfReg::R3,
                            EbpfReg::R0,
                            non_zero_skip,
                        ));

                        // Value is 0: store '0' at temp+19, set digit count to 1
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, b'0' as i32));
                        self.instructions
                            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                        self.instructions
                            .push(EbpfInsn::add64_imm(EbpfReg::R1, (temp_offset + 19) as i32));
                        self.instructions
                            .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 1));

                        // Extract digits for non-zero value (bounded loop for verifier)
                        for i in 0..20 {
                            // Skip if R3 == 0
                            let done_offset = 8i16;
                            self.instructions
                                .push(EbpfInsn::jeq_imm(EbpfReg::R3, 0, done_offset));

                            // R0 = R3 % 10 (digit)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R3));
                            self.instructions.push(EbpfInsn::mod64_imm(EbpfReg::R0, 10));

                            // Convert to ASCII: R0 += '0'
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R0, b'0' as i32));

                            // Store digit at temp + (19 - i)
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                            self.instructions.push(EbpfInsn::add64_imm(
                                EbpfReg::R1,
                                (temp_offset + 19 - i as i16) as i32,
                            ));
                            self.instructions
                                .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));

                            // R3 = R3 / 10
                            self.instructions.push(EbpfInsn::div64_imm(EbpfReg::R3, 10));

                            // R4++ (digit count)
                            self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R4, 1));
                        }

                        // Now copy digits from temp buffer to dst_buffer
                        // Digits are at temp + (20 - R4) to temp + 19
                        // Copy to dst_buffer + dst_len

                        // R5 = start position in temp = 20 - R4
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R5, 20));
                        self.instructions
                            .push(EbpfInsn::sub64_reg(EbpfReg::R5, EbpfReg::R4));

                        // Copy loop (bounded by max 20 digits)
                        for i in 0..20 {
                            // Skip if we've copied all digits (i >= R4)
                            self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, i));
                            let skip_copy = 10i16;
                            // Jump if R0 >= R4 (unsigned)
                            self.instructions.push(EbpfInsn::new(
                                opcode::BPF_JMP | opcode::BPF_JGE | opcode::BPF_X,
                                EbpfReg::R0.as_u8(),
                                EbpfReg::R4.as_u8(),
                                skip_copy,
                                0,
                            ));

                            // Load byte from temp + R5 + i
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R1, temp_offset as i32));
                            self.instructions
                                .push(EbpfInsn::add64_reg(EbpfReg::R1, EbpfReg::R5));
                            self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, i));
                            self.instructions
                                .push(EbpfInsn::ldxb(EbpfReg::R0, EbpfReg::R1, 0));

                            // Store to dst_buffer + dst_len + i
                            self.instructions
                                .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                            self.instructions
                                .push(EbpfInsn::add64_imm(EbpfReg::R2, dst_offset as i32));
                            self.instructions
                                .push(EbpfInsn::add64_reg(EbpfReg::R2, len_reg));
                            self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, i));
                            self.instructions
                                .push(EbpfInsn::stxb(EbpfReg::R2, 0, EbpfReg::R0));
                        }

                        // Update dst_len += digit_count (R4)
                        self.instructions
                            .push(EbpfInsn::add64_reg(len_reg, EbpfReg::R4));
                    }
                }
            }

            LirInst::IntToString {
                dst_buffer,
                dst_len,
                val,
            } => {
                // Convert integer to decimal string
                // Uses repeated division by 10 to extract digits

                let dst_offset = self.slot_offsets.get(dst_buffer).copied().unwrap_or(0);
                let val_reg = self.ensure_reg(*val)?;
                let len_reg = self.alloc_dst_reg(*dst_len)?;

                // Initialize length to 0
                self.instructions.push(EbpfInsn::mov64_imm(len_reg, 0));

                // Check for zero special case
                // if val == 0, just store '0' and return
                let non_zero_skip = 6i16; // Instructions to skip if non-zero
                self.instructions
                    .push(EbpfInsn::jne_reg(val_reg, EbpfReg::R0, non_zero_skip)); // R0 should be 0 here

                // Store '0' character
                self.instructions
                    .push(EbpfInsn::mov64_imm(EbpfReg::R0, b'0' as i32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));
                self.instructions
                    .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));
                self.instructions.push(EbpfInsn::mov64_imm(len_reg, 1));

                // For non-zero: extract digits (simplified - handles up to 10 digits)
                // This is a bounded loop for the verifier
                // R3 = working value, R4 = digit count, R5 = temp buffer offset
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R3, val_reg));
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

                // Extract up to 20 digits (covers full i64 range)
                for _ in 0..20 {
                    // Skip if R3 == 0
                    let done_offset = 8i16;
                    self.instructions
                        .push(EbpfInsn::jeq_imm(EbpfReg::R3, 0, done_offset));

                    // R0 = R3 % 10 (digit)
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R3));
                    self.instructions.push(EbpfInsn::mod64_imm(EbpfReg::R0, 10));

                    // Convert to ASCII: R0 += '0'
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R0, b'0' as i32));

                    // Store digit at temp position (we'll reverse later)
                    // For simplicity, store in reverse order directly
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(EbpfReg::R1, (dst_offset + 19) as i32));
                    self.instructions
                        .push(EbpfInsn::sub64_reg(EbpfReg::R1, EbpfReg::R4));
                    self.instructions
                        .push(EbpfInsn::stxb(EbpfReg::R1, 0, EbpfReg::R0));

                    // R3 = R3 / 10
                    self.instructions.push(EbpfInsn::div64_imm(EbpfReg::R3, 10));

                    // R4++ (digit count)
                    self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R4, 1));
                }

                // Copy digits from temp area to beginning (reverse order)
                // R4 now has the digit count
                self.instructions
                    .push(EbpfInsn::mov64_reg(len_reg, EbpfReg::R4));
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

    /// Emit binary operation with register operand
    fn emit_binop_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_reg(dst, rhs)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::sub64_reg(dst, rhs)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_reg(dst, rhs)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_reg(dst, rhs)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_reg(dst, rhs)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_reg(dst, rhs)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_reg(dst, rhs)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_reg(dst, rhs)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_reg(dst, rhs)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_reg(dst, rhs)),
            // Comparisons - set to 1, conditionally jump over setting to 0
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_reg(dst, op, rhs)?;
            }
        }
        Ok(())
    }

    /// Emit binary operation with immediate operand
    fn emit_binop_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_imm(dst, imm)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::add64_imm(dst, -imm)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_imm(dst, imm)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_imm(dst, imm)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_imm(dst, imm)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_imm(dst, imm)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_imm(dst, imm)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_imm(dst, imm)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_imm(dst, imm)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_imm(dst, imm)),
            // Comparisons
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_imm(dst, op, imm)?;
            }
        }
        Ok(())
    }

    /// Emit comparison with register, result in dst as 0 or 1
    fn emit_comparison_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
    ) -> Result<(), CompileError> {
        // Pattern: set dst to 1, then conditionally jump over setting to 0
        let tmp = EbpfReg::R0;
        self.instructions.push(EbpfInsn::mov64_reg(tmp, dst)); // Save LHS
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1)); // Assume true

        let jump_offset = 1i16; // Skip the next instruction

        // Build conditional jump instruction
        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_X,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_X,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_X,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_X,
            _ => unreachable!(),
        };

        self.instructions.push(EbpfInsn::new(
            jmp_opcode,
            tmp.as_u8(),
            rhs.as_u8(),
            jump_offset,
            0,
        ));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        Ok(())
    }

    /// Emit comparison with immediate, result in dst as 0 or 1
    fn emit_comparison_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
    ) -> Result<(), CompileError> {
        // Save original value
        let tmp = EbpfReg::R0;
        self.instructions.push(EbpfInsn::mov64_reg(tmp, dst));
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1)); // Assume true

        let jump_offset = 1i16;

        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_K,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_K,
            _ => unreachable!(),
        };

        self.instructions
            .push(EbpfInsn::new(jmp_opcode, tmp.as_u8(), 0, jump_offset, imm));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        Ok(())
    }

    fn slot_offset_i16(&self, slot: StackSlotId, offset: i32) -> Result<i16, CompileError> {
        let base = self.slot_offsets.get(&slot).copied().unwrap_or(0) as i32;
        let total = base + offset;
        i16::try_from(total).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "stack slot offset {} out of range",
                total
            ))
        })
    }

    fn value_to_reg(&mut self, value: &MirValue) -> Result<EbpfReg, CompileError> {
        match value {
            MirValue::VReg(v) => self.ensure_reg(*v),
            MirValue::Const(c) => {
                if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                    self.instructions
                        .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                } else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "constant {} too large for store",
                        c
                    )));
                }
                Ok(EbpfReg::R0)
            }
            MirValue::StackSlot(slot) => {
                let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R0, offset as i32));
                Ok(EbpfReg::R0)
            }
        }
    }

    fn emit_load(
        &mut self,
        dst: EbpfReg,
        base: EbpfReg,
        offset: i16,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self.instructions.push(EbpfInsn::ldxb(dst, base, offset)),
            2 => self.instructions.push(EbpfInsn::ldxh(dst, base, offset)),
            4 => self.instructions.push(EbpfInsn::ldxw(dst, base, offset)),
            8 => self.instructions.push(EbpfInsn::ldxdw(dst, base, offset)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "load size {} not supported",
                    size
                )));
            }
        }
        Ok(())
    }

    fn emit_store(
        &mut self,
        base: EbpfReg,
        offset: i16,
        src: EbpfReg,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self.instructions.push(EbpfInsn::stxb(base, offset, src)),
            2 => self.instructions.push(EbpfInsn::stxh(base, offset, src)),
            4 => self.instructions.push(EbpfInsn::stxw(base, offset, src)),
            8 => self.instructions.push(EbpfInsn::stxdw(base, offset, src)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "store size {} not supported",
                    size
                )));
            }
        }
        Ok(())
    }

    /// Compile context field load
    fn compile_load_ctx_field(
        &mut self,
        dst: EbpfReg,
        field: &CtxField,
        slot: Option<StackSlotId>,
    ) -> Result<(), CompileError> {
        match field {
            CtxField::Pid => {
                // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
                // Lower 32 bits = thread ID (what Linux calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                // Keep lower 32 bits, zero upper bits
                self.instructions.push(EbpfInsn::and32_imm(dst, -1));
            }
            CtxField::Tid => {
                // Upper 32 bits = thread group ID (what userspace calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Uid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                self.instructions.push(EbpfInsn::and32_imm(dst, -1));
            }
            CtxField::Gid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Timestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Cpu => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetSmpProcessorId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Comm => {
                let comm_offset = if let Some(slot) = slot {
                    *self.slot_offsets.get(&slot).ok_or_else(|| {
                        CompileError::UnsupportedInstruction("comm stack slot not found".into())
                    })?
                } else {
                    // Fallback: allocate temporary stack space if no slot was provided.
                    self.check_stack_space(16)?;
                    self.stack_offset -= 16;
                    self.stack_offset
                };

                // bpf_get_current_comm(buf, size)
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, comm_offset as i32));
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentComm));

                // Return pointer to comm on stack
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst, comm_offset as i32));
            }
            CtxField::Arg(n) => {
                let n = *n as usize;
                if n >= 6 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Argument index {} out of range",
                        n
                    )));
                }
                let offsets = KernelBtf::get().pt_regs_offsets().map_err(|e| {
                    CompileError::UnsupportedInstruction(format!(
                        "pt_regs argument access unavailable: {e}"
                    ))
                })?;
                let offset = offsets.arg_offsets[n];
                // R1 contains pointer to pt_regs on entry
                // We need to save it in R9 at start of function for later use
                // For now, assume R9 has the context pointer
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::RetVal => {
                if let Some(ctx) = self.probe_ctx
                    && !ctx.is_return_probe()
                {
                    return Err(CompileError::RetvalOnNonReturnProbe);
                }
                let offsets = KernelBtf::get().pt_regs_offsets().map_err(|e| {
                    CompileError::UnsupportedInstruction(format!(
                        "pt_regs return value access unavailable: {e}"
                    ))
                })?;
                let offset = offsets.retval_offset;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::KStack => {
                self.needs_kstack_map = true;
                self.compile_get_stackid(dst, KSTACK_MAP_NAME, false)?;
            }
            CtxField::UStack => {
                self.needs_ustack_map = true;
                self.compile_get_stackid(dst, USTACK_MAP_NAME, true)?;
            }
            CtxField::TracepointField(name) => {
                // Get tracepoint context from probe context
                let probe_ctx = self.probe_ctx.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Tracepoint field access requires probe context".into(),
                    )
                })?;

                let (category, tp_name) = probe_ctx.tracepoint_parts().ok_or_else(|| {
                    CompileError::TracepointContextError {
                        category: "unknown".into(),
                        name: probe_ctx.target.clone(),
                        reason: "Invalid tracepoint format. Expected 'category/name'".into(),
                    }
                })?;

                let btf = KernelBtf::get();
                let ctx = btf.get_tracepoint_context(category, tp_name).map_err(|e| {
                    CompileError::TracepointContextError {
                        category: category.into(),
                        name: tp_name.into(),
                        reason: e.to_string(),
                    }
                })?;

                // Look up the field in the tracepoint context
                let field_info =
                    ctx.get_field(name)
                        .ok_or_else(|| CompileError::TracepointFieldNotFound {
                            field: name.clone(),
                            available: ctx.field_names().join(", "),
                        })?;

                // Load the field from the context struct
                // R9 contains the saved context pointer (tracepoint context struct)
                let offset = field_info.offset as i16;

                // Choose load instruction based on field size
                match field_info.size {
                    1 => {
                        self.instructions
                            .push(EbpfInsn::ldxb(dst, EbpfReg::R9, offset));
                    }
                    2 => {
                        self.instructions
                            .push(EbpfInsn::ldxh(dst, EbpfReg::R9, offset));
                    }
                    4 => {
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
                    }
                    _ => {
                        // Default to 64-bit load for 8+ byte fields
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
                    }
                }
            }
        }
        Ok(())
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
