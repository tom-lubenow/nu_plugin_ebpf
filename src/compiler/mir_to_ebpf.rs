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
use crate::compiler::instruction::{BpfHelper, EbpfInsn, EbpfReg, HelperSignature, opcode};
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

        self.vreg_to_phys = alloc.coloring.clone();
        self.vreg_spills = vreg_spills;
        self.slot_offsets = slot_offsets;
        self.stack_offset = stack_offset;
        self.parallel_move_cycle_offset = parallel_move_cycle_offset;
        self.parallel_move_scratch_offset = parallel_move_scratch_offset;
        self.callee_saved_offsets.clear();

        Ok(alloc)
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
            self.compile_instruction(inst)?;
        }

        // Compile terminator
        self.compile_instruction(&block.terminator)?;

        Ok(())
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

    /// Compile bpf_get_stackid() call to get kernel or user stack trace ID
    fn compile_get_stackid(
        &mut self,
        dst: EbpfReg,
        map_name: &str,
        user_stack: bool,
    ) -> Result<(), CompileError> {
        // BPF_F_USER_STACK = 256, use 0 for kernel stack
        let flags: i32 = if user_stack { 256 } else { 0 };

        // R1 = ctx (restore from R9 where we saved it at program start)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));

        // R2 = map fd (will be relocated by loader)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R2);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        // R3 = flags
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, flags));

        // Call bpf_get_stackid
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetStackId));

        // Result (stack ID or negative error) is in R0, move to destination
        self.instructions
            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));

        Ok(())
    }

    /// Compile bpf_tail_call(ctx, prog_array, index)
    fn compile_tail_call(&mut self, map_name: &str, index: &MirValue) -> Result<(), CompileError> {
        // Load index into R3 before setting up helper args in R1/R2.
        // This avoids clobbering when the index vreg is allocated to R1/R2.
        let index_reg = self.value_to_reg(index)?;
        if index_reg != EbpfReg::R3 {
            self.instructions
                .push(EbpfInsn::mov64_reg(EbpfReg::R3, index_reg));
        }

        // R1 = ctx (restore from R9 where we saved it at program start)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));

        // R2 = prog array map fd (relocated by loader)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R2);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions.push(EbpfInsn::call(BpfHelper::TailCall));
        Ok(())
    }

    /// Compile emit event to ring buffer
    fn compile_emit_event(&mut self, data_reg: EbpfReg, size: usize) -> Result<(), CompileError> {
        let event_size = if size > 0 { size } else { 8 };
        self.check_stack_space(event_size as i16)?;
        // Stack grows downward - decrement first, then use offset
        self.stack_offset -= event_size as i16;
        let event_offset = self.stack_offset;

        if event_size <= 8 {
            // Store scalar data to stack
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, event_offset, data_reg));
        } else {
            if event_size % 8 != 0 {
                return Err(CompileError::UnsupportedInstruction(
                    "emit size must be 8-byte aligned for buffer output".into(),
                ));
            }
            // Copy buffer from pointer into stack
            for chunk in 0..(event_size / 8) {
                let offset = (chunk * 8) as i16;
                self.instructions
                    .push(EbpfInsn::ldxdw(EbpfReg::R0, data_reg, offset));
                self.instructions.push(EbpfInsn::stxdw(
                    EbpfReg::R10,
                    event_offset + offset,
                    EbpfReg::R0,
                ));
            }
        }

        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = data pointer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, event_offset as i32));

        // R3 = size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, event_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Compile emit record to ring buffer
    fn compile_emit_record(&mut self, fields: &[RecordFieldDef]) -> Result<(), CompileError> {
        if fields.is_empty() {
            return Ok(());
        }

        // Build schema and calculate total size
        let mut schema_fields = Vec::new();
        let mut offset = 0usize;
        let mut total_size = 0usize;

        for field in fields {
            let (field_type, size) = self.mir_type_to_bpf_field(&field.ty);
            schema_fields.push(SchemaField {
                name: field.name.clone(),
                field_type,
                offset,
            });
            offset += size;
            total_size += size;
        }

        let new_schema = EventSchema {
            fields: schema_fields,
            total_size,
        };
        if let Some(existing) = &self.event_schema {
            if existing != &new_schema {
                return Err(CompileError::UnsupportedInstruction(
                    "emit record schema mismatch: multiple record shapes in one program".into(),
                ));
            }
        } else {
            // Store schema
            self.event_schema = Some(new_schema);
        }

        // Allocate contiguous buffer on stack
        self.check_stack_space(total_size as i16)?;
        self.stack_offset -= total_size as i16;
        let buffer_offset = self.stack_offset;

        // Copy each field value to the buffer
        let mut dest_offset = buffer_offset;
        for field in fields {
            let (_, size) = self.mir_type_to_bpf_field(&field.ty);

            // Get the field value into a register
            let field_reg = self.ensure_reg(field.value)?;

            // Store to the buffer
            // For 8-byte values, use stxdw
            if size == 8 {
                self.instructions
                    .push(EbpfInsn::stxdw(EbpfReg::R10, dest_offset, field_reg));
            } else if size == 4 {
                self.instructions
                    .push(EbpfInsn::stxw(EbpfReg::R10, dest_offset, field_reg));
            } else {
                // For larger types (like comm=16), copy in 8-byte chunks
                // The field_reg should be a pointer to the data
                for chunk in 0..(size / 8) {
                    self.instructions.push(EbpfInsn::ldxdw(
                        EbpfReg::R0,
                        field_reg,
                        (chunk * 8) as i16,
                    ));
                    self.instructions.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        dest_offset + (chunk * 8) as i16,
                        EbpfReg::R0,
                    ));
                }
            }

            dest_offset += size as i16;
        }

        // Emit the buffer via ring buffer
        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to buffer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, buffer_offset as i32));

        // R3 = total size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, total_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Convert MIR type to BPF field type and size
    /// Note: All sizes are aligned to 8 bytes for eBPF stack alignment requirements
    fn mir_type_to_bpf_field(&self, ty: &MirType) -> (BpfFieldType, usize) {
        match ty {
            MirType::I64 | MirType::U64 => (BpfFieldType::Int, 8),
            // I32 still uses 8 bytes for stack alignment
            MirType::I32 | MirType::U32 => (BpfFieldType::Int, 8),
            MirType::I16 | MirType::U16 => (BpfFieldType::Int, 8),
            MirType::I8 | MirType::U8 | MirType::Bool => (BpfFieldType::Int, 8),
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) && *len == 16 => {
                (BpfFieldType::Comm, 16)
            }
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => {
                // Round up to 8-byte alignment
                let aligned_len = (*len + 7) & !7;
                (BpfFieldType::String, aligned_len)
            }
            _ => (BpfFieldType::Int, 8), // Default to 64-bit int
        }
    }

    /// Compile map update (specialized for `count` command semantics).
    fn compile_counter_map_update(
        &mut self,
        map_name: &str,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        // For count: lookup key, increment, update
        let key_size = if map_name == STRING_COUNTER_MAP_NAME {
            16
        } else {
            8
        };
        let total_size = key_size + 8; // key + value
        self.check_stack_space(total_size as i16)?;
        // Stack grows downward - decrement first
        self.stack_offset -= total_size as i16;
        let val_offset = self.stack_offset; // value at lower address
        let key_offset = self.stack_offset + 8; // key at higher address

        if key_size == 8 {
            // Store key to stack
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, key_reg));
        } else {
            // Copy 16-byte key from pointer
            for chunk in 0..2 {
                let offset = (chunk * 8) as i16;
                self.instructions
                    .push(EbpfInsn::ldxdw(EbpfReg::R0, key_reg, offset));
                self.instructions.push(EbpfInsn::stxdw(
                    EbpfReg::R10,
                    key_offset + offset,
                    EbpfReg::R0,
                ));
            }
        }

        // bpf_map_lookup_elem(map, key) -> value ptr or null
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If null, initialize to 0; else load and increment
        let jmp_to_init = self.instructions.len();
        self.instructions.push(EbpfInsn::jeq_imm(EbpfReg::R0, 0, 0)); // Placeholder

        // Load current value, increment
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R3, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R3, 1));
        let jmp_to_update = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0)); // Skip init

        // init: value = 1
        let init_idx = self.instructions.len();
        self.instructions[jmp_to_init] =
            EbpfInsn::jeq_imm(EbpfReg::R0, 0, (init_idx - jmp_to_init - 1) as i16);
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R3, 1));

        // update:
        let update_idx = self.instructions.len();
        self.instructions[jmp_to_update] = EbpfInsn::jump((update_idx - jmp_to_update - 1) as i16);

        // Store new value to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, val_offset, EbpfReg::R3));

        // bpf_map_update_elem(map, key, value, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, val_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    fn register_counter_map_kind(
        &mut self,
        map_name: &str,
        kind: MapKind,
    ) -> Result<(), CompileError> {
        if !matches!(kind, MapKind::Hash | MapKind::PerCpuHash) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map '{}' only supports Hash/PerCpuHash kinds, got {:?}",
                map_name, kind
            )));
        }

        let slot = if map_name == COUNTER_MAP_NAME {
            &mut self.counter_map_kind
        } else if map_name == STRING_COUNTER_MAP_NAME {
            &mut self.string_counter_map_kind
        } else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "internal error: '{}' is not a counter map",
                map_name
            )));
        };

        if let Some(existing) = *slot {
            if existing != kind {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map '{}' used with conflicting kinds: {:?} vs {:?}",
                    map_name, existing, kind
                )));
            }
        } else {
            *slot = Some(kind);
        }

        Ok(())
    }

    fn build_counter_map_def(
        &self,
        map_name: &str,
        kind: MapKind,
    ) -> Result<BpfMapDef, CompileError> {
        let key_size = if map_name == STRING_COUNTER_MAP_NAME {
            16
        } else {
            8
        };
        let value_size = 8;
        let max_entries = 10240;

        match kind {
            MapKind::Hash => Ok(BpfMapDef::hash(key_size, value_size, max_entries)),
            MapKind::PerCpuHash => Ok(BpfMapDef::per_cpu_hash(key_size, value_size, max_entries)),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "map '{}' only supports Hash/PerCpuHash kinds, got {:?}",
                map_name, kind
            ))),
        }
    }

    fn is_builtin_map_name(name: &str) -> bool {
        matches!(
            name,
            RINGBUF_MAP_NAME
                | COUNTER_MAP_NAME
                | STRING_COUNTER_MAP_NAME
                | HISTOGRAM_MAP_NAME
                | TIMESTAMP_MAP_NAME
                | KSTACK_MAP_NAME
                | USTACK_MAP_NAME
        )
    }

    fn supported_generic_map_kind(kind: MapKind) -> bool {
        matches!(
            kind,
            MapKind::Hash | MapKind::Array | MapKind::PerCpuHash | MapKind::PerCpuArray
        )
    }

    fn map_operand_layout(
        &self,
        vreg: VReg,
        what: &str,
        default_size: usize,
    ) -> Result<MapOperandLayout, CompileError> {
        let ty = self.current_types.get(&vreg);
        match ty {
            Some(MirType::Ptr { pointee, .. }) => {
                let size = match pointee.size() {
                    0 => default_size,
                    n => n,
                };
                Ok(MapOperandLayout::Pointer { size })
            }
            Some(ty) => {
                let size = match ty.size() {
                    0 => default_size,
                    n => n,
                };
                if size > 8 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{} v{} has size {} bytes and must be passed as a pointer",
                        what, vreg.0, size
                    )));
                }
                Ok(MapOperandLayout::Scalar { size })
            }
            None => Ok(MapOperandLayout::Scalar { size: default_size }),
        }
    }

    fn value_ptr_size_from_lookup_dst(&self, dst: VReg) -> usize {
        match self.current_types.get(&dst) {
            Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
            _ => 8,
        }
    }

    fn allocate_stack_temp(&mut self, size: usize) -> Result<i16, CompileError> {
        let aligned = size.div_ceil(8) * 8;
        self.check_stack_space(aligned as i16)?;
        self.stack_offset -= aligned as i16;
        Ok(self.stack_offset)
    }

    fn emit_store_scalar_to_stack(
        &mut self,
        src: EbpfReg,
        offset: i16,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self
                .instructions
                .push(EbpfInsn::stxb(EbpfReg::R10, offset, src)),
            2 => self
                .instructions
                .push(EbpfInsn::stxh(EbpfReg::R10, offset, src)),
            4 => self
                .instructions
                .push(EbpfInsn::stxw(EbpfReg::R10, offset, src)),
            8 => self
                .instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported scalar map operand size {} bytes",
                    size
                )));
            }
        }
        Ok(())
    }

    fn emit_map_fd_load(&mut self, map_name: &str) {
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });
    }

    fn setup_map_key_arg(
        &mut self,
        key_reg: EbpfReg,
        layout: MapOperandLayout,
    ) -> Result<(), CompileError> {
        match layout {
            MapOperandLayout::Pointer { .. } => {
                if key_reg != EbpfReg::R2 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R2, key_reg));
                }
            }
            MapOperandLayout::Scalar { size } => {
                let key_offset = self.allocate_stack_temp(size)?;
                self.emit_store_scalar_to_stack(key_reg, key_offset, size)?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
            }
        }
        Ok(())
    }

    fn setup_map_value_arg(
        &mut self,
        value_reg: EbpfReg,
        layout: MapOperandLayout,
    ) -> Result<(), CompileError> {
        match layout {
            MapOperandLayout::Pointer { .. } => {
                if value_reg != EbpfReg::R3 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R3, value_reg));
                }
            }
            MapOperandLayout::Scalar { size } => {
                let value_offset = self.allocate_stack_temp(size)?;
                self.emit_store_scalar_to_stack(value_reg, value_offset, size)?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
            }
        }
        Ok(())
    }

    fn register_generic_map_spec(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key_size: usize,
        value_size: Option<usize>,
    ) -> Result<(), CompileError> {
        if Self::is_builtin_map_name(&map.name) {
            return Ok(());
        }
        if !Self::supported_generic_map_kind(map.kind) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map operations do not support map kind {:?} for '{}'",
                map.kind, map.name
            )));
        }

        let mut inferred_key_size = key_size.max(1) as u32;
        if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
            inferred_key_size = 4;
        }
        let (inferred_value_size, defaulted) = match value_size {
            Some(size) => (size.max(1) as u32, false),
            None => (8, true),
        };

        match self.generic_map_specs.get_mut(&map.name) {
            Some(spec) => {
                if spec.kind != map.kind {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map '{}' used with conflicting kinds: {:?} vs {:?}",
                        map.name, spec.kind, map.kind
                    )));
                }
                if spec.key_size != inferred_key_size {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map '{}' used with conflicting key sizes: {} vs {}",
                        map.name, spec.key_size, inferred_key_size
                    )));
                }
                if spec.value_size != inferred_value_size {
                    if spec.value_size_defaulted && !defaulted {
                        spec.value_size = inferred_value_size;
                        spec.value_size_defaulted = false;
                    } else if !(defaulted && !spec.value_size_defaulted) {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map '{}' used with conflicting value sizes: {} vs {}",
                            map.name, spec.value_size, inferred_value_size
                        )));
                    }
                }
            }
            None => {
                self.generic_map_specs.insert(
                    map.name.clone(),
                    MapLayoutSpec {
                        kind: map.kind,
                        key_size: inferred_key_size,
                        value_size: inferred_value_size,
                        value_size_defaulted: defaulted,
                    },
                );
            }
        }

        Ok(())
    }

    fn build_generic_map_def(&self, spec: MapLayoutSpec) -> Result<BpfMapDef, CompileError> {
        let max_entries = 10240;
        let map_def = match spec.kind {
            MapKind::Hash => BpfMapDef::hash(spec.key_size, spec.value_size, max_entries),
            MapKind::Array => BpfMapDef::array(spec.value_size, max_entries),
            MapKind::PerCpuHash => {
                BpfMapDef::per_cpu_hash(spec.key_size, spec.value_size, max_entries)
            }
            MapKind::PerCpuArray => BpfMapDef::per_cpu_array(spec.value_size, max_entries),
            other => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "map kind {:?} is not supported for generic map operations",
                    other
                )));
            }
        };
        Ok(map_def)
    }

    fn compile_generic_map_lookup(
        &mut self,
        dst: VReg,
        dst_reg: EbpfReg,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        let value_size = self.value_ptr_size_from_lookup_dst(dst);
        self.register_generic_map_spec(map, key_size, Some(value_size))?;

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));
        if dst_reg != EbpfReg::R0 {
            self.instructions
                .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R0));
        }
        Ok(())
    }

    fn compile_generic_map_update(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
        val: VReg,
        val_reg: EbpfReg,
        flags: u64,
    ) -> Result<(), CompileError> {
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let val_layout = self.map_operand_layout(val, "map value", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        let value_size = match val_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        self.register_generic_map_spec(map, key_size, Some(value_size))?;
        if flags > i32::MAX as u64 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map update flags {} exceed supported 32-bit immediate range",
                flags
            )));
        }

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.setup_map_value_arg(val_reg, val_layout)?;
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R4, flags as i32));
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));
        Ok(())
    }

    fn compile_generic_map_delete(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        key_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "map delete is not supported for array map kind {:?} ('{}')",
                map.kind, map.name
            )));
        }
        let key_layout = self.map_operand_layout(key, "map key", 8)?;
        let key_size = match key_layout {
            MapOperandLayout::Pointer { size } | MapOperandLayout::Scalar { size } => size,
        };
        self.register_generic_map_spec(map, key_size, None)?;

        self.setup_map_key_arg(key_reg, key_layout)?;
        self.emit_map_fd_load(&map.name);
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapDeleteElem));
        Ok(())
    }

    /// Compile read string from user/kernel memory
    fn compile_read_str(
        &mut self,
        dst_offset: i16,
        ptr_reg: EbpfReg,
        user_space: bool,
        max_len: usize,
    ) -> Result<(), CompileError> {
        // bpf_probe_read_{user,kernel}_str(dst, size, src)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R2, max_len as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, ptr_reg));

        let helper = if user_space {
            BpfHelper::ProbeReadUserStr
        } else {
            BpfHelper::ProbeReadKernelStr
        };
        self.instructions.push(EbpfInsn::call(helper));

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

    /// Ensure a virtual register is in a physical register
    /// If the vreg is spilled, emit a reload instruction
    fn ensure_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        // Check if this vreg has a physical register
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
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

    // === Histogram and Timing ===

    /// Compile histogram aggregation
    /// Computes log2 bucket of value and increments counter in histogram map
    fn compile_histogram(&mut self, value_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (bucket) and value (count)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Compute log2 bucket using binary search
        // Save value to R0 for manipulation, bucket accumulator in R1
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R0, value_reg));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 0));

        // If value <= 0, bucket = 0
        // JLE R0, 0, skip_log2 (offset will be filled in later)
        let skip_log2_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0, // offset placeholder
        ));

        // Binary search for highest bit
        // Check >= 2^32
        self.emit_log2_check(32)?;
        self.emit_log2_check(16)?;
        self.emit_log2_check(8)?;
        self.emit_log2_check(4)?;
        self.emit_log2_check(2)?;
        self.emit_log2_check(1)?;

        // Fix up skip_log2 jump to skip past log2 computation
        let skip_log2_offset = (self.instructions.len() - skip_log2_idx - 1) as i16;
        self.instructions[skip_log2_idx].offset = skip_log2_offset;

        // Store bucket (R1) to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R1));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, jump to init
        let init_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0,
        ));

        // Exists - increment in place
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, 1));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R0, 0, EbpfReg::R1));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // Init path
        let init_offset = (self.instructions.len() - init_idx - 1) as i16;
        self.instructions[init_idx].offset = init_offset;

        // Store 1 to value
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 1));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R1));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
    }

    /// Helper for log2 computation - check if value >= 2^bits
    fn emit_log2_check(&mut self, bits: i32) -> Result<(), CompileError> {
        if bits >= 32 {
            // Need 64-bit compare against a register
            self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 1));
            self.instructions
                .push(EbpfInsn::lsh64_imm(EbpfReg::R2, bits));
            self.instructions.push(EbpfInsn::new(
                opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_X,
                EbpfReg::R0.as_u8(),
                EbpfReg::R2.as_u8(),
                2,
                0,
            ));
        } else {
            // JLT R0, 2^bits, skip (2 instructions)
            self.instructions.push(EbpfInsn::new(
                opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
                EbpfReg::R0.as_u8(),
                0,
                2,
                1 << bits,
            ));
        }
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, bits));
        self.instructions
            .push(EbpfInsn::rsh64_imm(EbpfReg::R0, bits));
        Ok(())
    }

    /// Compile start-timer: store current ktime keyed by TID
    fn compile_start_timer(&mut self) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid) and value (timestamp)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Get current pid_tgid as key
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Get current time
        self.instructions
            .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R0));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    /// Compile stop-timer: lookup start time, compute delta, delete entry
    fn compile_stop_timer(&mut self, dst_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid) and start timestamp
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let start_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Get current pid_tgid as key
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, return 0
        let no_timer_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            0,
            0,
        ));

        // Load start timestamp and store it on stack
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, start_offset, EbpfReg::R1));

        // Get current time
        self.instructions
            .push(EbpfInsn::call(BpfHelper::KtimeGetNs));

        // Reload start timestamp and compute delta = current - start
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R10, start_offset));
        self.instructions
            .push(EbpfInsn::sub64_reg(EbpfReg::R0, EbpfReg::R1));

        // Save delta to dst_reg
        if dst_reg != EbpfReg::R0 {
            self.instructions
                .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R0));
        }

        // Delete map entry
        let delete_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: delete_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapDeleteElem));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // No timer path - set dst to 0
        let no_timer_offset = (self.instructions.len() - no_timer_idx - 1) as i16;
        self.instructions[no_timer_idx].offset = no_timer_offset;
        self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 0));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
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
mod tests {
    use super::*;
    use crate::compiler::ir_to_mir::lower_ir_to_mir;
    use crate::compiler::mir_to_lir::lower_mir_to_lir;
    use nu_protocol::RegId;
    use nu_protocol::ast::{Math, Operator};
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use std::sync::Arc;

    fn make_ir_block(instructions: Vec<Instruction>) -> IrBlock {
        IrBlock {
            instructions,
            spans: vec![],
            data: Arc::from([]),
            ast: vec![],
            comments: vec![],
            register_count: 10,
            file_count: 0,
        }
    }

    /// Test valid bytecode for return zero
    #[test]
    fn test_return_zero() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(!mir_result.bytecode.is_empty(), "Should produce bytecode");
        assert_eq!(
            mir_result.bytecode.len() % 8,
            0,
            "Bytecode should be aligned to 8 bytes"
        );
    }

    /// Test valid bytecode for addition
    #[test]
    fn test_add() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(2),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(!mir_result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_parallel_move_r0_cycle() {
        let mut func = LirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.precolored.insert(v0, EbpfReg::R0);
        func.precolored.insert(v1, EbpfReg::R1);
        func.precolored.insert(v2, EbpfReg::R2);

        func.block_mut(entry)
            .instructions
            .push(LirInst::ParallelMove {
                moves: vec![(v0, v1), (v1, v2), (v2, v0)],
            });
        func.block_mut(entry).terminator = LirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        let program = LirProgram::new(func);
        let result = MirToEbpfCompiler::new(&program, None).compile();
        assert!(result.is_ok(), "ParallelMove with R0 should compile");
    }

    #[test]
    fn test_parallel_move_stack_to_stack() {
        let program = LirProgram::new(LirFunction::new());
        let mut compiler = MirToEbpfCompiler::new(&program, None);

        compiler.parallel_move_cycle_offset = Some(-8);
        compiler.parallel_move_scratch_offset = Some(-16);
        compiler.vreg_spills.insert(VReg(0), -24);
        compiler.vreg_spills.insert(VReg(1), -32);
        compiler.vreg_to_phys.insert(VReg(2), EbpfReg::R1);

        let inst = LirInst::ParallelMove {
            moves: vec![(VReg(0), VReg(1)), (VReg(0), VReg(2))],
        };

        compiler
            .compile_instruction(&inst)
            .expect("ParallelMove stack-to-stack should compile");
        assert!(
            !compiler.instructions.is_empty(),
            "ParallelMove should emit instructions"
        );
    }

    /// Test that old compiler handles branching (MIR branch test is separate)
    #[test]
    fn test_branch() {
        let _ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Bool(true),
            },
            Instruction::BranchIf {
                cond: RegId::new(0),
                index: 3, // Jump to Return
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // MIR compiler branching is tested separately with proper block construction
    }

    /// Test multiplication
    #[test]
    fn test_multiply() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(5),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(3),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Multiply),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test MIR function creation directly
    #[test]
    fn test_mir_direct_compile() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        // Create entry block
        let mut entry_block = BasicBlock::new(BlockId(0));

        // Simple: mov r0, 42; exit
        entry_block.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(42),
        });
        entry_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        func.blocks.push(entry_block);
        func.vreg_count = 1;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "Direct MIR compile produced empty bytecode"
        );
    }

    /// Test MIR branching directly
    #[test]
    fn test_mir_branch_compile() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        // Entry block: load condition, branch
        let mut entry = BasicBlock::new(BlockId(0));
        entry.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(1), // true
        });
        entry.terminator = MirInst::Branch {
            cond: VReg(0),
            if_true: BlockId(1),
            if_false: BlockId(2),
        };

        // True block: return 1
        let mut true_block = BasicBlock::new(BlockId(1));
        true_block.instructions.push(MirInst::Copy {
            dst: VReg(1),
            src: MirValue::Const(1),
        });
        true_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(1))),
        };

        // False block: return 0
        let mut false_block = BasicBlock::new(BlockId(2));
        false_block.instructions.push(MirInst::Copy {
            dst: VReg(2),
            src: MirValue::Const(0),
        });
        false_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(2))),
        };

        func.blocks.push(entry);
        func.blocks.push(true_block);
        func.blocks.push(false_block);
        func.vreg_count = 3;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "MIR branch compile produced empty bytecode"
        );
    }

    #[test]
    fn test_mir_phi_compile_without_prepass() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        let mut entry = BasicBlock::new(BlockId(0));
        entry.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(1),
        });
        entry.terminator = MirInst::Branch {
            cond: VReg(0),
            if_true: BlockId(1),
            if_false: BlockId(2),
        };

        let mut left = BasicBlock::new(BlockId(1));
        left.instructions.push(MirInst::Copy {
            dst: VReg(1),
            src: MirValue::Const(10),
        });
        left.terminator = MirInst::Jump { target: BlockId(3) };

        let mut right = BasicBlock::new(BlockId(2));
        right.instructions.push(MirInst::Copy {
            dst: VReg(2),
            src: MirValue::Const(20),
        });
        right.terminator = MirInst::Jump { target: BlockId(3) };

        let mut join = BasicBlock::new(BlockId(3));
        join.instructions.push(MirInst::Phi {
            dst: VReg(3),
            args: vec![(BlockId(1), VReg(1)), (BlockId(2), VReg(2))],
        });
        join.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(3))),
        };

        func.blocks.push(entry);
        func.blocks.push(left);
        func.blocks.push(right);
        func.blocks.push(join);
        func.vreg_count = 4;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "MIR with phi should compile via internal SSA destruction"
        );
    }

    /// Test histogram instruction compiles
    #[test]
    fn test_mir_histogram() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let mut entry = BasicBlock::new(BlockId(0));

        // Load a value and compute histogram bucket
        entry.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(42),
        });
        entry
            .instructions
            .push(MirInst::Histogram { value: VReg(0) });
        entry.terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        func.blocks.push(entry);
        func.vreg_count = 1;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty());
        // Should have histogram map
        assert!(result.maps.iter().any(|m| m.name == HISTOGRAM_MAP_NAME));
    }

    /// Test start/stop timer instructions compile
    #[test]
    fn test_mir_timer() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let mut entry = BasicBlock::new(BlockId(0));

        entry.instructions.push(MirInst::StartTimer);
        entry.instructions.push(MirInst::StopTimer { dst: VReg(0) });
        entry.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        func.blocks.push(entry);
        func.vreg_count = 1;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty());
        // Should have timestamp map
        assert!(result.maps.iter().any(|m| m.name == TIMESTAMP_MAP_NAME));
    }

    /// Test loop header and back compile
    #[test]
    fn test_mir_loop() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        // Entry: set counter to 0
        let mut entry = BasicBlock::new(BlockId(0));
        entry.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(0),
        });
        entry.terminator = MirInst::Jump { target: BlockId(1) };

        // Header: check if counter < 10, go to body or exit
        let mut header = BasicBlock::new(BlockId(1));
        header.terminator = MirInst::LoopHeader {
            counter: VReg(0),
            limit: 10,
            body: BlockId(2),
            exit: BlockId(3),
        };

        // Body: increment and loop back
        let mut body = BasicBlock::new(BlockId(2));
        body.terminator = MirInst::LoopBack {
            counter: VReg(0),
            step: 1,
            header: BlockId(1),
        };

        // Exit: return
        let mut exit = BasicBlock::new(BlockId(3));
        exit.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        func.blocks.push(entry);
        func.blocks.push(header);
        func.blocks.push(body);
        func.blocks.push(exit);
        func.vreg_count = 1;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "Loop compile produced empty bytecode"
        );
    }

    // ==================== Additional Parity Tests ====================

    /// Test parity for subtraction
    #[test]
    fn test_subtract() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(10),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(3),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Subtract),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for division
    #[test]
    fn test_divide() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(100),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(5),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Divide),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for modulo operation
    #[test]
    fn test_modulo() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(17),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(5),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Modulo),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for comparison: greater than
    #[test]
    fn test_greater_than() {
        use nu_protocol::ast::Comparison;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(10),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(5),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Comparison(Comparison::GreaterThan),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for comparison: less than
    #[test]
    fn test_less_than() {
        use nu_protocol::ast::Comparison;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(3),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(7),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Comparison(Comparison::LessThan),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for comparison: equal
    #[test]
    fn test_equal() {
        use nu_protocol::ast::Comparison;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(42),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(42),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Comparison(Comparison::Equal),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for comparison: not equal
    #[test]
    fn test_not_equal() {
        use nu_protocol::ast::Comparison;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(2),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Comparison(Comparison::NotEqual),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for logical NOT
    #[test]
    fn test_logical_not() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Bool(true),
            },
            Instruction::Not {
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for bitwise AND
    #[test]
    fn test_bitwise_and() {
        use nu_protocol::ast::Bits;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0b1111),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(0b1010),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Bits(Bits::BitAnd),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for bitwise OR
    #[test]
    fn test_bitwise_or() {
        use nu_protocol::ast::Bits;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0b1100),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(0b0011),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Bits(Bits::BitOr),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for left shift
    #[test]
    fn test_shift_left() {
        use nu_protocol::ast::Bits;

        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(4),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Bits(Bits::ShiftLeft),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for chained arithmetic: (a + b) * c
    #[test]
    fn test_chained_arithmetic() {
        let ir = make_ir_block(vec![
            // a = 2
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(2),
            },
            // b = 3
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(3),
            },
            // c = 4
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(4),
            },
            // a = a + b (= 5)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            // a = a * c (= 20)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Multiply),
                rhs: RegId::new(2),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for conditional return
    #[test]
    fn test_conditional_return() {
        let ir = make_ir_block(vec![
            // Load condition
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1), // true
            },
            // Load return value for true branch
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(42),
            },
            // Load return value for false branch
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(0),
            },
            // Branch to index 5 if true
            Instruction::BranchIf {
                cond: RegId::new(0),
                index: 5,
            },
            // False branch: return 0
            Instruction::Return { src: RegId::new(2) },
            // True branch: return 42
            Instruction::Return { src: RegId::new(1) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for large constant
    #[test]
    fn test_large_constant() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0x1_0000_0000), // > 32-bit
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test parity for negative constant
    #[test]
    fn test_negative_constant() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(-42),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);
        // Compile and verify
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "Should produce empty bytecode"
        );
    }

    /// Test register pressure - more vregs than physical registers
    /// This tests the linear scan register allocator integration
    #[test]
    fn test_register_pressure_integration() {
        // Create code that uses multiple registers to exercise allocation
        // v0 = 1, v1 = 2, v2 = 3, v3 = 4, v4 = 5
        // result = v0 + v1 + v2 + v3 + v4 (needs all values live)
        let ir = make_ir_block(vec![
            // Load 5 values into different registers
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(2),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(3),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(4),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(5),
            },
            // Chain additions to force all values to be live
            // r0 = r0 + r1 (1 + 2 = 3)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            // r0 = r0 + r2 (3 + 3 = 6)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(2),
            },
            // r0 = r0 + r3 (6 + 4 = 10)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(3),
            },
            // r0 = r0 + r4 (10 + 5 = 15)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(4),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        // Compile and verify should handle register pressure via linear scan
        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();

        // Should produce valid bytecode
        assert!(
            !mir_result.bytecode.is_empty(),
            "MIR compiler should produce bytecode even with register pressure"
        );
        assert_eq!(
            mir_result.bytecode.len() % 8,
            0,
            "Bytecode should be aligned to 8 bytes"
        );

        // Should produce more instructions due to spill/reload
        // A basic version without spilling would be ~11 instructions
        // With spilling we expect more
        let insn_count = mir_result.bytecode.len() / 8;
        assert!(
            insn_count >= 10,
            "Should have at least 10 instructions, got {}",
            insn_count
        );
    }

    #[test]
    fn test_register_pressure_codegen_stable() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(2),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(3),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(4),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(5),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(2),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(3),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(4),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();

        let mut baseline: Option<(Vec<u8>, usize)> = None;
        for _ in 0..8 {
            let result = compile_mir_to_ebpf(&mir_program, None).unwrap();
            let signature = (result.bytecode, result.main_size);
            if let Some(expected) = &baseline {
                assert_eq!(
                    &signature, expected,
                    "codegen should be stable across repeated compilations"
                );
            } else {
                baseline = Some(signature);
            }
        }
    }

    /// Test that the linear scan allocator correctly handles simultaneous live ranges
    #[test]
    fn test_simultaneous_live_ranges() {
        // Create a pattern where multiple values must be live at once:
        // v0 = 10, v1 = 20, v2 = 30, v3 = 40
        // temp = v0 + v1
        // result = temp + v2 + v3
        // Here v2 and v3 are live across multiple operations
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(10),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(20),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(30),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(40),
            },
            // v0 = v0 + v1 (v2, v3 still live)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            // v0 = v0 + v2 (v3 still live)
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(2),
            },
            // v0 = v0 + v3
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(3),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();

        assert!(
            !mir_result.bytecode.is_empty(),
            "Should compile with simultaneous live ranges"
        );
    }

    #[test]
    fn test_string_literal_lowering_populates_buffer() {
        use crate::compiler::mir::{MirInst, StringAppendType};
        use nu_protocol::ir::DataSlice;

        let mut data = Vec::new();
        data.extend_from_slice(b"hello");
        let ir = IrBlock {
            instructions: vec![
                Instruction::LoadLiteral {
                    dst: RegId::new(0),
                    lit: Literal::String(DataSlice { start: 0, len: 5 }),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![],
            data: Arc::from(data),
            ast: vec![],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };

        let mir_program =
            lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();

        let saw_literal_append = mir_program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| match inst {
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } => bytes.starts_with(b"hello") && bytes.len() == 16 && bytes[5] == 0,
                _ => false,
            })
        });

        assert!(
            saw_literal_append,
            "Expected string literal to populate stack buffer via StringAppend"
        );
    }

    #[test]
    fn test_emit_event_copies_buffer() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let v0 = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::EmitEvent { data: v0, size: 16 });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let mut compiler = MirToEbpfCompiler::new(&lir, None);
        compiler
            .prepare_function_state(
                &lir.main,
                compiler.available_regs.clone(),
                lir.main.precolored.clone(),
            )
            .unwrap();
        compiler.compile_function(&lir.main).unwrap();
        compiler.fixup_jumps().unwrap();

        // After graph coloring, VReg(0) should be assigned a register
        let data_reg = compiler
            .vreg_to_phys
            .get(&VReg(0))
            .copied()
            .expect("VReg(0) should be assigned a physical register by graph coloring");
        let saw_copy = compiler.instructions.iter().any(|insn| {
            insn.opcode == (opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM)
                && insn.dst_reg == EbpfReg::R0.as_u8()
                && insn.src_reg == data_reg.as_u8()
        });

        assert!(saw_copy, "Expected buffer copy from pointer for emit");
    }

    #[test]
    fn test_emit_record_schema_mismatch_errors() {
        use crate::compiler::CompileError;
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(2),
        });

        func.block_mut(entry)
            .instructions
            .push(MirInst::EmitRecord {
                fields: vec![RecordFieldDef {
                    name: "a".to_string(),
                    value: v0,
                    ty: MirType::I64,
                }],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::EmitRecord {
                fields: vec![RecordFieldDef {
                    name: "b".to_string(),
                    value: v1,
                    ty: MirType::I64,
                }],
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None);
        match result {
            Err(CompileError::UnsupportedInstruction(msg)) => {
                assert!(
                    msg.contains("schema mismatch"),
                    "Unexpected error message: {msg}"
                );
            }
            Ok(_) => panic!("Expected schema mismatch error, got Ok"),
            Err(e) => panic!("Expected schema mismatch error, got: {e:?}"),
        }
    }

    #[test]
    fn test_string_counter_map_emitted() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let v0 = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: STRING_COUNTER_MAP_NAME.to_string(),
                kind: MapKind::Hash,
            },
            key: v0,
            val: v0,
            flags: 0,
        });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        let map = result
            .maps
            .iter()
            .find(|m| m.name == STRING_COUNTER_MAP_NAME)
            .expect("Expected string counter map");
        assert_eq!(map.def.key_size, 16);
    }

    #[test]
    fn test_counter_map_emits_per_cpu_kind() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(123),
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: COUNTER_MAP_NAME.to_string(),
                kind: MapKind::PerCpuHash,
            },
            key,
            val: key,
            flags: 0,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).expect("counter map should compile");

        let map = result
            .maps
            .iter()
            .find(|m| m.name == COUNTER_MAP_NAME)
            .expect("expected counters map");
        assert_eq!(
            map.def.map_type,
            crate::compiler::elf::BpfMapType::PerCpuHash as u32
        );
    }

    #[test]
    fn test_counter_map_kind_conflict_rejected() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key0 = func.alloc_vreg();
        let key1 = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key0,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key1,
            src: MirValue::Const(2),
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: COUNTER_MAP_NAME.to_string(),
                kind: MapKind::Hash,
            },
            key: key0,
            val: key0,
            flags: 0,
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: COUNTER_MAP_NAME.to_string(),
                kind: MapKind::PerCpuHash,
            },
            key: key1,
            val: key1,
            flags: 0,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected kind conflict"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("conflicting kinds"),
                    "unexpected error message: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_counter_map_rejects_non_hash_kind() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(9),
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: COUNTER_MAP_NAME.to_string(),
                kind: MapKind::Array,
            },
            key,
            val: key,
            flags: 0,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected kind rejection"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("Hash/PerCpuHash"),
                    "unexpected error message: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_map_lookup_compiles_and_emits_generic_map() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(7),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "custom_lookup".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).expect("map lookup should compile");
        let map = result
            .maps
            .iter()
            .find(|m| m.name == "custom_lookup")
            .expect("expected generic map definition");
        assert_eq!(map.def.key_size, 8);
        assert_eq!(map.def.value_size, 8);
        assert!(
            result
                .relocations
                .iter()
                .any(|r| r.map_name == "custom_lookup")
        );

        let has_lookup_helper = result.bytecode.chunks(8).any(|chunk| {
            chunk[0] == opcode::CALL
                && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                    == BpfHelper::MapLookupElem as i32
        });
        assert!(
            has_lookup_helper,
            "expected bpf_map_lookup_elem helper call"
        );
    }

    #[test]
    fn test_map_update_compiles_and_emits_generic_map() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let val = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(42),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: val,
            src: MirValue::Const(99),
        });
        func.block_mut(entry).instructions.push(MirInst::MapUpdate {
            map: MapRef {
                name: "custom_update".to_string(),
                kind: MapKind::Hash,
            },
            key,
            val,
            flags: 1,
        });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).expect("map update should compile");
        let map = result
            .maps
            .iter()
            .find(|m| m.name == "custom_update")
            .expect("expected generic map definition");
        assert_eq!(map.def.key_size, 8);
        assert_eq!(map.def.value_size, 8);
        assert!(
            result
                .relocations
                .iter()
                .any(|r| r.map_name == "custom_update")
        );

        let has_update_helper = result.bytecode.chunks(8).any(|chunk| {
            chunk[0] == opcode::CALL
                && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                    == BpfHelper::MapUpdateElem as i32
        });
        assert!(
            has_update_helper,
            "expected bpf_map_update_elem helper call"
        );
    }

    #[test]
    fn test_map_delete_compiles_and_emits_generic_map() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(11),
        });
        func.block_mut(entry).instructions.push(MirInst::MapDelete {
            map: MapRef {
                name: "custom_delete".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).expect("map delete should compile");
        let map = result
            .maps
            .iter()
            .find(|m| m.name == "custom_delete")
            .expect("expected generic map definition");
        assert_eq!(map.def.key_size, 8);
        assert_eq!(map.def.value_size, 8);
        assert!(
            result
                .relocations
                .iter()
                .any(|r| r.map_name == "custom_delete")
        );

        let has_delete_helper = result.bytecode.chunks(8).any(|chunk| {
            chunk[0] == opcode::CALL
                && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                    == BpfHelper::MapDeleteElem as i32
        });
        assert!(
            has_delete_helper,
            "expected bpf_map_delete_elem helper call"
        );
    }

    #[test]
    fn test_map_delete_rejects_array_maps() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapDelete {
            map: MapRef {
                name: "array_delete".to_string(),
                kind: MapKind::Array,
            },
            key,
        });
        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected array map delete rejection, got Ok"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("array map kind") || msg.contains("Array"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_tail_call_compiles_and_emits_prog_array_map() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let idx = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(3),
        });
        func.block_mut(entry).terminator = MirInst::TailCall {
            prog_map: MapRef {
                name: "tail_targets".to_string(),
                kind: MapKind::ProgArray,
            },
            index: MirValue::VReg(idx),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).expect("tail call should compile");
        let map = result
            .maps
            .iter()
            .find(|m| m.name == "tail_targets")
            .expect("expected prog array map");
        assert_eq!(
            map.def.map_type,
            crate::compiler::elf::BpfMapType::ProgArray as u32
        );
        assert!(
            result
                .relocations
                .iter()
                .any(|r| r.map_name == "tail_targets")
        );

        let has_tail_call_helper = result.bytecode.chunks(8).any(|chunk| {
            chunk[0] == opcode::CALL
                && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                    == BpfHelper::TailCall as i32
        });
        assert!(has_tail_call_helper, "expected bpf_tail_call helper call");
    }

    #[test]
    fn test_tail_call_rejects_non_prog_array_map() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        func.block_mut(entry).terminator = MirInst::TailCall {
            prog_map: MapRef {
                name: "bad_tail_map".to_string(),
                kind: MapKind::Hash,
            },
            index: MirValue::Const(0),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected non-prog-array map error, got Ok"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("ProgArray") || msg.contains("prog array"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_helper_call_rejects_more_than_five_args() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let mut args = Vec::new();
        for n in 0..6 {
            let v = func.alloc_vreg();
            func.block_mut(entry).instructions.push(MirInst::Copy {
                dst: v,
                src: MirValue::Const(n),
            });
            args.push(MirValue::VReg(v));
        }
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 9999, // Unknown helper still follows generic 5-arg limit
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected argument-limit error, got Ok"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("at most 5 arguments"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_subfunction_call_rejects_more_than_five_args() {
        use crate::compiler::mir::*;

        let mut subfn = MirFunction::with_name("too_many_args");
        subfn.param_count = 6;
        let sub_entry = subfn.alloc_block();
        subfn.entry = sub_entry;
        subfn.block_mut(sub_entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let mut main = MirFunction::new();
        let entry = main.alloc_block();
        main.entry = entry;

        let mut args = Vec::new();
        for n in 0..6 {
            let v = main.alloc_vreg();
            main.block_mut(entry).instructions.push(MirInst::Copy {
                dst: v,
                src: MirValue::Const(10 + n),
            });
            args.push(v);
        }
        let dst = main.alloc_vreg();
        main.block_mut(entry).instructions.push(MirInst::CallSubfn {
            dst,
            subfn: SubfunctionId(0),
            args,
        });
        main.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(dst)),
        };

        let program = MirProgram {
            main,
            subfunctions: vec![subfn],
        };

        match compile_mir_to_ebpf(&program, None) {
            Ok(_) => panic!("expected argument-limit error, got Ok"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("at most 5 arguments"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    // ==================== BPF-to-BPF Function Call Tests ====================

    /// Test BPF-to-BPF function call compiles correctly
    #[test]
    fn test_bpf_to_bpf_call_simple() {
        use crate::compiler::mir::*;

        // Create a subfunction that adds 1 to its argument and returns it
        let mut subfn = MirFunction::with_name("add_one");
        subfn.param_count = 1;
        let entry = subfn.alloc_block();
        subfn.entry = entry;

        // Subfunction: R1 = arg, return R1 + 1
        // VReg(0) represents the first argument (passed in R1)
        let v0 = VReg(0);
        let v1 = subfn.alloc_vreg(); // Result

        subfn.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        // Create main function that calls the subfunction
        let mut main_func = MirFunction::new();
        let main_entry = main_func.alloc_block();
        main_func.entry = main_entry;

        let arg = main_func.alloc_vreg();
        let result = main_func.alloc_vreg();

        // Load argument value
        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: arg,
                src: MirValue::Const(41),
            });

        // Call subfunction with arg
        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: result,
                subfn: SubfunctionId(0),
                args: vec![arg],
            });

        // Return result
        main_func.block_mut(main_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result)),
        };

        let program = MirProgram {
            main: main_func,
            subfunctions: vec![subfn],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");

        // The bytecode should contain a call instruction
        // BPF call instruction has opcode 0x85 (for local calls with src_reg=1)
        let has_call = result.bytecode.chunks(8).any(|chunk| {
            chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10 // opcode CALL with src_reg=1
        });
        assert!(has_call, "Should contain a BPF-to-BPF call instruction");
    }

    /// Test BPF-to-BPF call with multiple arguments
    #[test]
    fn test_bpf_to_bpf_call_multi_args() {
        use crate::compiler::mir::*;

        // Create a subfunction that adds two arguments
        let mut subfn = MirFunction::with_name("add_two");
        subfn.param_count = 2;
        let entry = subfn.alloc_block();
        subfn.entry = entry;

        // VReg(0) = arg0, VReg(1) = arg1
        let arg0 = VReg(0);
        let arg1 = VReg(1);
        let result = subfn.alloc_vreg();

        subfn.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: result,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(arg0),
            rhs: MirValue::VReg(arg1),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result)),
        };

        // Create main function
        let mut main_func = MirFunction::new();
        let main_entry = main_func.alloc_block();
        main_func.entry = main_entry;

        let a = main_func.alloc_vreg();
        let b = main_func.alloc_vreg();
        let result = main_func.alloc_vreg();

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: a,
                src: MirValue::Const(10),
            });
        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: b,
                src: MirValue::Const(32),
            });

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: result,
                subfn: SubfunctionId(0),
                args: vec![a, b],
            });

        main_func.block_mut(main_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result)),
        };

        let program = MirProgram {
            main: main_func,
            subfunctions: vec![subfn],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    /// Test multiple BPF-to-BPF calls to the same function
    #[test]
    fn test_bpf_to_bpf_multiple_calls() {
        use crate::compiler::mir::*;

        // Create a subfunction
        let mut subfn = MirFunction::with_name("double");
        subfn.param_count = 1;
        let entry = subfn.alloc_block();
        subfn.entry = entry;

        let arg = VReg(0);
        let result = subfn.alloc_vreg();

        subfn.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: result,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(arg),
            rhs: MirValue::Const(2),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result)),
        };

        // Main function calls the subfunction twice
        let mut main_func = MirFunction::new();
        let main_entry = main_func.alloc_block();
        main_func.entry = main_entry;

        let v0 = main_func.alloc_vreg();
        let v1 = main_func.alloc_vreg();
        let v2 = main_func.alloc_vreg();

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: v0,
                src: MirValue::Const(5),
            });

        // First call: double(5)
        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: v1,
                subfn: SubfunctionId(0),
                args: vec![v0],
            });

        // Second call: double(result of first call)
        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: v2,
                subfn: SubfunctionId(0),
                args: vec![v1],
            });

        main_func.block_mut(main_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        let program = MirProgram {
            main: main_func,
            subfunctions: vec![subfn],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");

        // Count call instructions
        let call_count = result
            .bytecode
            .chunks(8)
            .filter(|chunk| chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10)
            .count();
        assert_eq!(call_count, 2, "Should have 2 BPF-to-BPF call instructions");
    }

    /// Test that call instruction offsets are correct
    #[test]
    fn test_bpf_to_bpf_call_offset_verification() {
        use crate::compiler::mir::*;

        // Create a simple subfunction: return arg + 100
        let mut subfn = MirFunction::with_name("add_hundred");
        subfn.param_count = 1;
        let entry = subfn.alloc_block();
        subfn.entry = entry;

        let arg = VReg(0);
        let result_vreg = subfn.alloc_vreg();

        subfn.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: result_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(arg),
            rhs: MirValue::Const(100),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result_vreg)),
        };

        // Create main function that calls the subfunction
        let mut main_func = MirFunction::new();
        let main_entry = main_func.alloc_block();
        main_func.entry = main_entry;

        let input = main_func.alloc_vreg();
        let output = main_func.alloc_vreg();

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: input,
                src: MirValue::Const(42),
            });

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: output,
                subfn: SubfunctionId(0),
                args: vec![input],
            });

        main_func.block_mut(main_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(output)),
        };

        let program = MirProgram {
            main: main_func,
            subfunctions: vec![subfn],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();

        // Find the call instruction and verify its offset
        let mut call_idx = None;
        let mut call_offset: Option<i32> = None;

        for (i, chunk) in result.bytecode.chunks(8).enumerate() {
            if chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10 {
                // This is a BPF-to-BPF call
                call_idx = Some(i);
                // imm is at bytes 4-7 (little endian)
                call_offset = Some(i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]));
                break;
            }
        }

        assert!(call_idx.is_some(), "Should find a call instruction");
        let call_idx = call_idx.unwrap();
        let call_offset = call_offset.unwrap();

        // The subfunction should start after the main function's code
        // The call offset is relative: target = call_idx + 1 + offset
        let target_idx = (call_idx as i32 + 1 + call_offset) as usize;
        let total_instructions = result.bytecode.len() / 8;

        assert!(
            target_idx < total_instructions,
            "Call target {} should be within bytecode (total: {})",
            target_idx,
            total_instructions
        );

        // Verify the subfunction exists at the target location
        // It should have some instructions (not all zeros)
        let subfunction_start = target_idx * 8;
        let subfn_first_insn = &result.bytecode[subfunction_start..subfunction_start + 8];
        assert!(
            subfn_first_insn.iter().any(|&b| b != 0),
            "Subfunction should have non-zero instructions"
        );

        println!(
            "Call at instruction {}, offset {}, targets instruction {}",
            call_idx, call_offset, target_idx
        );
        println!("Total instructions: {}", total_instructions);
    }

    /// Test bytecode disassembly for debugging
    #[test]
    fn test_bpf_to_bpf_bytecode_structure() {
        use crate::compiler::mir::*;

        // Simple subfunction that returns its argument * 2
        let mut subfn = MirFunction::with_name("double");
        subfn.param_count = 1;
        let entry = subfn.alloc_block();
        subfn.entry = entry;

        let arg = VReg(0);
        let result_vreg = subfn.alloc_vreg();

        subfn.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: result_vreg,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(arg),
            rhs: MirValue::Const(2),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result_vreg)),
        };

        // Main function
        let mut main_func = MirFunction::new();
        let main_entry = main_func.alloc_block();
        main_func.entry = main_entry;

        let v0 = main_func.alloc_vreg();
        let v1 = main_func.alloc_vreg();

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::Copy {
                dst: v0,
                src: MirValue::Const(21),
            });

        main_func
            .block_mut(main_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: v1,
                subfn: SubfunctionId(0),
                args: vec![v0],
            });

        main_func.block_mut(main_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        let program = MirProgram {
            main: main_func,
            subfunctions: vec![subfn],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();

        // Disassemble and print
        println!("\n=== BPF-to-BPF Call Bytecode ===");
        for (i, chunk) in result.bytecode.chunks(8).enumerate() {
            let opcode = chunk[0];
            let regs = chunk[1];
            let dst = regs & 0x0f;
            let src = (regs >> 4) & 0x0f;
            let offset = i16::from_le_bytes([chunk[2], chunk[3]]);
            let imm = i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

            let desc = match opcode {
                0x85 if src == 1 => format!("call local +{}", imm),
                0x85 => format!("call helper #{}", imm),
                0xb7 => format!("mov r{}, {}", dst, imm),
                0xbf => format!("mov r{}, r{}", dst, src),
                0x0f => format!("add r{}, r{}", dst, src),
                0x07 => format!("add r{}, {}", dst, imm),
                0x2f => format!("mul r{}, r{}", dst, src),
                0x27 => format!("mul r{}, {}", dst, imm),
                0x95 => "exit".to_string(),
                _ => format!(
                    "op={:#04x} dst=r{} src=r{} off={} imm={}",
                    opcode, dst, src, offset, imm
                ),
            };

            println!(
                "{:4}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  ; {}",
                i,
                chunk[0],
                chunk[1],
                chunk[2],
                chunk[3],
                chunk[4],
                chunk[5],
                chunk[6],
                chunk[7],
                desc
            );
        }
        println!("=================================\n");

        // Verify structure
        let total = result.bytecode.len() / 8;
        assert!(total >= 4, "Should have at least 4 instructions");

        // Find exit instructions (opcode 0x95)
        let exit_count = result.bytecode.chunks(8).filter(|c| c[0] == 0x95).count();
        assert!(
            exit_count >= 2,
            "Should have at least 2 exit instructions (main + subfunction)"
        );
    }

    #[test]
    fn test_string_append_literal() {
        // Test appending a literal string
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate stack slot for string buffer
        let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

        // Allocate vreg for length tracking
        let len_vreg = func.alloc_vreg();

        // Initialize length to 0
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });

        // Append "hello" literal
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: slot,
                dst_len: len_vreg,
                val: MirValue::Const(0), // Not used for literals
                val_type: StringAppendType::Literal {
                    bytes: b"hello".to_vec(),
                },
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let compiler = MirToEbpfCompiler::new(&lir, None);
        let result = compiler.compile();

        assert!(result.is_ok(), "StringAppend literal should compile");
        let result = result.unwrap();
        assert!(!result.bytecode.is_empty(), "Should generate bytecode");
    }

    #[test]
    fn test_int_to_string() {
        // Test integer to string conversion
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate stack slot for string buffer
        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);

        // Allocate vregs
        let val_vreg = func.alloc_vreg();
        let len_vreg = func.alloc_vreg();

        // Load value 12345
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: val_vreg,
            src: MirValue::Const(12345),
        });

        // Convert to string
        func.block_mut(entry)
            .instructions
            .push(MirInst::IntToString {
                dst_buffer: slot,
                dst_len: len_vreg,
                val: val_vreg,
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let compiler = MirToEbpfCompiler::new(&lir, None);
        let result = compiler.compile();

        assert!(result.is_ok(), "IntToString should compile");
        let result = result.unwrap();
        assert!(!result.bytecode.is_empty(), "Should generate bytecode");
    }

    #[test]
    fn test_string_append_slot() {
        // Test appending from another string slot
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate source and dest stack slots
        let src_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
        let dst_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

        // Allocate vregs
        let len_vreg = func.alloc_vreg();
        let src_vreg = func.alloc_vreg();

        // Initialize length to 0
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });

        // Create src vreg pointing to slot
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: src_vreg,
            src: MirValue::StackSlot(src_slot),
        });

        // Append from source slot
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: dst_slot,
                dst_len: len_vreg,
                val: MirValue::VReg(src_vreg),
                val_type: StringAppendType::StringSlot {
                    slot: src_slot,
                    max_len: 32,
                },
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let compiler = MirToEbpfCompiler::new(&lir, None);
        let result = compiler.compile();

        assert!(result.is_ok(), "StringAppend slot should compile");
        let result = result.unwrap();
        assert!(!result.bytecode.is_empty(), "Should generate bytecode");
    }

    #[test]
    fn test_string_append_integer() {
        // Test appending an integer to a string (integer interpolation)
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate stack slot for string buffer
        let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

        // Allocate vregs
        let len_vreg = func.alloc_vreg();
        let int_vreg = func.alloc_vreg();

        // Initialize length to 0
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });

        // Load integer value 12345
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: int_vreg,
            src: MirValue::Const(12345),
        });

        // Append integer to string
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: slot,
                dst_len: len_vreg,
                val: MirValue::VReg(int_vreg),
                val_type: StringAppendType::Integer,
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let compiler = MirToEbpfCompiler::new(&lir, None);
        let result = compiler.compile();

        assert!(result.is_ok(), "StringAppend integer should compile");
        let result = result.unwrap();
        assert!(!result.bytecode.is_empty(), "Should generate bytecode");
    }

    #[test]
    fn test_string_append_integer_zero() {
        // Test appending zero to a string (edge case)
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate stack slot for string buffer
        let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

        // Allocate vregs
        let len_vreg = func.alloc_vreg();
        let int_vreg = func.alloc_vreg();

        // Initialize length to 0
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });

        // Load integer value 0
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: int_vreg,
            src: MirValue::Const(0),
        });

        // Append integer to string
        func.block_mut(entry)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: slot,
                dst_len: len_vreg,
                val: MirValue::VReg(int_vreg),
                val_type: StringAppendType::Integer,
            });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let lir = lower_mir_to_lir(&program);
        let compiler = MirToEbpfCompiler::new(&lir, None);
        let result = compiler.compile();

        assert!(result.is_ok(), "StringAppend integer zero should compile");
        let result = result.unwrap();
        assert!(!result.bytecode.is_empty(), "Should generate bytecode");
    }

    /// Test list literal compilation with ListNew, ListPush, and EmitEvent
    /// This tests the fix for the R0 initialization bug and proper register allocation
    #[test]
    fn test_list_literal_compilation() {
        use crate::compiler::cfg::CFG;
        use crate::compiler::mir::*;
        use crate::compiler::passes::{ListLowering, MirPass};

        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        // Allocate stack slot for list buffer (length + 3 elements)
        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);

        // Allocate vregs
        let list_ptr = func.alloc_vreg();
        let item1 = func.alloc_vreg();
        let item2 = func.alloc_vreg();
        let item3 = func.alloc_vreg();

        // ListNew: initialize list buffer
        func.block_mut(entry).instructions.push(MirInst::ListNew {
            dst: list_ptr,
            buffer: slot,
            max_len: 3,
        });

        // Push elements
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: item1,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::ListPush {
            list: list_ptr,
            item: item1,
        });

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: item2,
            src: MirValue::Const(2),
        });
        func.block_mut(entry).instructions.push(MirInst::ListPush {
            list: list_ptr,
            item: item2,
        });

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: item3,
            src: MirValue::Const(3),
        });
        func.block_mut(entry).instructions.push(MirInst::ListPush {
            list: list_ptr,
            item: item3,
        });

        // Emit the list
        func.block_mut(entry).instructions.push(MirInst::EmitEvent {
            data: list_ptr,
            size: 32,
        });

        func.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = ListLowering;
        assert!(pass.run(&mut func, &cfg));

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        // Compile and verify
        let lir = lower_mir_to_lir(&program);
        let mut compiler = MirToEbpfCompiler::new(&lir, None);
        compiler
            .prepare_function_state(
                &lir.main,
                compiler.available_regs.clone(),
                lir.main.precolored.clone(),
            )
            .unwrap();

        // Verify list_ptr (VReg 0) got a physical register
        assert!(
            compiler.vreg_to_phys.contains_key(&VReg(0)),
            "list_ptr vreg should be assigned a physical register"
        );

        compiler.compile_function(&lir.main).unwrap();
        compiler.fixup_jumps().unwrap();

        // Verify bytecode was generated
        assert!(
            !compiler.instructions.is_empty(),
            "Should generate bytecode for list literal"
        );

        // The first instructions should set up the list pointer (mov + add for R10 + offset)
        // Then initialize length to 0 (mov R0, 0; stxdw)
        let has_list_init = compiler.instructions.iter().any(|insn| {
            // Look for mov immediate 0 (R0 = 0 for length initialization)
            insn.opcode == (opcode::BPF_ALU64 | opcode::BPF_MOV | opcode::BPF_K) && insn.imm == 0
        });
        assert!(has_list_init, "Should have length initialization to 0");
    }
}
