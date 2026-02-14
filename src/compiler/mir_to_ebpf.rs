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
mod compile_driver;
mod control_flow;
mod function_setup;
mod helper_calls;
mod instruction_helpers;
mod instruction_lowering;
mod maps;
mod ops;
mod parallel_moves;
mod remat;
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
