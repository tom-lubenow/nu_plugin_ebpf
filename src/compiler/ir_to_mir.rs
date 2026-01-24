//! Nushell IR to MIR lowering
//!
//! This module converts Nushell's internal IR representation into MIR,
//! which is then lowered to eBPF bytecode by mir_to_ebpf.

use std::collections::{HashMap, HashSet};

use nu_protocol::ast::{CellPath, PathMember, Pattern, RangeInclusion};
use nu_protocol::ir::{Instruction, IrBlock, Literal};
use nu_protocol::{BlockId as NuBlockId, DeclId, RegId, Value, VarId};

use super::CompileError;
use super::elf::ProbeContext;
use super::mir::{
    BasicBlock, BinOpKind, BlockId, CtxField, MapKind, MapRef, MirFunction, MirInst, MirProgram,
    MirType, MirValue, RecordFieldDef, StackSlotId, StackSlotKind, StringAppendType, SubfunctionId,
    VReg,
};

/// Command types we recognize for eBPF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfCommand {
    Emit,
    ReadStr,
    ReadKernelStr,
    Filter,
    Count,
    Histogram,
    StartTimer,
    StopTimer,
}

/// Infer the context parameter VarId from IR instructions.
///
/// Closure parameters are variables that are loaded but never stored to within the closure.
/// The first such variable (by order of first load) is the context parameter.
pub fn infer_ctx_param(ir_block: &IrBlock) -> Option<VarId> {
    let mut stored_vars: HashSet<VarId> = HashSet::new();
    let mut first_loaded: Vec<VarId> = Vec::new();

    // First pass: collect all stored variables
    for instruction in &ir_block.instructions {
        if let Instruction::StoreVariable { var_id, .. } = instruction {
            stored_vars.insert(*var_id);
        }
    }

    // Second pass: find loaded variables that were never stored (parameters)
    for instruction in &ir_block.instructions {
        if let Instruction::LoadVariable { var_id, .. } = instruction {
            if !stored_vars.contains(var_id) && !first_loaded.contains(var_id) {
                first_loaded.push(*var_id);
            }
        }
    }

    // The first parameter is the context
    first_loaded.first().copied()
}

/// Extract all closure/block IDs referenced in an IR block.
///
/// This scans the IR for LoadLiteral instructions that load closures, blocks,
/// or row conditions, and returns all the block IDs found.
pub fn extract_closure_block_ids(ir_block: &IrBlock) -> Vec<NuBlockId> {
    let mut block_ids = Vec::new();

    for instruction in &ir_block.instructions {
        if let Instruction::LoadLiteral { lit, .. } = instruction {
            match lit {
                Literal::Closure(block_id)
                | Literal::Block(block_id)
                | Literal::RowCondition(block_id) => {
                    if !block_ids.contains(block_id) {
                        block_ids.push(*block_id);
                    }
                }
                _ => {}
            }
        }
    }

    block_ids
}

/// A field in a record being built
#[derive(Debug, Clone)]
struct RecordField {
    name: String,
    value_vreg: VReg,
    /// Stack offset where this field's value is stored (for safety)
    #[allow(dead_code)] // Reserved for future stack safety checks
    stack_offset: Option<i16>,
    ty: MirType,
}

/// Bounded iterator info for ranges
#[derive(Debug, Clone, Copy)]
struct BoundedRange {
    /// Start value
    #[allow(dead_code)] // Used for counter initialization (stored in vreg)
    start: i64,
    /// Step value
    step: i64,
    /// End value
    end: i64,
    /// Whether end is inclusive
    inclusive: bool,
}

/// Loop context for tracking active loops
#[derive(Debug, Clone)]
struct LoopContext {
    /// Block ID of the loop header
    header_block: BlockId,
    /// Block ID of the exit block
    exit_block: BlockId,
    /// Counter register
    counter_vreg: VReg,
    /// Step value for increment
    step: i64,
    /// IR index of the Iterate instruction (for matching Jump back)
    iterate_ir_index: usize,
    /// IR index where loop ends (for matching exit jumps)
    end_ir_index: usize,
}

/// Metadata tracked for each Nushell register during lowering
#[derive(Debug, Clone, Default)]
struct RegMetadata {
    /// Compile-time integer constant
    literal_int: Option<i64>,
    /// Compile-time string (for field names)
    literal_string: Option<String>,
    /// Whether this register holds the context parameter
    is_context: bool,
    /// Cell path for field access (like $ctx.pid)
    cell_path: Option<CellPath>,
    /// Stack slot for string storage
    string_slot: Option<StackSlotId>,
    /// Record fields being built
    record_fields: Vec<RecordField>,
    /// Type of value in this register (for context fields)
    field_type: Option<MirType>,
    /// Bounded range for iteration
    bounded_range: Option<BoundedRange>,
    /// List buffer (stack slot, max_len) for list construction
    list_buffer: Option<(StackSlotId, usize)>,
    /// Closure block ID (for inline execution in where/each)
    closure_block_id: Option<nu_protocol::BlockId>,
}

/// Lowering context for IR to MIR conversion
pub struct IrToMirLowering<'a> {
    /// The MIR function being built
    func: MirFunction,
    /// Mapping from Nushell RegId to MIR VReg
    reg_map: HashMap<u32, VReg>,
    /// Metadata for each register
    reg_metadata: HashMap<u32, RegMetadata>,
    /// Current basic block being built
    current_block: BlockId,
    /// IR block for data access
    ir_block: Option<&'a IrBlock>,
    /// Probe context for field access (reserved for future BTF/CO-RE support)
    #[allow(dead_code)]
    probe_ctx: Option<&'a ProbeContext>,
    /// Mapping from DeclId to command name (for plugin context where engine_state is unavailable)
    decl_names: &'a HashMap<DeclId, String>,
    /// Mapping from BlockId to IrBlock for nested closures (where, each, etc.)
    closure_irs: &'a HashMap<nu_protocol::BlockId, IrBlock>,
    /// Captured closure values to inline
    captures: &'a [(String, i64)],
    /// Context parameter variable ID (if any)
    ctx_param: Option<VarId>,
    /// Pipeline input register (for commands)
    pipeline_input: Option<VReg>,
    /// Pipeline input source RegId (for metadata lookup)
    pipeline_input_reg: Option<RegId>,
    /// Positional arguments for the next call (vreg, source RegId for metadata)
    positional_args: Vec<(VReg, RegId)>,
    /// Named flags for the next call (e.g., --verbose)
    named_flags: Vec<String>,
    /// Named arguments with values for the next call (e.g., --count 5)
    named_args: HashMap<String, (VReg, RegId)>,
    /// Variable mappings for inlined functions (VarId -> VReg)
    var_mappings: HashMap<VarId, VReg>,
    /// Needs ringbuf map
    pub needs_ringbuf: bool,
    /// Needs counter map
    pub needs_counter_map: bool,
    /// Needs histogram map
    pub needs_histogram_map: bool,
    /// Needs timestamp map (for timing)
    pub needs_timestamp_map: bool,
    /// Active loop contexts (for emitting LoopBack instead of Jump)
    loop_contexts: Vec<LoopContext>,
    /// Mapping from IR instruction index to MIR block (for forward jumps)
    ir_index_to_block: HashMap<usize, BlockId>,
    /// Generated subfunctions
    subfunctions: Vec<MirFunction>,
    /// Registry of generated subfunctions by DeclId
    subfunction_registry: HashMap<DeclId, SubfunctionId>,
    /// Call count for each user function (for inline vs subfunction decision)
    call_counts: HashMap<DeclId, usize>,
}

impl<'a> IrToMirLowering<'a> {
    /// Create a new lowering context
    pub fn new(
        ir_block: &'a IrBlock,
        probe_ctx: Option<&'a ProbeContext>,
        decl_names: &'a HashMap<DeclId, String>,
        closure_irs: &'a HashMap<nu_protocol::BlockId, IrBlock>,
        captures: &'a [(String, i64)],
        ctx_param: Option<VarId>,
    ) -> Self {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        Self {
            func,
            reg_map: HashMap::new(),
            reg_metadata: HashMap::new(),
            current_block: entry,
            ir_block: Some(ir_block),
            probe_ctx,
            decl_names,
            closure_irs,
            captures,
            ctx_param,
            pipeline_input: None,
            pipeline_input_reg: None,
            positional_args: Vec::new(),
            named_flags: Vec::new(),
            named_args: HashMap::new(),
            var_mappings: HashMap::new(),
            needs_ringbuf: false,
            needs_counter_map: false,
            needs_histogram_map: false,
            needs_timestamp_map: false,
            loop_contexts: Vec::new(),
            ir_index_to_block: HashMap::new(),
            subfunctions: Vec::new(),
            subfunction_registry: HashMap::new(),
            call_counts: HashMap::new(),
        }
    }

    /// Get or create a block for an IR instruction index
    fn get_or_create_block_for_ir(&mut self, ir_idx: usize) -> BlockId {
        if let Some(&block) = self.ir_index_to_block.get(&ir_idx) {
            block
        } else {
            let block = self.func.alloc_block();
            self.ir_index_to_block.insert(ir_idx, block);
            block
        }
    }

    /// Get a slice of data from the IR block
    fn get_data_slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        self.ir_block.map(|b| &b.data[start..start + len])
    }

    /// Get metadata for a register
    fn get_metadata(&self, reg: RegId) -> Option<&RegMetadata> {
        self.reg_metadata.get(&reg.get())
    }

    /// Get or create metadata for a register
    fn get_or_create_metadata(&mut self, reg: RegId) -> &mut RegMetadata {
        self.reg_metadata.entry(reg.get()).or_default()
    }

    /// Clear metadata for a register (when it's written to)
    /// Reserved for future use with more complex metadata tracking
    #[allow(dead_code)]
    fn clear_metadata(&mut self, reg: RegId) {
        self.reg_metadata.remove(&reg.get());
    }

    /// Check if a register holds the context value
    fn is_context_reg(&self, reg: RegId) -> bool {
        self.get_metadata(reg)
            .map(|m| m.is_context)
            .unwrap_or(false)
    }

    /// Get or create a VReg for a Nushell RegId
    fn get_vreg(&mut self, reg: RegId) -> VReg {
        let reg_id = reg.get();
        if let Some(&vreg) = self.reg_map.get(&reg_id) {
            vreg
        } else {
            let vreg = self.func.alloc_vreg();
            self.reg_map.insert(reg_id, vreg);
            vreg
        }
    }

    /// Get the current block being built
    fn current_block_mut(&mut self) -> &mut BasicBlock {
        self.func.block_mut(self.current_block)
    }

    /// Add an instruction to the current block
    fn emit(&mut self, inst: MirInst) {
        self.current_block_mut().instructions.push(inst);
    }

    /// Set the terminator for the current block
    fn terminate(&mut self, inst: MirInst) {
        self.func.block_mut(self.current_block).terminator = inst;
    }

    /// Lower an entire IR block to MIR
    pub fn lower_block(&mut self, ir_block: &IrBlock) -> Result<(), CompileError> {
        for (idx, instruction) in ir_block.instructions.iter().enumerate() {
            self.lower_instruction(instruction, idx)?;
        }
        Ok(())
    }

    /// Lower a single IR instruction to MIR
    fn lower_instruction(
        &mut self,
        instruction: &Instruction,
        ir_idx: usize,
    ) -> Result<(), CompileError> {
        // Check if this IR index is a jump target with a pre-allocated block
        if let Some(&target_block) = self.ir_index_to_block.get(&ir_idx) {
            // If we have a current block without a terminator, add a jump to this block
            if !matches!(
                self.func.block(self.current_block).terminator,
                MirInst::Jump { .. }
                    | MirInst::Branch { .. }
                    | MirInst::Return { .. }
                    | MirInst::LoopHeader { .. }
                    | MirInst::LoopBack { .. }
                    | MirInst::TailCall { .. }
            ) {
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }
            // Switch to the target block
            self.current_block = target_block;
        }

        match instruction {
            // === Data Movement ===
            Instruction::LoadLiteral { dst, lit } => {
                self.lower_load_literal(*dst, lit)?;
            }

            Instruction::Move { dst, src } => {
                // Copy value and metadata
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                // Copy metadata
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            Instruction::Clone { dst, src } => {
                // Same as Move for our purposes
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            // === Arithmetic ===
            Instruction::BinaryOp { lhs_dst, op, rhs } => {
                self.lower_binary_op(*lhs_dst, *op, *rhs)?;
            }

            Instruction::Not { src_dst } => {
                let vreg = self.get_vreg(*src_dst);
                self.emit(MirInst::UnaryOp {
                    dst: vreg,
                    op: super::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(vreg),
                });
            }

            // === Control Flow ===
            Instruction::BranchIf { cond, index } => {
                self.lower_branch_if(*cond, *index)?;
            }

            Instruction::Jump { index } => {
                // Check if this Jump is a loop back-edge
                if let Some(loop_ctx) = self.loop_contexts.last() {
                    if *index == loop_ctx.iterate_ir_index {
                        // This is a loop back-edge - emit LoopBack
                        let counter = loop_ctx.counter_vreg;
                        let step = loop_ctx.step;
                        let header = loop_ctx.header_block;
                        self.terminate(MirInst::LoopBack {
                            counter,
                            step,
                            header,
                        });
                        return Ok(());
                    } else if *index == loop_ctx.end_ir_index {
                        // This is a loop exit - jump to exit block
                        let exit = loop_ctx.exit_block;
                        self.loop_contexts.pop();
                        self.terminate(MirInst::Jump { target: exit });
                        return Ok(());
                    }
                }
                // Regular jump - get or create target block
                let target = self.get_or_create_block_for_ir(*index);
                self.terminate(MirInst::Jump { target });
            }

            Instruction::Match {
                pattern,
                src,
                index,
            } => {
                // Match is used for short-circuit boolean evaluation
                self.lower_match(pattern, *src, *index)?;
            }

            Instruction::Return { src } => {
                let val = Some(MirValue::VReg(self.get_vreg(*src)));
                self.terminate(MirInst::Return { val });
            }

            // === Field Access ===
            Instruction::FollowCellPath { src_dst, path } => {
                self.lower_follow_cell_path(*src_dst, *path)?;
            }

            Instruction::UpsertCellPath {
                src_dst,
                path,
                new_value,
            } => {
                // Cell path updates (like $record.field = 42) are not supported
                // in eBPF because:
                // 1. Records are stack-allocated with fixed layout
                // 2. Most eBPF programs build records once for emission
                // Get the path for a better error message
                let path_str = self
                    .get_metadata(*path)
                    .and_then(|m| {
                        m.cell_path.as_ref().map(|cp| {
                            cp.members
                                .iter()
                                .map(|m| match m {
                                    PathMember::String { val, .. } => val.clone(),
                                    PathMember::Int { val, .. } => val.to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join(".")
                        })
                    })
                    .unwrap_or_else(|| "<unknown>".to_string());

                let _ = (src_dst, new_value); // Silence unused warnings
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Cell path update (.{} = ...) is not supported in eBPF. \
                     Consider building the record with the correct value initially.",
                    path_str
                )));
            }

            // === Commands ===
            Instruction::Call { decl_id, src_dst } => {
                self.lower_call(*decl_id, *src_dst)?;
            }

            Instruction::PushPositional { src } => {
                // Track positional argument for user-defined functions and built-ins
                // like `where {closure}`, `each {closure}`, `skip N`, etc.
                // NOTE: Do NOT set pipeline_input here - positional args are separate
                // from pipeline input. Pipeline input comes from src_dst of Call.
                let src_vreg = self.get_vreg(*src);
                self.positional_args.push((src_vreg, *src));
            }

            Instruction::AppendRest { src } => {
                // Track as positional argument (rest parameter)
                // NOTE: Do NOT set pipeline_input here either
                let src_vreg = self.get_vreg(*src);
                self.positional_args.push((src_vreg, *src));
            }

            Instruction::PushFlag { name } => {
                // Track boolean flag for the next call
                if let Some(flag_name) = self
                    .get_data_slice(name.start as usize, name.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                {
                    self.named_flags.push(flag_name.to_string());
                }
            }

            Instruction::PushNamed { name, src } => {
                // Track named argument with value for the next call
                // Extract name first to avoid borrow conflict
                let arg_name = self
                    .get_data_slice(name.start as usize, name.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(|s| s.to_string());
                if let Some(arg_name) = arg_name {
                    let src_vreg = self.get_vreg(*src);
                    self.named_args.insert(arg_name, (src_vreg, *src));
                }
            }

            // === Records ===
            Instruction::RecordInsert { src_dst, key, val } => {
                self.lower_record_insert(*src_dst, *key, *val)?;
            }

            // === Lists ===
            Instruction::ListPush { src_dst, item } => {
                let list_vreg = self.get_vreg(*src_dst);
                let item_vreg = self.get_vreg(*item);

                // Emit ListPush instruction
                self.emit(MirInst::ListPush {
                    list: list_vreg,
                    item: item_vreg,
                });

                // Copy metadata from source list
                if let Some(meta) = self.get_metadata(*src_dst).cloned() {
                    self.reg_metadata.insert(src_dst.get(), meta);
                }
            }

            Instruction::ListSpread { src_dst, items } => {
                // ListSpread adds all items from one list to another
                // For now, we'll emit a bounded loop that copies elements
                let dst_list = self.get_vreg(*src_dst);
                let src_list = self.get_vreg(*items);

                // Get source list metadata for bounds
                let src_meta = self.get_metadata(*items).cloned();
                if let Some(meta) = src_meta {
                    if let Some((_slot, max_len)) = meta.list_buffer {
                        // Emit length load and bounded copy loop
                        let len_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListLen {
                            dst: len_vreg,
                            list: src_list,
                        });

                        // For each item in source list, push to destination
                        // This is done at compile time for known small lists
                        for i in 0..max_len {
                            let item_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListGet {
                                dst: item_vreg,
                                list: src_list,
                                idx: MirValue::Const(i as i64),
                            });
                            self.emit(MirInst::ListPush {
                                list: dst_list,
                                item: item_vreg,
                            });
                        }
                    }
                }
            }

            // === String Interpolation ===
            Instruction::StringAppend { src_dst, val } => {
                // Get the destination string buffer info
                let dst_meta = self.get_metadata(*src_dst).cloned();
                let val_meta = self.get_metadata(*val).cloned();

                // For string append, we need:
                // 1. A string buffer (from Literal::String or a built interpolation)
                // 2. A value to append (string, int, etc.)
                if let Some(meta) = dst_meta {
                    if let Some(slot) = meta.string_slot {
                        // Create a length tracker vreg if not present
                        let len_vreg = self.func.alloc_vreg();
                        // Initialize length to 0 (or we could track actual length)
                        self.emit(MirInst::Copy {
                            dst: len_vreg,
                            src: MirValue::Const(0),
                        });

                        // Determine what type of value we're appending
                        let val_type = if val_meta
                            .as_ref()
                            .map(|m| m.string_slot.is_some())
                            .unwrap_or(false)
                        {
                            let val_slot = val_meta.as_ref().unwrap().string_slot.unwrap();
                            StringAppendType::StringSlot {
                                slot: val_slot,
                                max_len: 256,
                            }
                        } else if val_meta
                            .as_ref()
                            .map(|m| m.literal_string.is_some())
                            .unwrap_or(false)
                        {
                            let bytes = val_meta
                                .as_ref()
                                .unwrap()
                                .literal_string
                                .as_ref()
                                .unwrap()
                                .as_bytes()
                                .to_vec();
                            StringAppendType::Literal { bytes }
                        } else {
                            // Default to integer
                            StringAppendType::Integer
                        };

                        let val_vreg = self.get_vreg(*val);
                        self.emit(MirInst::StringAppend {
                            dst_buffer: slot,
                            dst_len: len_vreg,
                            val: MirValue::VReg(val_vreg),
                            val_type,
                        });
                    }
                }
            }

            // === Variables ===
            Instruction::LoadVariable { dst, var_id } => {
                self.lower_load_variable(*dst, *var_id)?;
            }

            Instruction::StoreVariable { var_id, src } => {
                // Store variable - for now just track the vreg
                let _src_vreg = self.get_vreg(*src);
                let _ = var_id; // Would need a var_map to track this
            }

            Instruction::DropVariable { .. } => {
                // No-op in eBPF
            }

            // === Environment Variables (not supported in eBPF) ===
            Instruction::LoadEnv { key, .. } | Instruction::LoadEnvOpt { key, .. } => {
                // Environment variables are not accessible from eBPF (kernel space)
                // Get the key name for a better error message
                let key_name = self
                    .get_data_slice(key.start as usize, key.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Environment variable access ($env.{}) is not supported in eBPF. \
                     eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            Instruction::StoreEnv { key, .. } => {
                let key_name = self
                    .get_data_slice(key.start as usize, key.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Setting environment variable ($env.{}) is not supported in eBPF. \
                     eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            // === No-ops ===
            Instruction::Span { .. } => {
                // Span tracking - no-op
            }

            Instruction::Collect { .. } => {
                // Collect stream to value - in eBPF we don't have streams, so no-op
            }

            Instruction::OnError { index } | Instruction::OnErrorInto { index, .. } => {
                // Error handling - we don't have try/catch in eBPF, record jump target
                let _ = index;
            }

            Instruction::PopErrorHandler => {
                // No-op
            }

            Instruction::RedirectOut { mode } | Instruction::RedirectErr { mode } => {
                // Redirection - no-op in eBPF, we don't have stdout/stderr
                let _ = mode;
            }

            // === Bounded Loops ===
            Instruction::Iterate {
                dst,
                stream,
                end_index,
            } => {
                // Get the range info from the stream register
                let range = self
                    .get_metadata(*stream)
                    .and_then(|m| m.bounded_range)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Iterate requires a compile-time known range (e.g., 1..10)".into(),
                        )
                    })?;

                let dst_vreg = self.get_vreg(*dst);
                let counter_vreg = self.get_vreg(*stream); // Use stream reg as counter

                // Calculate the limit for the loop
                let limit = if range.inclusive {
                    range.end + range.step.signum() // Include end value
                } else {
                    range.end
                };

                // Create blocks: header block (current becomes entry to header), body block, exit block
                let header_block = self.func.alloc_block();
                let body_block = self.func.alloc_block();
                let exit_block = self.func.alloc_block();

                // Current block jumps to header
                self.terminate(MirInst::Jump {
                    target: header_block,
                });

                // Set up header block with LoopHeader terminator
                self.current_block = header_block;
                self.terminate(MirInst::LoopHeader {
                    counter: counter_vreg,
                    limit,
                    body: body_block,
                    exit: exit_block,
                });

                // Switch to body block for loop body code
                self.current_block = body_block;

                // Copy counter to destination for use in loop body
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(counter_vreg),
                });

                // Record this as a loop context so Jump can emit LoopBack
                self.loop_contexts.push(LoopContext {
                    header_block,
                    exit_block,
                    counter_vreg,
                    step: range.step,
                    iterate_ir_index: ir_idx,
                    end_ir_index: *end_index,
                });
            }

            // === Unsupported ===
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{:?} (MIR lowering not yet implemented)",
                    instruction
                )));
            }
        }
        Ok(())
    }

    /// Lower LoadLiteral instruction
    fn lower_load_literal(
        &mut self,
        dst: RegId,
        lit: &nu_protocol::ir::Literal,
    ) -> Result<(), CompileError> {
        use nu_protocol::ir::Literal;

        let dst_vreg = self.get_vreg(dst);

        match lit {
            Literal::Int(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(*val),
                });
                // Track literal value for constant propagation
                let meta = self.get_or_create_metadata(dst);
                meta.literal_int = Some(*val);
            }

            Literal::Bool(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
            }

            Literal::String(data_slice) => {
                // Allocate stack slot for string
                let slot = self.func.alloc_stack_slot(
                    data_slice.len as usize + 1, // Include null terminator
                    8,
                    StackSlotKind::StringBuffer,
                );
                // Get the string value first (before mutable borrow for metadata)
                let string_value = self
                    .get_data_slice(data_slice.start as usize, data_slice.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(|s| s.to_string());
                // TODO: Store string bytes to slot
                // For now, just record slot ID in a vreg (placeholder)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                // Track the string slot and value
                let meta = self.get_or_create_metadata(dst);
                meta.string_slot = Some(slot);
                // Also track the literal string value for record field names
                if let Some(s) = string_value {
                    meta.literal_string = Some(s);
                }
            }

            Literal::CellPath(cell_path) => {
                // Cell paths are metadata-only - they guide field access compilation
                // They don't need a runtime value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Dummy value
                });
                // Track the cell path for use in FollowCellPath
                let meta = self.get_or_create_metadata(dst);
                meta.cell_path = Some((**cell_path).clone());
            }

            Literal::Record { capacity: _ } => {
                // Record allocation - just track that this is a record
                // Actual fields are added via RecordInsert
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Placeholder
                });
                // Initialize empty record fields in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.record_fields = Vec::new();
            }

            Literal::Range {
                start,
                step,
                end,
                inclusion,
            } => {
                // For eBPF bounded loops, we need compile-time known bounds
                let start_val = self
                    .get_metadata(*start)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range start must be a compile-time known integer for eBPF loops"
                                .into(),
                        )
                    })?;

                // Step can be nothing (default 1) or an explicit integer
                let step_val = self
                    .get_metadata(*step)
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1);

                let end_val = self
                    .get_metadata(*end)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range end must be a compile-time known integer for eBPF loops".into(),
                        )
                    })?;

                // Validate step is non-zero
                if step_val == 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "Range step cannot be zero".into(),
                    ));
                }

                // Store range info in metadata for use by Iterate
                let range = BoundedRange {
                    start: start_val,
                    step: step_val,
                    end: end_val,
                    inclusive: *inclusion == RangeInclusion::Inclusive,
                };

                // Set a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(start_val), // Initial value
                });

                let meta = self.get_or_create_metadata(dst);
                meta.bounded_range = Some(range);
            }

            Literal::List { capacity } => {
                // Allocate stack slot for list: [length: u64, elem0, elem1, ...]
                // Due to eBPF 512-byte stack limit, we cap capacity at 60 elements
                // (8 bytes per elem + 8 bytes for length = 488 bytes max)
                const MAX_LIST_CAPACITY: usize = 60;
                let max_len = (*capacity as usize).min(MAX_LIST_CAPACITY);
                let buffer_size = 8 + (max_len * 8); // length + elements

                let slot = self
                    .func
                    .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);

                // Emit ListNew to initialize the list buffer
                self.emit(MirInst::ListNew {
                    dst: dst_vreg,
                    buffer: slot,
                    max_len,
                });

                // Track the list buffer in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.list_buffer = Some((slot, max_len));
            }

            Literal::Closure(block_id) => {
                // Track the closure block ID for use in where/each
                // Closures as first-class values (stored in variables, passed around)
                // are not supported, but inline closures for where/each work.
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            Literal::Block(block_id) => {
                // Track block ID same as closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            Literal::RowCondition(block_id) => {
                // RowCondition is used by `where` command - same as Closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            _ => {
                return Err(CompileError::UnsupportedLiteral);
            }
        }
        Ok(())
    }

    /// Lower BinaryOp instruction
    fn lower_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: nu_protocol::ast::Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::{Boolean, Comparison, Math, Operator};

        let lhs_vreg = self.get_vreg(lhs_dst);
        let rhs_vreg = self.get_vreg(rhs);

        let mir_op = match op {
            Operator::Math(Math::Add) => BinOpKind::Add,
            Operator::Math(Math::Subtract) => BinOpKind::Sub,
            Operator::Math(Math::Multiply) => BinOpKind::Mul,
            Operator::Math(Math::Divide) => BinOpKind::Div,
            Operator::Math(Math::Modulo) => BinOpKind::Mod,
            Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
            Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
            Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
            Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
            Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
            Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
            Operator::Bits(nu_protocol::ast::Bits::BitAnd) => BinOpKind::And,
            Operator::Bits(nu_protocol::ast::Bits::BitOr) => BinOpKind::Or,
            Operator::Bits(nu_protocol::ast::Bits::BitXor) => BinOpKind::Xor,
            Operator::Bits(nu_protocol::ast::Bits::ShiftLeft) => BinOpKind::Shl,
            Operator::Bits(nu_protocol::ast::Bits::ShiftRight) => BinOpKind::Shr,
            // Logical and/or - use bitwise ops since comparisons return 0 or 1
            Operator::Boolean(Boolean::And) => BinOpKind::And,
            Operator::Boolean(Boolean::Or) => BinOpKind::Or,
            Operator::Boolean(Boolean::Xor) => BinOpKind::Xor,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Operator {:?} not supported in eBPF",
                    op
                )));
            }
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: mir_op,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });

        Ok(())
    }

    /// Lower BranchIf instruction
    fn lower_branch_if(&mut self, cond: RegId, then_branch: usize) -> Result<(), CompileError> {
        let cond_vreg = self.get_vreg(cond);

        // Get or create block for the true branch (jump target)
        let true_block = self.get_or_create_block_for_ir(then_branch);
        // Create a new block for the false (fall-through) branch
        let false_block = self.func.alloc_block();

        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: true_block,
            if_false: false_block,
        });

        // Continue building in the false block
        self.current_block = false_block;

        Ok(())
    }

    /// Lower Match instruction (used for pattern matching and short-circuit boolean evaluation)
    fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        index: usize,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);
        let target_block = self.get_or_create_block_for_ir(index);
        let continue_block = self.func.alloc_block();

        match pattern {
            Pattern::Value(value) => {
                match value {
                    Value::Bool { val, .. } => {
                        // For `and`: match(false) - jump if src == 0
                        // For `or`: match(true) - jump if src != 0
                        if *val {
                            // Jump if src != 0 (true)
                            self.terminate(MirInst::Branch {
                                cond: src_vreg,
                                if_true: target_block,
                                if_false: continue_block,
                            });
                        } else {
                            // Jump if src == 0 (false) - need to negate
                            let tmp = self.func.alloc_vreg();
                            self.emit(MirInst::UnaryOp {
                                dst: tmp,
                                op: super::mir::UnaryOpKind::Not,
                                src: MirValue::VReg(src_vreg),
                            });
                            self.terminate(MirInst::Branch {
                                cond: tmp,
                                if_true: target_block,
                                if_false: continue_block,
                            });
                        }
                    }
                    Value::Int { val, .. } => {
                        // Compare src == val, branch if equal
                        let cmp_result = self.func.alloc_vreg();
                        self.emit(MirInst::BinOp {
                            dst: cmp_result,
                            op: BinOpKind::Eq,
                            lhs: MirValue::VReg(src_vreg),
                            rhs: MirValue::Const(*val),
                        });
                        self.terminate(MirInst::Branch {
                            cond: cmp_result,
                            if_true: target_block,
                            if_false: continue_block,
                        });
                    }
                    Value::Nothing { .. } => {
                        // Match against 0 (Nothing is represented as 0 in eBPF)
                        let cmp_result = self.func.alloc_vreg();
                        self.emit(MirInst::BinOp {
                            dst: cmp_result,
                            op: BinOpKind::Eq,
                            lhs: MirValue::VReg(src_vreg),
                            rhs: MirValue::Const(0),
                        });
                        self.terminate(MirInst::Branch {
                            cond: cmp_result,
                            if_true: target_block,
                            if_false: continue_block,
                        });
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "Match against value type {:?} not supported in eBPF",
                            value.get_type()
                        )));
                    }
                }
            }

            Pattern::Variable(var_id) => {
                // Variable pattern always matches, binds the value to the variable
                // Store the value in the variable mapping
                self.var_mappings.insert(*var_id, src_vreg);
                // Always jump to target (unconditional match)
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }

            Pattern::IgnoreValue => {
                // The `_` wildcard pattern always matches
                // Just jump to target unconditionally
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }

            Pattern::Or(patterns) => {
                // Or pattern: if any sub-pattern matches, jump to target
                // Create a chain of blocks, each testing one pattern
                let mut current = self.current_block;

                for (i, sub_pattern) in patterns.iter().enumerate() {
                    self.current_block = current;
                    let next = if i == patterns.len() - 1 {
                        continue_block // Last pattern falls through to continue if no match
                    } else {
                        self.func.alloc_block() // More patterns to try
                    };

                    // Recursively lower the sub-pattern
                    // Note: this modifies self.current_block
                    self.lower_match(&sub_pattern.pattern, src, index)?;

                    current = next;
                }
            }

            Pattern::Record(field_patterns) => {
                // Record destructuring: { name: $n, age: $a }
                // Get record fields from metadata
                let record_fields = self
                    .get_metadata(src)
                    .map(|m| m.record_fields.clone())
                    .unwrap_or_default();

                if record_fields.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "Record pattern on non-record value in eBPF".into(),
                    ));
                }

                // For each field in the pattern, extract the value and bind it
                for (field_name, sub_pattern) in field_patterns {
                    // Find the field in the record
                    let field = record_fields.iter().find(|f| &f.name == field_name);

                    if let Some(field) = field {
                        // Bind the field value to the pattern
                        match &sub_pattern.pattern {
                            Pattern::Variable(var_id) => {
                                // Bind field value to variable
                                self.var_mappings.insert(*var_id, field.value_vreg);
                            }
                            Pattern::IgnoreValue => {
                                // _ pattern - just ignore the field
                            }
                            _ => {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "Nested pattern {:?} in record field not yet supported",
                                    sub_pattern.pattern
                                )));
                            }
                        }
                    } else {
                        // Field not found - pattern doesn't match
                        // Jump to continue block (no match)
                        self.terminate(MirInst::Jump {
                            target: continue_block,
                        });
                        self.current_block = continue_block;
                        return Ok(());
                    }
                }

                // All fields matched - jump to target
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }

            Pattern::List(element_patterns) => {
                // List destructuring: [$first, $second, ..$rest]
                // Get list info from metadata
                let list_info = self.get_metadata(src).and_then(|m| m.list_buffer);

                if list_info.is_none() {
                    return Err(CompileError::UnsupportedInstruction(
                        "List pattern on non-list value in eBPF".into(),
                    ));
                }

                let list_vreg = src_vreg;
                let mut idx = 0;

                for sub_pattern in element_patterns {
                    match &sub_pattern.pattern {
                        Pattern::Variable(var_id) => {
                            // Extract element at index and bind to variable
                            let elem_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListGet {
                                dst: elem_vreg,
                                list: list_vreg,
                                idx: MirValue::Const(idx as i64),
                            });
                            self.var_mappings.insert(*var_id, elem_vreg);
                            idx += 1;
                        }
                        Pattern::IgnoreValue => {
                            // _ pattern - skip this element
                            idx += 1;
                        }
                        Pattern::Rest(var_id) => {
                            // ..$rest - bind remaining elements as a new list
                            // For now, create a new list with remaining elements
                            let remaining_slot = self.func.alloc_stack_slot(
                                128, // Fixed size for rest list
                                8,
                                StackSlotKind::ListBuffer,
                            );
                            let rest_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListNew {
                                dst: rest_vreg,
                                buffer: remaining_slot,
                                max_len: 16,
                            });

                            // Get list length
                            let len_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListLen {
                                dst: len_vreg,
                                list: list_vreg,
                            });

                            // Copy remaining elements (bounded loop)
                            // For simplicity, unroll for up to 8 elements
                            for i in 0..8 {
                                let actual_idx = idx + i;
                                let elem_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::ListGet {
                                    dst: elem_vreg,
                                    list: list_vreg,
                                    idx: MirValue::Const(actual_idx as i64),
                                });
                                self.emit(MirInst::ListPush {
                                    list: rest_vreg,
                                    item: elem_vreg,
                                });
                            }

                            self.var_mappings.insert(*var_id, rest_vreg);
                            break; // Rest pattern must be last
                        }
                        Pattern::IgnoreRest => {
                            // .. pattern - ignore remaining elements
                            break;
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "Nested pattern {:?} in list element not yet supported",
                                sub_pattern.pattern
                            )));
                        }
                    }
                }

                // Pattern matched - jump to target
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }

            Pattern::Rest(_) | Pattern::IgnoreRest => {
                // Rest patterns only valid inside List patterns
                return Err(CompileError::UnsupportedInstruction(
                    "Rest pattern (..) only valid inside list patterns".into(),
                ));
            }

            Pattern::Expression(_) => {
                // Expression patterns need evaluation at compile time
                return Err(CompileError::UnsupportedInstruction(
                    "Expression patterns in match not yet supported in eBPF".into(),
                ));
            }

            Pattern::Garbage => {
                return Err(CompileError::UnsupportedInstruction(
                    "Invalid pattern in match expression".into(),
                ));
            }
        }

        self.current_block = continue_block;
        Ok(())
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        // Check if this is a context field access
        if !self.is_context_reg(src_dst) {
            return Err(CompileError::UnsupportedInstruction(
                "FollowCellPath only supported on context parameter".into(),
            ));
        }

        // Get the cell path from the path register's metadata
        let path = self
            .get_metadata(path_reg)
            .and_then(|m| m.cell_path.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;

        // Extract field name from path
        if path.members.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "Only single-level field access supported (e.g., $ctx.pid)".into(),
            ));
        }

        let field_name = match &path.members[0] {
            PathMember::String { val, .. } => val.clone(),
            PathMember::Int { val, .. } => {
                // For arg0, arg1, etc. represented as integers
                format!("arg{}", val)
            }
        };

        // Map field name to CtxField
        // Note: In Linux BPF, bpf_get_current_pid_tgid() returns:
        //   - Lower 32 bits: thread ID (kernel calls this "pid")
        //   - Upper 32 bits: thread group ID (kernel calls this "tgid", userspace calls this "PID")
        let ctx_field = match field_name.as_str() {
            "pid" => CtxField::Pid,
            "tid" | "tgid" => CtxField::Tid, // tgid = thread group ID (what userspace calls PID)
            "uid" => CtxField::Uid,
            "gid" => CtxField::Gid,
            "comm" => CtxField::Comm,
            "cpu" => CtxField::Cpu,
            "ktime" | "timestamp" => CtxField::Timestamp,
            "retval" => CtxField::RetVal,
            "kstack" => CtxField::KStack,
            "ustack" => CtxField::UStack,
            s if s.starts_with("arg") => {
                let num: u8 = s[3..].parse().map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("Invalid arg: {}", s))
                })?;
                CtxField::Arg(num)
            }
            _ => CtxField::TracepointField(field_name),
        };

        let dst_vreg = self.get_vreg(src_dst);
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field.clone(),
        });

        // Determine the type of this context field
        let field_type = match &ctx_field {
            CtxField::Comm => MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid => MirType::I32,
            _ => MirType::I64,
        };

        // Clear context flag but set the field type
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(field_type);

        Ok(())
    }

    /// Lower Call instruction (emit, count, etc. or user-defined functions)
    fn lower_call(&mut self, decl_id: DeclId, src_dst: RegId) -> Result<(), CompileError> {
        // Look up command name from our decl_names mapping
        let cmd_name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        let dst_vreg = self.get_vreg(src_dst);

        match cmd_name.as_str() {
            "emit" => {
                self.needs_ringbuf = true;
                // Check if we're emitting a record - check both pipeline_input_reg and src_dst
                // (src_dst is used when record is piped directly: { ... } | emit)
                let record_fields = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .map(|m| m.record_fields.clone())
                    .filter(|f| !f.is_empty())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .map(|m| m.record_fields.clone())
                            .filter(|f| !f.is_empty())
                    })
                    .unwrap_or_default();

                if !record_fields.is_empty() {
                    // Emit a structured record
                    let fields: Vec<RecordFieldDef> = record_fields
                        .iter()
                        .map(|f| RecordFieldDef {
                            name: f.name.clone(),
                            value: f.value_vreg,
                            ty: f.ty.clone(),
                        })
                        .collect();
                    self.emit(MirInst::EmitRecord { fields });
                } else {
                    let field_type = self
                        .pipeline_input_reg
                        .and_then(|reg| self.get_metadata(reg))
                        .and_then(|m| m.field_type.clone())
                        .or_else(|| {
                            self.get_metadata(src_dst)
                                .and_then(|m| m.field_type.clone())
                        });
                    let size = match field_type {
                        Some(MirType::Array { elem, len })
                            if matches!(elem.as_ref(), MirType::U8) =>
                        {
                            len
                        }
                        _ => 8,
                    };
                    // Emit a single value
                    let data_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                    self.emit(MirInst::EmitEvent {
                        data: data_vreg,
                        size,
                    });
                }
                // Set result to 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "count" => {
                self.needs_counter_map = true;
                let key_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let key_type = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.field_type.clone())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .and_then(|m| m.field_type.clone())
                    });

                // Check for --per-cpu flag
                let per_cpu = self.named_flags.contains(&"per-cpu".to_string());

                let (map_name, map_kind) = match key_type {
                    Some(MirType::Array { elem, len }) if matches!(elem.as_ref(), MirType::U8) => {
                        if len == 16 {
                            let kind = if per_cpu {
                                MapKind::PerCpuHash
                            } else {
                                MapKind::Hash
                            };
                            ("str_counters", kind)
                        } else {
                            return Err(CompileError::UnsupportedInstruction(
                                "count only supports 16-byte strings (e.g., $ctx.comm)".into(),
                            ));
                        }
                    }
                    _ => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        ("counters", kind)
                    }
                };
                self.emit(MirInst::MapUpdate {
                    map: MapRef {
                        name: map_name.to_string(),
                        kind: map_kind,
                    },
                    key: key_vreg,
                    val: dst_vreg, // Will be handled specially in MIR->eBPF
                    flags: 0,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "read-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let max_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(128);

                let slot = self
                    .func
                    .alloc_stack_slot(max_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: true,
                    max_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: max_len,
                });
            }

            "read-kernel-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let max_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(128);

                let slot = self
                    .func
                    .alloc_stack_slot(max_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: false,
                    max_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: max_len,
                });
            }

            "histogram" => {
                self.needs_histogram_map = true;
                let value_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                self.emit(MirInst::Histogram { value: value_vreg });
                // Return 0 (pass-through)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "start-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StartTimer);
                // Return 0 (void)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "stop-timer" => {
                self.needs_timestamp_map = true;
                self.emit(MirInst::StopTimer { dst: dst_vreg });
            }

            "where" => {
                // where { condition } - filter pipeline by condition
                // Get the pipeline input (value to filter)
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Inline the closure with $in bound to input_vreg
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;
                    let result_vreg = self.inline_closure_with_in(closure_ir, input_vreg)?;

                    // Create exit block and continue block
                    let exit_block = self.func.alloc_block();
                    let continue_block = self.func.alloc_block();

                    // Branch: if result is 0/false, exit
                    let negated = self.func.alloc_vreg();
                    self.emit(MirInst::UnaryOp {
                        dst: negated,
                        op: super::mir::UnaryOpKind::Not,
                        src: MirValue::VReg(result_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: negated,
                        if_true: exit_block,
                        if_false: continue_block,
                    });

                    // Exit block returns 0
                    self.current_block = exit_block;
                    self.terminate(MirInst::Return {
                        val: Some(MirValue::Const(0)),
                    });

                    // Continue block passes the original value through
                    self.current_block = continue_block;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });

                    // Copy metadata from input to output
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                            out_meta.list_buffer = meta.list_buffer;
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "where requires a closure argument".into(),
                    ));
                }
            }

            "each" => {
                // each { transform } - transform pipeline value(s)
                // Get the pipeline input
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                // Check if input is a list
                let is_list = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.list_buffer)
                    .is_some();

                if let Some(block_id) = closure_block_id {
                    // Look up the closure IR
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;

                    if is_list {
                        // List transformation: iterate and transform each element
                        let list_info = input_reg
                            .and_then(|reg| self.get_metadata(reg))
                            .and_then(|m| m.list_buffer)
                            .unwrap();
                        let (_src_slot, max_len) = list_info;

                        // Allocate output list
                        let out_slot = self.func.alloc_stack_slot(
                            (max_len + 1) * 8,
                            8,
                            StackSlotKind::ListBuffer,
                        );
                        let out_list_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListNew {
                            dst: out_list_vreg,
                            buffer: out_slot,
                            max_len,
                        });

                        // Get length of input list
                        let len_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListLen {
                            dst: len_vreg,
                            list: input_vreg,
                        });

                        // Unrolled loop: for i in 0..max_len
                        for i in 0..max_len.min(16) {
                            // Skip if i >= len
                            let skip_block = self.func.alloc_block();
                            let process_block = self.func.alloc_block();

                            let idx_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::Copy {
                                dst: idx_vreg,
                                src: MirValue::Const(i as i64),
                            });

                            // Compare i < len
                            let in_bounds = self.func.alloc_vreg();
                            self.emit(MirInst::BinOp {
                                dst: in_bounds,
                                op: BinOpKind::Lt,
                                lhs: MirValue::VReg(idx_vreg),
                                rhs: MirValue::VReg(len_vreg),
                            });
                            self.terminate(MirInst::Branch {
                                cond: in_bounds,
                                if_true: process_block,
                                if_false: skip_block,
                            });

                            // Process block: get element, transform, push to output
                            self.current_block = process_block;
                            let elem_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListGet {
                                dst: elem_vreg,
                                list: input_vreg,
                                idx: MirValue::Const(i as i64),
                            });

                            // Transform element with closure
                            let transformed = self.inline_closure_with_in(closure_ir, elem_vreg)?;

                            // Push to output list
                            self.emit(MirInst::ListPush {
                                list: out_list_vreg,
                                item: transformed,
                            });

                            self.terminate(MirInst::Jump { target: skip_block });

                            // Continue to next iteration
                            self.current_block = skip_block;
                        }

                        // Output is the new list
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(out_list_vreg),
                        });

                        // Track output list metadata
                        let meta = self.get_or_create_metadata(src_dst);
                        meta.list_buffer = Some((out_slot, max_len));
                    } else {
                        // Single value transformation
                        let result_vreg = self.inline_closure_with_in(closure_ir, input_vreg)?;
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::VReg(result_vreg),
                        });
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "each requires a closure argument".into(),
                    ));
                }
            }

            "skip" => {
                // skip N - skip the first N elements of a list
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the skip count from positional args
                let skip_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1) as usize;

                // Check if input is a list
                let list_info = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.list_buffer);

                if let Some((_src_slot, max_len)) = list_info {
                    // Create output list
                    let out_slot =
                        self.func
                            .alloc_stack_slot((max_len + 1) * 8, 8, StackSlotKind::ListBuffer);
                    let out_list_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListNew {
                        dst: out_list_vreg,
                        buffer: out_slot,
                        max_len,
                    });

                    // Get length of input list
                    let len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListLen {
                        dst: len_vreg,
                        list: input_vreg,
                    });

                    // Copy elements starting from skip_count
                    for i in 0..max_len.min(16) {
                        let actual_idx = i + skip_count;
                        if actual_idx >= max_len {
                            break;
                        }

                        // Skip if actual_idx >= len
                        let skip_block = self.func.alloc_block();
                        let process_block = self.func.alloc_block();

                        let idx_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::Copy {
                            dst: idx_vreg,
                            src: MirValue::Const(actual_idx as i64),
                        });

                        let in_bounds = self.func.alloc_vreg();
                        self.emit(MirInst::BinOp {
                            dst: in_bounds,
                            op: BinOpKind::Lt,
                            lhs: MirValue::VReg(idx_vreg),
                            rhs: MirValue::VReg(len_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: in_bounds,
                            if_true: process_block,
                            if_false: skip_block,
                        });

                        // Process: get element and push to output
                        self.current_block = process_block;
                        let elem_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListGet {
                            dst: elem_vreg,
                            list: input_vreg,
                            idx: MirValue::Const(actual_idx as i64),
                        });
                        self.emit(MirInst::ListPush {
                            list: out_list_vreg,
                            item: elem_vreg,
                        });
                        self.terminate(MirInst::Jump { target: skip_block });

                        self.current_block = skip_block;
                    }

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(out_list_vreg),
                    });

                    let meta = self.get_or_create_metadata(src_dst);
                    meta.list_buffer = Some((out_slot, max_len.saturating_sub(skip_count)));
                } else {
                    // For non-list values, skip N means return nothing (exit)
                    if skip_count > 0 {
                        self.terminate(MirInst::Return {
                            val: Some(MirValue::Const(0)),
                        });
                        let continue_block = self.func.alloc_block();
                        self.current_block = continue_block;
                    }
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                }
            }

            "take" => {
                // take N - take only the first N elements of a list
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the take count from positional args
                let take_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1) as usize;

                // Check if input is a list
                let list_info = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|m| m.list_buffer);

                if let Some((_src_slot, max_len)) = list_info {
                    // Create output list
                    let out_max = take_count.min(max_len);
                    let out_slot =
                        self.func
                            .alloc_stack_slot((out_max + 1) * 8, 8, StackSlotKind::ListBuffer);
                    let out_list_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListNew {
                        dst: out_list_vreg,
                        buffer: out_slot,
                        max_len: out_max,
                    });

                    // Get length of input list
                    let len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListLen {
                        dst: len_vreg,
                        list: input_vreg,
                    });

                    // Copy up to take_count elements
                    for i in 0..take_count.min(16) {
                        // Skip if i >= len
                        let skip_block = self.func.alloc_block();
                        let process_block = self.func.alloc_block();

                        let idx_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::Copy {
                            dst: idx_vreg,
                            src: MirValue::Const(i as i64),
                        });

                        let in_bounds = self.func.alloc_vreg();
                        self.emit(MirInst::BinOp {
                            dst: in_bounds,
                            op: BinOpKind::Lt,
                            lhs: MirValue::VReg(idx_vreg),
                            rhs: MirValue::VReg(len_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: in_bounds,
                            if_true: process_block,
                            if_false: skip_block,
                        });

                        // Process: get element and push to output
                        self.current_block = process_block;
                        let elem_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListGet {
                            dst: elem_vreg,
                            list: input_vreg,
                            idx: MirValue::Const(i as i64),
                        });
                        self.emit(MirInst::ListPush {
                            list: out_list_vreg,
                            item: elem_vreg,
                        });
                        self.terminate(MirInst::Jump { target: skip_block });

                        self.current_block = skip_block;
                    }

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(out_list_vreg),
                    });

                    let meta = self.get_or_create_metadata(src_dst);
                    meta.list_buffer = Some((out_slot, out_max));
                } else {
                    // For non-list values, take 1+ means pass through, take 0 means nothing
                    if take_count == 0 {
                        self.terminate(MirInst::Return {
                            val: Some(MirValue::Const(0)),
                        });
                        let continue_block = self.func.alloc_block();
                        self.current_block = continue_block;
                    }
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                }
            }

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Command '{}' not supported in eBPF",
                    cmd_name
                )));
            }
        }

        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();
        Ok(())
    }

    /// Call a user-defined function (inline for single use, subfunction for multiple calls)
    // NOTE: User-defined function inlining is not supported in plugin context
    // because it requires access to EngineState to look up block definitions.
    // If needed in the future, the plugin protocol could be extended to support
    // fetching block IR by DeclId.
    #[allow(dead_code)]
    fn inline_user_function(
        &mut self,
        _decl_id: DeclId,
        _src_dst: RegId,
    ) -> Result<(), CompileError> {
        Err(CompileError::UnsupportedInstruction(
            "User-defined function inlining is not supported in plugin context".into(),
        ))
    }

    /// Get or create a subfunction for a user-defined command
    /// NOTE: Not supported in plugin context
    #[allow(dead_code)]
    fn get_or_create_subfunction(
        &mut self,
        _decl_id: DeclId,
    ) -> Result<SubfunctionId, CompileError> {
        Err(CompileError::UnsupportedInstruction(
            "User-defined subfunctions are not supported in plugin context".into(),
        ))
    }

    /// Inline a function body directly at the call site
    /// NOTE: Not supported in plugin context
    #[allow(dead_code)]
    fn inline_function_body(
        &mut self,
        _decl_id: DeclId,
        _dst_vreg: VReg,
        _positional_args: &[(VReg, RegId)],
    ) -> Result<(), CompileError> {
        Err(CompileError::UnsupportedInstruction(
            "User-defined function inlining is not supported in plugin context".into(),
        ))
    }

    /// Lower RecordInsert instruction
    fn lower_record_insert(
        &mut self,
        src_dst: RegId,
        key: RegId,
        val: RegId,
    ) -> Result<(), CompileError> {
        // Get field name from key register's metadata
        let field_name = self
            .get_metadata(key)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Record key must be a literal string".into())
            })?;

        let val_vreg = self.get_vreg(val);

        // Get the type from the value register's metadata, defaulting to I64
        let field_type = self
            .get_metadata(val)
            .and_then(|m| m.field_type.clone())
            .unwrap_or(MirType::I64);

        // IMPORTANT: Create a fresh VReg and copy the value to preserve it.
        // The IR reuses registers, so val_vreg might be overwritten by subsequent operations.
        // By copying to a fresh VReg, we ensure the value is preserved until emit time.
        let preserved_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved_vreg,
            src: MirValue::VReg(val_vreg),
        });

        // Add field to the record being built (using preserved VReg with inferred type)
        let field = RecordField {
            name: field_name,
            value_vreg: preserved_vreg,
            stack_offset: None,
            ty: field_type,
        };

        let meta = self.get_or_create_metadata(src_dst);
        meta.record_fields.push(field);

        Ok(())
    }

    /// Inline a closure with $in bound to a specific value
    /// Returns the vreg containing the closure's result
    ///
    /// This is used for commands like `where` and `each` that take closure arguments.
    /// The closure's parameter is bound to the input value.
    fn inline_closure_with_in(
        &mut self,
        ir_block: &IrBlock,
        in_vreg: VReg,
    ) -> Result<VReg, CompileError> {
        // Collect all variable IDs that are loaded in this closure
        // These could be $in, closure parameters, or captured variables
        // Map all of them to the input value since this is a single-value transform
        let mut loaded_var_ids: Vec<VarId> = Vec::new();
        for inst in &ir_block.instructions {
            if let Instruction::LoadVariable { var_id, .. } = inst {
                if !loaded_var_ids.contains(var_id) {
                    loaded_var_ids.push(*var_id);
                }
            }
        }

        // Save old mappings to restore later
        use nu_protocol::IN_VARIABLE_ID;
        let old_in_mapping = self.var_mappings.get(&IN_VARIABLE_ID).copied();

        // Map $in variable to in_vreg
        self.var_mappings.insert(IN_VARIABLE_ID, in_vreg);

        // Map all loaded variables to in_vreg (they all represent the row/input)
        let mut param_var_ids: Vec<VarId> = Vec::new();
        for var_id in loaded_var_ids {
            // Don't override existing mappings (like captures from outer scope)
            if !self.var_mappings.contains_key(&var_id) {
                param_var_ids.push(var_id);
                self.var_mappings.insert(var_id, in_vreg);
            }
        }

        // Allocate a vreg for the result
        let result_vreg = self.func.alloc_vreg();

        // Save current register mappings (closure has its own register space)
        // IMPORTANT: We start with an empty reg_map so the closure allocates fresh
        // vregs for all its internal registers. This is proper alpha-renaming -
        // without it, the closure would overwrite in_vreg during computation.
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);

        // Lower the closure body
        for (ir_idx, inst) in ir_block.instructions.iter().enumerate() {
            // Handle Return specially to capture the result
            if let Instruction::Return { src } = inst {
                let src_vreg = self.get_vreg(*src);
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                break;
            }

            // Lower other instructions normally
            self.lower_instruction(inst, ir_idx)?;
        }

        // Restore register mappings
        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;

        // Restore old $in mapping (if any)
        if let Some(old) = old_in_mapping {
            self.var_mappings.insert(IN_VARIABLE_ID, old);
        } else {
            self.var_mappings.remove(&IN_VARIABLE_ID);
        }

        // Remove parameter mappings
        for var_id in param_var_ids {
            self.var_mappings.remove(&var_id);
        }

        Ok(result_vreg)
    }

    /// Lower LoadVariable instruction
    fn lower_load_variable(
        &mut self,
        dst: RegId,
        var_id: nu_protocol::VarId,
    ) -> Result<(), CompileError> {
        let dst_vreg = self.get_vreg(dst);

        // Check if this is a parameter from an inlined function
        if let Some(&param_vreg) = self.var_mappings.get(&var_id) {
            // Copy the parameter value to the destination
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(param_vreg),
            });
            return Ok(());
        }

        // Check if this is the context parameter variable
        if let Some(ctx_var) = self.ctx_param
            && var_id == ctx_var
        {
            // Mark this register as holding the context
            let meta = self.get_or_create_metadata(dst);
            meta.is_context = true;
            // Emit a placeholder - actual context access happens in FollowCellPath
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::Const(0), // Placeholder
            });
            return Ok(());
        }

        // Check if this is a captured variable
        for (name, value) in self.captures {
            // We'd need the variable name to match, but we only have var_id
            // For now, check if any capture matches by trying them all
            let _ = (name, value);
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "Variable {} not found in captures or function parameters",
            var_id.get()
        )))
    }

    /// Finish lowering and return the MIR program
    pub fn finish(self) -> MirProgram {
        let mut program = MirProgram::new(self.func);
        program.subfunctions = self.subfunctions;
        program
    }
}

/// Lower Nushell IR to MIR
///
/// This is the main entry point for the IR → MIR conversion.
///
/// The `decl_names` parameter maps DeclId to command names for the eBPF helper
/// commands (emit, count, histogram, etc.). In plugin context, this is built
/// by querying the engine via `find_decl()`.
pub fn lower_ir_to_mir(
    ir_block: &IrBlock,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    closure_irs: &HashMap<nu_protocol::BlockId, IrBlock>,
    captures: &[(String, i64)],
    ctx_param: Option<VarId>,
) -> Result<MirProgram, CompileError> {
    let mut lowering =
        IrToMirLowering::new(ir_block, probe_ctx, decl_names, closure_irs, captures, ctx_param);
    lowering.lower_block(ir_block)?;
    Ok(lowering.finish())
}

/// Simplified lowering context for generating subfunction MIR
/// Used when creating BPF-to-BPF subfunctions from user-defined commands
struct SubfunctionLowering<'a> {
    /// The MIR function being built
    func: &'a mut MirFunction,
    /// IR block to lower
    ir_block: &'a IrBlock,
    /// Parameter VarId -> VReg mappings
    param_map: HashMap<VarId, VReg>,
    /// Nushell RegId -> MIR VReg mappings
    reg_map: HashMap<u32, VReg>,
    /// Current basic block
    current_block: BlockId,
}

impl<'a> SubfunctionLowering<'a> {
    fn new(
        func: &'a mut MirFunction,
        ir_block: &'a IrBlock,
        params: &[(Option<VarId>, VReg)],
    ) -> Self {
        let param_map: HashMap<VarId, VReg> = params
            .iter()
            .filter_map(|(var_id, vreg)| var_id.map(|v| (v, *vreg)))
            .collect();

        Self {
            func,
            ir_block,
            param_map,
            reg_map: HashMap::new(),
            current_block: BlockId(0),
        }
    }

    fn lower(&mut self) -> Result<(), CompileError> {
        self.current_block = self.func.entry;

        for (ir_idx, inst) in self.ir_block.instructions.iter().enumerate() {
            self.lower_instruction(inst, ir_idx)?;
        }

        Ok(())
    }

    fn get_vreg(&mut self, reg: RegId) -> VReg {
        let reg_id = reg.get();
        if let Some(&vreg) = self.reg_map.get(&reg_id) {
            vreg
        } else {
            let vreg = self.func.alloc_vreg();
            self.reg_map.insert(reg_id, vreg);
            vreg
        }
    }

    fn emit(&mut self, inst: MirInst) {
        self.func
            .block_mut(self.current_block)
            .instructions
            .push(inst);
    }

    fn terminate(&mut self, inst: MirInst) {
        self.func.block_mut(self.current_block).terminator = inst;
    }

    fn lower_instruction(
        &mut self,
        inst: &Instruction,
        _ir_idx: usize,
    ) -> Result<(), CompileError> {
        match inst {
            Instruction::LoadLiteral { dst, lit } => {
                let dst_vreg = self.get_vreg(*dst);
                match lit {
                    nu_protocol::ir::Literal::Int(i) => {
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(*i),
                        });
                    }
                    nu_protocol::ir::Literal::Bool(b) => {
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(if *b { 1 } else { 0 }),
                        });
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Unsupported literal type in subfunction".into(),
                        ));
                    }
                }
            }

            Instruction::LoadVariable { dst, var_id } => {
                let dst_vreg = self.get_vreg(*dst);
                if let Some(&param_vreg) = self.param_map.get(var_id) {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(param_vreg),
                    });
                } else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Unknown variable {} in subfunction",
                        var_id.get()
                    )));
                }
            }

            Instruction::Move { dst, src } => {
                let dst_vreg = self.get_vreg(*dst);
                let src_vreg = self.get_vreg(*src);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
            }

            Instruction::BinaryOp { lhs_dst, op, rhs } => {
                use nu_protocol::ast::{Boolean, Comparison, Math, Operator};

                let dst_vreg = self.get_vreg(*lhs_dst);
                let rhs_vreg = self.get_vreg(*rhs);

                let mir_op = match op {
                    Operator::Math(Math::Add) => BinOpKind::Add,
                    Operator::Math(Math::Subtract) => BinOpKind::Sub,
                    Operator::Math(Math::Multiply) => BinOpKind::Mul,
                    Operator::Math(Math::Divide) => BinOpKind::Div,
                    Operator::Math(Math::Modulo) => BinOpKind::Mod,
                    Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
                    Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
                    Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
                    Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
                    Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
                    Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
                    Operator::Bits(nu_protocol::ast::Bits::BitAnd) => BinOpKind::And,
                    Operator::Bits(nu_protocol::ast::Bits::BitOr) => BinOpKind::Or,
                    Operator::Bits(nu_protocol::ast::Bits::BitXor) => BinOpKind::Xor,
                    Operator::Bits(nu_protocol::ast::Bits::ShiftLeft) => BinOpKind::Shl,
                    Operator::Bits(nu_protocol::ast::Bits::ShiftRight) => BinOpKind::Shr,
                    // Logical and/or - use bitwise ops since comparisons return 0 or 1
                    Operator::Boolean(Boolean::And) => BinOpKind::And,
                    Operator::Boolean(Boolean::Or) => BinOpKind::Or,
                    Operator::Boolean(Boolean::Xor) => BinOpKind::Xor,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "Unsupported binary operator {:?} in subfunction",
                            op
                        )));
                    }
                };

                let temp = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: temp,
                    src: MirValue::VReg(dst_vreg),
                });
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: mir_op,
                    lhs: MirValue::VReg(temp),
                    rhs: MirValue::VReg(rhs_vreg),
                });
            }

            Instruction::Return { src } => {
                let src_vreg = self.get_vreg(*src);
                self.terminate(MirInst::Return {
                    val: Some(MirValue::VReg(src_vreg)),
                });
            }

            Instruction::ReturnEarly { src } => {
                let src_vreg = self.get_vreg(*src);
                self.terminate(MirInst::Return {
                    val: Some(MirValue::VReg(src_vreg)),
                });
            }

            // Skip instructions that don't produce code
            Instruction::Drop { .. }
            | Instruction::Drain { .. }
            | Instruction::Clone { .. }
            | Instruction::Collect { .. }
            | Instruction::Span { .. } => {}

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Instruction {:?} not supported in subfunctions",
                    inst
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mir_function_creation() {
        let mut func = MirFunction::new();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        assert_eq!(v0.0, 0);
        assert_eq!(v1.0, 1);
        assert_eq!(func.vreg_count, 2);
    }

    #[test]
    fn test_basic_block_creation() {
        let mut func = MirFunction::new();
        let b0 = func.alloc_block();
        let b1 = func.alloc_block();

        assert_eq!(b0.0, 0);
        assert_eq!(b1.0, 1);
        assert_eq!(func.blocks.len(), 2);
    }

    #[test]
    fn test_list_instructions_creation() {
        // Test that list MIR instructions can be created correctly
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        // Allocate virtual registers
        let list_ptr = func.alloc_vreg();
        let item1 = func.alloc_vreg();
        let item2 = func.alloc_vreg();
        let len = func.alloc_vreg();
        let result = func.alloc_vreg();

        // Allocate stack slot for list buffer
        let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer); // 8 + 8*8 = 72 bytes

        // Create list instructions
        func.block_mut(bb0).instructions.push(MirInst::ListNew {
            dst: list_ptr,
            buffer: slot,
            max_len: 8,
        });

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: item1,
            src: MirValue::Const(42),
        });

        func.block_mut(bb0).instructions.push(MirInst::ListPush {
            list: list_ptr,
            item: item1,
        });

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: item2,
            src: MirValue::Const(100),
        });

        func.block_mut(bb0).instructions.push(MirInst::ListPush {
            list: list_ptr,
            item: item2,
        });

        func.block_mut(bb0).instructions.push(MirInst::ListLen {
            dst: len,
            list: list_ptr,
        });

        func.block_mut(bb0).instructions.push(MirInst::ListGet {
            dst: result,
            list: list_ptr,
            idx: MirValue::Const(0),
        });

        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(result)),
        };

        // Verify instructions were created
        assert_eq!(func.block(bb0).instructions.len(), 7);

        // Verify list instructions have correct structure
        match &func.block(bb0).instructions[0] {
            MirInst::ListNew {
                dst,
                buffer,
                max_len,
            } => {
                assert_eq!(*dst, list_ptr);
                assert_eq!(*buffer, slot);
                assert_eq!(*max_len, 8);
            }
            _ => panic!("Expected ListNew instruction"),
        }

        match &func.block(bb0).instructions[2] {
            MirInst::ListPush { list, item } => {
                assert_eq!(*list, list_ptr);
                assert_eq!(*item, item1);
            }
            _ => panic!("Expected ListPush instruction"),
        }

        match &func.block(bb0).instructions[5] {
            MirInst::ListLen { dst, list } => {
                assert_eq!(*dst, len);
                assert_eq!(*list, list_ptr);
            }
            _ => panic!("Expected ListLen instruction"),
        }

        match &func.block(bb0).instructions[6] {
            MirInst::ListGet { dst, list, idx } => {
                assert_eq!(*dst, result);
                assert_eq!(*list, list_ptr);
                match idx {
                    MirValue::Const(0) => {}
                    _ => panic!("Expected constant index 0"),
                }
            }
            _ => panic!("Expected ListGet instruction"),
        }
    }

    #[test]
    fn test_list_def_and_uses() {
        // Test that list instructions correctly report definitions and uses
        let mut func = MirFunction::new();
        let list_ptr = func.alloc_vreg();
        let item = func.alloc_vreg();
        let len = func.alloc_vreg();
        let result = func.alloc_vreg();
        let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer);

        // ListNew defines dst
        let inst = MirInst::ListNew {
            dst: list_ptr,
            buffer: slot,
            max_len: 8,
        };
        assert_eq!(inst.def(), Some(list_ptr));
        assert!(inst.uses().is_empty());

        // ListPush uses both list and item, defines nothing
        let inst = MirInst::ListPush {
            list: list_ptr,
            item,
        };
        assert_eq!(inst.def(), None);
        let uses = inst.uses();
        assert_eq!(uses.len(), 2);
        assert!(uses.contains(&list_ptr));
        assert!(uses.contains(&item));

        // ListLen defines dst, uses list
        let inst = MirInst::ListLen {
            dst: len,
            list: list_ptr,
        };
        assert_eq!(inst.def(), Some(len));
        let uses = inst.uses();
        assert_eq!(uses.len(), 1);
        assert!(uses.contains(&list_ptr));

        // ListGet defines dst, uses list (and maybe idx if VReg)
        let inst = MirInst::ListGet {
            dst: result,
            list: list_ptr,
            idx: MirValue::Const(0),
        };
        assert_eq!(inst.def(), Some(result));
        let uses = inst.uses();
        assert_eq!(uses.len(), 1);
        assert!(uses.contains(&list_ptr));

        // ListGet with VReg index
        let idx_vreg = func.alloc_vreg();
        let inst = MirInst::ListGet {
            dst: result,
            list: list_ptr,
            idx: MirValue::VReg(idx_vreg),
        };
        let uses = inst.uses();
        assert_eq!(uses.len(), 2);
        assert!(uses.contains(&list_ptr));
        assert!(uses.contains(&idx_vreg));
    }
}
