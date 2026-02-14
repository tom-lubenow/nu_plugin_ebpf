//! HIR to MIR lowering
//!
//! This module converts the compiler's HIR representation into MIR,
//! which is then lowered to eBPF bytecode by mir_to_ebpf.

use std::collections::{HashMap, HashSet};

use nu_protocol::ast::{CellPath, PathMember, Pattern, RangeInclusion};
use nu_protocol::ir::IrBlock;
use nu_protocol::{BlockId as NuBlockId, DeclId, IN_VARIABLE_ID, RegId, Value, VarId};

use super::CompileError;
use super::elf::ProbeContext;
use super::hindley_milner::HMType;
use super::hir::{
    HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
    lower_ir_to_hir,
};
use super::hir_type_infer::HirTypeInfo;
use super::mir::{
    BasicBlock, BinOpKind, BlockId, CtxField, MapKind, MapRef, MirFunction, MirInst, MirProgram,
    MirType, MirTypeHints, MirValue, RecordFieldDef, StackSlotId, StackSlotKind, StringAppendType,
    SubfunctionId, VReg,
};

#[derive(Debug, Clone)]
pub struct UserFunctionSig {
    pub params: Vec<UserParam>,
}

#[derive(Debug, Clone)]
pub struct UserParam {
    pub name: Option<String>,
    pub kind: UserParamKind,
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserParamKind {
    Input,
    Positional,
    Named,
    Switch,
    Rest,
}

/// Maximum string size that eBPF can reliably handle
/// Strings longer than this will be truncated
pub const MAX_STRING_SIZE: usize = 128;
const STRING_APPEND_COPY_CAP: usize = 64;
const MAX_INT_STRING_LEN: usize = 20;

mod closures;
mod user_functions;

#[derive(Debug, Clone, Default)]
struct HirMirTypeHints {
    main: HashMap<u32, MirType>,
    closures: HashMap<NuBlockId, HashMap<u32, MirType>>,
    decls: HashMap<DeclId, HashMap<u32, MirType>>,
}

fn mir_hints_from_hir(type_info: &HirTypeInfo) -> HirMirTypeHints {
    fn convert(map: &HashMap<RegId, HMType>) -> HashMap<u32, MirType> {
        map.iter()
            .filter_map(|(reg, ty)| {
                let mir_ty = ty.to_mir_type()?;
                if matches!(mir_ty, MirType::Unknown) {
                    None
                } else {
                    Some((reg.get(), mir_ty))
                }
            })
            .collect()
    }

    let mut closures = HashMap::new();
    for (block_id, types) in &type_info.closures {
        closures.insert(*block_id, convert(types));
    }
    let mut decls = HashMap::new();
    for (decl_id, types) in &type_info.decls {
        decls.insert(*decl_id, convert(types));
    }

    HirMirTypeHints {
        main: convert(&type_info.main),
        closures,
        decls,
    }
}

fn align_to_eight(len: usize) -> usize {
    (len + 7) & !7
}

/// Maximum entries per eBPF map before data loss may occur
pub const MAX_MAP_ENTRIES: usize = 10240;

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
    /// VReg tracking the current string length for this slot
    string_len_vreg: Option<VReg>,
    /// Max possible content length for the string (excludes padding)
    string_len_bound: Option<usize>,
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

/// Lowering context for HIR to MIR conversion
pub struct HirToMirLowering<'a> {
    /// The MIR function being built
    func: MirFunction,
    /// Mapping from Nushell RegId to MIR VReg
    reg_map: HashMap<u32, VReg>,
    /// Metadata for each register
    reg_metadata: HashMap<u32, RegMetadata>,
    /// Current basic block being built
    current_block: BlockId,
    /// Probe context for field access (reserved for future BTF/CO-RE support)
    #[allow(dead_code)]
    probe_ctx: Option<&'a ProbeContext>,
    /// Mapping from DeclId to command name (for plugin context where engine_state is unavailable)
    decl_names: &'a HashMap<DeclId, String>,
    /// Mapping from BlockId to HirFunction for nested closures (where, each, etc.)
    closure_irs: &'a HashMap<nu_protocol::BlockId, HirFunction>,
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
    /// Mapping from HIR block to MIR block
    hir_block_map: HashMap<HirBlockId, BlockId>,
    /// Loop body initializations (copy counter into dst)
    loop_body_inits: HashMap<BlockId, Vec<(VReg, VReg)>>,
    /// Type hints for the current HIR function (RegId -> MirType)
    current_type_hints: HashMap<u32, MirType>,
    /// Type hints for closure HIR functions (BlockId -> RegId -> MirType)
    closure_type_hints: HashMap<NuBlockId, HashMap<u32, MirType>>,
    /// Type hints for user-defined functions (DeclId -> RegId -> MirType)
    decl_type_hints: HashMap<DeclId, HashMap<u32, MirType>>,
    /// Collected MIR type hints (VReg -> MirType)
    vreg_type_hints: HashMap<VReg, MirType>,
    /// User-defined functions by DeclId
    user_functions: &'a HashMap<DeclId, HirFunction>,
    /// User-defined function signatures by DeclId
    decl_signatures: &'a HashMap<DeclId, UserFunctionSig>,
    /// Cached parameter VarIds for user-defined functions
    subfunction_params: HashMap<DeclId, Vec<VarId>>,
    /// Subfunction vreg type hints (aligned with subfunctions vec)
    subfunction_hints: Vec<HashMap<VReg, MirType>>,
    /// Subfunctions currently being lowered (recursion guard)
    subfunction_in_progress: HashSet<DeclId>,
    /// Generated subfunctions
    subfunctions: Vec<MirFunction>,
    /// Registry of generated subfunctions by DeclId
    /// Reserved for future BPF-to-BPF subfunction support
    #[allow(dead_code)]
    subfunction_registry: HashMap<DeclId, SubfunctionId>,
    /// Call count for each user function (for inline vs subfunction decision)
    /// Reserved for future BPF-to-BPF subfunction support
    #[allow(dead_code)]
    call_counts: HashMap<DeclId, usize>,
}

impl<'a> HirToMirLowering<'a> {
    /// Create a new lowering context
    fn new(
        probe_ctx: Option<&'a ProbeContext>,
        decl_names: &'a HashMap<DeclId, String>,
        closure_irs: &'a HashMap<nu_protocol::BlockId, HirFunction>,
        captures: &'a [(String, i64)],
        ctx_param: Option<VarId>,
        type_hints: Option<&'a HirMirTypeHints>,
        user_functions: &'a HashMap<DeclId, HirFunction>,
        decl_signatures: &'a HashMap<DeclId, UserFunctionSig>,
    ) -> Self {
        let (current_type_hints, closure_type_hints, decl_type_hints) = match type_hints {
            Some(hints) => (
                hints.main.clone(),
                hints.closures.clone(),
                hints.decls.clone(),
            ),
            None => (HashMap::new(), HashMap::new(), HashMap::new()),
        };
        Self {
            func: MirFunction::new(),
            reg_map: HashMap::new(),
            reg_metadata: HashMap::new(),
            current_block: BlockId(0),
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
            hir_block_map: HashMap::new(),
            loop_body_inits: HashMap::new(),
            current_type_hints,
            closure_type_hints,
            decl_type_hints,
            vreg_type_hints: HashMap::new(),
            user_functions,
            decl_signatures,
            subfunction_params: HashMap::new(),
            subfunction_hints: Vec::new(),
            subfunction_in_progress: HashSet::new(),
            subfunctions: Vec::new(),
            subfunction_registry: HashMap::new(),
            call_counts: HashMap::new(),
        }
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
            if let Some(hint) = self.current_type_hints.get(&reg_id) {
                self.vreg_type_hints
                    .entry(vreg)
                    .or_insert_with(|| hint.clone());
            }
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

    fn stack_slot_size(&self, slot: StackSlotId) -> Option<usize> {
        self.func
            .stack_slots
            .iter()
            .find(|s| s.id == slot)
            .map(|s| s.size)
    }

    fn ensure_string_slot_capacity(
        &mut self,
        slot: StackSlotId,
        required_len: usize,
    ) -> Result<usize, CompileError> {
        if required_len.saturating_add(1) > MAX_STRING_SIZE {
            return Err(CompileError::UnsupportedInstruction(format!(
                "string interpolation requires {} bytes (limit {})",
                required_len + 1,
                MAX_STRING_SIZE
            )));
        }

        let needed = align_to_eight(required_len.saturating_add(1))
            .min(MAX_STRING_SIZE)
            .max(16);
        let slot_entry = self
            .func
            .stack_slots
            .iter_mut()
            .find(|s| s.id == slot)
            .ok_or_else(|| CompileError::UnsupportedInstruction("string slot not found".into()))?;

        if needed > slot_entry.size {
            let old_size = slot_entry.size;
            slot_entry.size = needed;

            let mut offset = old_size;
            while offset < needed {
                self.emit(MirInst::StoreSlot {
                    slot,
                    offset: offset as i32,
                    val: MirValue::Const(0),
                    ty: MirType::U64,
                });
                offset += 8;
            }
        }

        Ok(needed)
    }

    /// Set the terminator for the current block
    fn terminate(&mut self, inst: MirInst) {
        self.func.block_mut(self.current_block).terminator = inst;
    }

    /// Lower an entire HIR function to MIR
    pub fn lower_block(&mut self, hir: &HirFunction) -> Result<(), CompileError> {
        self.hir_block_map.clear();
        for block in &hir.blocks {
            let mir_block = self.func.alloc_block();
            self.hir_block_map.insert(block.id, mir_block);
        }

        if let Some(entry) = self.hir_block_map.get(&hir.entry).copied() {
            self.func.entry = entry;
        }

        for block in &hir.blocks {
            self.current_block = *self.hir_block_map.get(&block.id).ok_or_else(|| {
                CompileError::UnsupportedInstruction("HIR block mapping missing".into())
            })?;

            if let Some(inits) = self.loop_body_inits.remove(&self.current_block) {
                for (dst, src) in inits {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(src),
                    });
                }
            }

            for stmt in &block.stmts {
                self.lower_stmt(stmt)?;
            }
            self.lower_terminator(&block.terminator)?;
        }

        Ok(())
    }

    /// Lower a single HIR statement to MIR
    fn lower_stmt(&mut self, instruction: &HirStmt) -> Result<(), CompileError> {
        match instruction {
            // === Data Movement ===
            HirStmt::LoadLiteral { dst, lit } => {
                self.lower_load_literal(*dst, lit)?;
            }

            HirStmt::LoadValue { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "LoadValue is not supported in eBPF lowering".into(),
                ));
            }

            HirStmt::Move { dst, src } => {
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

            HirStmt::Clone { dst, src } => {
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
            HirStmt::BinaryOp { lhs_dst, op, rhs } => {
                self.lower_binary_op(*lhs_dst, *op, *rhs)?;
            }

            HirStmt::Not { src_dst } => {
                let vreg = self.get_vreg(*src_dst);
                self.emit(MirInst::UnaryOp {
                    dst: vreg,
                    op: super::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(vreg),
                });
            }

            // === Field Access ===
            HirStmt::FollowCellPath { src_dst, path } => {
                self.lower_follow_cell_path(*src_dst, *path)?;
            }

            HirStmt::CloneCellPath { dst, src, path } => {
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
                self.lower_follow_cell_path(*dst, *path)?;
            }

            HirStmt::UpsertCellPath {
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
                    "Cell path update (.{} = ...) is not supported in eBPF.                      Consider building the record with the correct value initially.",
                    path_str
                )));
            }

            // === Commands ===
            HirStmt::Call {
                decl_id,
                src_dst,
                args,
            } => {
                self.set_call_args(args)?;
                self.lower_call(*decl_id, *src_dst)?;
            }

            // === Records ===
            HirStmt::RecordInsert { src_dst, key, val } => {
                self.lower_record_insert(*src_dst, *key, *val)?;
            }

            HirStmt::RecordSpread { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Record spread is not supported in eBPF".into(),
                ));
            }

            // === Lists ===
            HirStmt::ListPush { src_dst, item } => {
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

            HirStmt::ListSpread { src_dst, items } => {
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
            HirStmt::StringAppend { src_dst, val } => {
                let dst_slot = self.get_metadata(*src_dst).and_then(|m| m.string_slot);
                let val_meta = self.get_metadata(*val).cloned();

                // For string append, we need:
                // 1. A string buffer (from Literal::String or a built interpolation)
                // 2. A value to append (string, int, etc.)
                if let Some(slot) = dst_slot {
                    let len_vreg_existing =
                        self.get_metadata(*src_dst).and_then(|m| m.string_len_vreg);
                    let len_was_missing = len_vreg_existing.is_none();
                    let len_vreg = len_vreg_existing.unwrap_or_else(|| {
                        let len_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::Copy {
                            dst: len_vreg,
                            src: MirValue::Const(0),
                        });
                        len_vreg
                    });

                    if len_was_missing {
                        let meta = self.get_or_create_metadata(*src_dst);
                        meta.string_len_vreg = Some(len_vreg);
                    }

                    // Determine what type of value we're appending and its max length.
                    let (val_type, append_max) = if val_meta
                        .as_ref()
                        .map(|m| m.string_slot.is_some())
                        .unwrap_or(false)
                    {
                        let val_slot = val_meta.as_ref().unwrap().string_slot.unwrap();
                        let max_len = val_meta
                            .as_ref()
                            .and_then(|m| m.string_len_bound)
                            .or_else(|| self.stack_slot_size(val_slot).map(|s| s.saturating_sub(1)))
                            .unwrap_or(0);
                        let append_max = max_len.min(STRING_APPEND_COPY_CAP);
                        (
                            StringAppendType::StringSlot {
                                slot: val_slot,
                                max_len: append_max,
                            },
                            append_max,
                        )
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
                        let append_max = bytes
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|idx| idx + 1)
                            .unwrap_or(0);
                        (StringAppendType::Literal { bytes }, append_max)
                    } else {
                        // Default to integer
                        (StringAppendType::Integer, MAX_INT_STRING_LEN)
                    };

                    let slot_size = self.stack_slot_size(slot).unwrap_or(0);
                    let current_bound = self
                        .get_metadata(*src_dst)
                        .and_then(|m| m.string_len_bound)
                        .unwrap_or_else(|| {
                            if len_was_missing {
                                0
                            } else {
                                slot_size.saturating_sub(1)
                            }
                        });
                    let new_bound = current_bound.saturating_add(append_max);
                    let new_size = self.ensure_string_slot_capacity(slot, new_bound)?;
                    let meta = self.get_or_create_metadata(*src_dst);
                    meta.string_len_bound = Some(new_bound);
                    meta.field_type = Some(MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: new_size,
                    });

                    let val_vreg = self.get_vreg(*val);
                    self.emit(MirInst::StringAppend {
                        dst_buffer: slot,
                        dst_len: len_vreg,
                        val: MirValue::VReg(val_vreg),
                        val_type,
                    });
                }
            }

            HirStmt::GlobFrom { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Glob expansion is not supported in eBPF".into(),
                ));
            }

            // === Variables ===
            HirStmt::LoadVariable { dst, var_id } => {
                self.lower_load_variable(*dst, *var_id)?;
            }

            HirStmt::StoreVariable { var_id, src } => {
                let src_vreg = self.get_vreg(*src);
                let preserved = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: preserved,
                    src: MirValue::VReg(src_vreg),
                });
                self.var_mappings.insert(*var_id, preserved);
            }

            HirStmt::DropVariable { var_id } => {
                self.var_mappings.remove(var_id);
            }

            // === Environment Variables (not supported in eBPF) ===
            HirStmt::LoadEnv { key, .. } | HirStmt::LoadEnvOpt { key, .. } => {
                // Environment variables are not accessible from eBPF (kernel space)
                // Get the key name for a better error message
                let key_name = std::str::from_utf8(key).unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Environment variable access ($env.{}) is not supported in eBPF.                      eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            HirStmt::StoreEnv { key, .. } => {
                let key_name = std::str::from_utf8(key).unwrap_or("<unknown>");
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Setting environment variable ($env.{}) is not supported in eBPF.                      eBPF programs run in kernel space without access to user environment.",
                    key_name
                )));
            }

            // === No-ops ===
            HirStmt::Span { .. }
            | HirStmt::Collect { .. }
            | HirStmt::Drop { .. }
            | HirStmt::Drain { .. }
            | HirStmt::DrainIfEnd { .. }
            | HirStmt::CheckErrRedirected { .. }
            | HirStmt::OpenFile { .. }
            | HirStmt::WriteFile { .. }
            | HirStmt::CloseFile { .. }
            | HirStmt::RedirectOut { .. }
            | HirStmt::RedirectErr { .. }
            | HirStmt::OnError { .. }
            | HirStmt::OnErrorInto { .. }
            | HirStmt::PopErrorHandler
            | HirStmt::CheckMatchGuard { .. } => {
                // No-ops in eBPF (no spans/streams/redirection/files)
            }
        }
        Ok(())
    }

    fn lower_terminator(&mut self, term: &HirTerminator) -> Result<(), CompileError> {
        match term {
            HirTerminator::Goto { target } => {
                let target = *self
                    .hir_block_map
                    .get(target)
                    .ok_or_else(|| CompileError::UnsupportedInstruction("Invalid block".into()))?;
                self.terminate(MirInst::Jump { target });
            }
            HirTerminator::Jump { target } => {
                let target_block = *self
                    .hir_block_map
                    .get(target)
                    .ok_or_else(|| CompileError::UnsupportedInstruction("Invalid block".into()))?;
                if let Some(loop_ctx) = self.loop_contexts.last() {
                    if target_block == loop_ctx.header_block {
                        self.terminate(MirInst::LoopBack {
                            counter: loop_ctx.counter_vreg,
                            step: loop_ctx.step,
                            header: loop_ctx.header_block,
                        });
                        return Ok(());
                    }
                    if target_block == loop_ctx.exit_block {
                        self.loop_contexts.pop();
                        self.terminate(MirInst::Jump {
                            target: target_block,
                        });
                        return Ok(());
                    }
                }
                self.terminate(MirInst::Jump {
                    target: target_block,
                });
            }
            HirTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } => {
                let if_true = *self.hir_block_map.get(if_true).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let if_false = *self.hir_block_map.get(if_false).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid branch target".into())
                })?;
                let cond_vreg = self.get_vreg(*cond);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
                    if_true,
                    if_false,
                });
            }
            HirTerminator::BranchIfEmpty { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "BranchIfEmpty is not supported in eBPF".into(),
                ));
            }
            HirTerminator::Match {
                pattern,
                src,
                if_true,
                if_false,
            } => {
                let if_true = *self.hir_block_map.get(if_true).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid match target".into())
                })?;
                let if_false = *self.hir_block_map.get(if_false).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid match target".into())
                })?;
                self.lower_match(pattern, *src, if_true, if_false)?;
            }
            HirTerminator::Iterate {
                dst,
                stream,
                body,
                end,
            } => {
                let range = self
                    .get_metadata(*stream)
                    .and_then(|m| m.bounded_range)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Iterate requires a compile-time known range (e.g., 1..10)".into(),
                        )
                    })?;

                let dst_vreg = self.get_vreg(*dst);
                let counter_vreg = self.get_vreg(*stream);

                let limit = if range.inclusive {
                    range.end + range.step.signum()
                } else {
                    range.end
                };

                let body_block = *self.hir_block_map.get(body).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop body".into())
                })?;
                let exit_block = *self.hir_block_map.get(end).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("Invalid loop exit".into())
                })?;

                self.terminate(MirInst::LoopHeader {
                    counter: counter_vreg,
                    limit,
                    body: body_block,
                    exit: exit_block,
                });

                self.loop_body_inits
                    .entry(body_block)
                    .or_default()
                    .push((dst_vreg, counter_vreg));

                self.loop_contexts.push(LoopContext {
                    header_block: self.current_block,
                    exit_block,
                    counter_vreg,
                    step: range.step,
                });
            }
            HirTerminator::Return { src } => {
                let val = Some(MirValue::VReg(self.get_vreg(*src)));
                self.terminate(MirInst::Return { val });
            }
            HirTerminator::ReturnEarly { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Return early is not supported in eBPF".into(),
                ));
            }
            HirTerminator::Unreachable => {
                return Err(CompileError::UnsupportedInstruction(
                    "Encountered unreachable block".into(),
                ));
            }
        }
        Ok(())
    }

    fn set_call_args(&mut self, args: &HirCallArgs) -> Result<(), CompileError> {
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();

        for reg in &args.positional {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for reg in &args.rest {
            let vreg = self.get_vreg(*reg);
            self.positional_args.push((vreg, *reg));
        }
        for (name, reg) in &args.named {
            let name = std::str::from_utf8(name)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid arg name".into()))?
                .to_string();
            let vreg = self.get_vreg(*reg);
            self.named_args.insert(name, (vreg, *reg));
        }
        for flag in &args.flags {
            let flag = std::str::from_utf8(flag)
                .map_err(|_| CompileError::UnsupportedInstruction("Invalid flag name".into()))?
                .to_string();
            self.named_flags.push(flag);
        }

        Ok(())
    }

    fn clear_call_state(&mut self) {
        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        self.positional_args.clear();
        self.named_flags.clear();
        self.named_args.clear();
    }

    fn const_vreg(&mut self, value: i64) -> VReg {
        let vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: vreg,
            src: MirValue::Const(value),
        });
        vreg
    }

    fn input_vreg_for_call(&mut self, src_dst: RegId) -> VReg {
        if let Some(vreg) = self.pipeline_input {
            return vreg;
        }
        if self.reg_map.contains_key(&src_dst.get()) {
            return self.get_vreg(src_dst);
        }
        self.const_vreg(0)
    }

    fn lower_load_literal(&mut self, dst: RegId, lit: &HirLiteral) -> Result<(), CompileError> {
        let dst_vreg = self.get_vreg(dst);

        match lit {
            HirLiteral::Int(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(*val),
                });
                // Track literal value for constant propagation
                let meta = self.get_or_create_metadata(dst);
                meta.literal_int = Some(*val);
            }

            HirLiteral::Bool(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
            }

            HirLiteral::String(bytes) => {
                // Warn if string exceeds eBPF limits
                let string_len = bytes.len();
                let max_content_len = MAX_STRING_SIZE.saturating_sub(1);
                if string_len > max_content_len {
                    eprintln!(
                        "Warning: string literal ({} bytes) exceeds eBPF limit of {} bytes and will be truncated",
                        string_len, max_content_len
                    );
                }
                let content_len = bytes.len().min(max_content_len);
                let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);

                // Allocate stack slot for string buffer (aligned for emit)
                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);

                // Build literal bytes with null terminator and zero padding
                let mut literal_bytes = vec![0u8; aligned_len];
                literal_bytes[..content_len].copy_from_slice(&bytes[..content_len]);
                // literal_bytes is zero-initialized, so null + padding are already zeroed.

                // Write literal bytes into the buffer at runtime
                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: len_vreg,
                    src: MirValue::Const(0),
                });
                self.emit(MirInst::StringAppend {
                    dst_buffer: slot,
                    dst_len: len_vreg,
                    val: MirValue::Const(0),
                    val_type: StringAppendType::Literal {
                        bytes: literal_bytes,
                    },
                });

                let string_value = std::str::from_utf8(&bytes[..content_len])
                    .ok()
                    .map(|s| s.to_string());

                // Record slot pointer in a vreg
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                // Track the string slot and value
                let meta = self.get_or_create_metadata(dst);
                meta.string_slot = Some(slot);
                meta.string_len_vreg = Some(len_vreg);
                meta.string_len_bound = Some(content_len);
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
                // Also track the literal string value for record field names
                if let Some(s) = string_value {
                    meta.literal_string = Some(s);
                }
            }

            HirLiteral::CellPath(cell_path) => {
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

            HirLiteral::Record { capacity: _ } => {
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

            HirLiteral::Range {
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

            HirLiteral::List { capacity } => {
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

            HirLiteral::Closure(block_id) => {
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

            HirLiteral::Block(block_id) => {
                // Track block ID same as closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::RowCondition(block_id) => {
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

    /// Lower Match instruction (used for pattern matching and short-circuit boolean evaluation)
    fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        if_true: BlockId,
        if_false: BlockId,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);

        match pattern {
            Pattern::Value(value) => match value {
                Value::Bool { val, .. } => {
                    if *val {
                        self.terminate(MirInst::Branch {
                            cond: src_vreg,
                            if_true,
                            if_false,
                        });
                    } else {
                        let tmp = self.func.alloc_vreg();
                        self.emit(MirInst::UnaryOp {
                            dst: tmp,
                            op: super::mir::UnaryOpKind::Not,
                            src: MirValue::VReg(src_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: tmp,
                            if_true,
                            if_false,
                        });
                    }
                }
                Value::Nothing { .. } => {
                    let cmp_result = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: cmp_result,
                        op: BinOpKind::Eq,
                        lhs: MirValue::VReg(src_vreg),
                        rhs: MirValue::Const(0),
                    });
                    self.terminate(MirInst::Branch {
                        cond: cmp_result,
                        if_true,
                        if_false,
                    });
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Match against value type {:?} not supported in eBPF",
                        value.get_type()
                    )));
                }
            },
            Pattern::Variable(var_id) => {
                self.var_mappings.insert(*var_id, src_vreg);
                self.terminate(MirInst::Jump { target: if_true });
            }
            Pattern::IgnoreValue => {
                self.terminate(MirInst::Jump { target: if_true });
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "Pattern matching not supported in eBPF".into(),
                ));
            }
        }
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
        let slot = self.get_metadata(src_dst).and_then(|m| m.string_slot);
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field.clone(),
            slot,
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
        let src_dst_had_value = self.reg_map.contains_key(&src_dst.get());
        let dst_vreg = self.get_vreg(src_dst);

        if self.user_functions.contains_key(&decl_id) {
            self.lower_user_function_call(decl_id, src_dst, dst_vreg)?;
            self.clear_call_state();
            return Ok(());
        }

        // Look up command name from our decl_names mapping
        let cmd_name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

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
                    Some(MirType::Array { ref elem, len })
                        if matches!(elem.as_ref(), MirType::U8) =>
                    {
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

                // Map update increments counter for key
                self.emit(MirInst::MapUpdate {
                    map: MapRef {
                        name: map_name.to_string(),
                        kind: map_kind,
                    },
                    key: key_vreg,
                    val: dst_vreg, // handled specially in MIR->eBPF
                    flags: 0,
                });

                // Return 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });

                // Set type for key (useful for pointer safety)
                let meta = self.get_or_create_metadata(src_dst);
                meta.field_type = key_type;
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

            "read-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);

                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: true,
                    max_len: aligned_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.string_len_bound = Some(aligned_len.saturating_sub(1));
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
            }

            "read-kernel-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-kernel-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);

                let slot = self
                    .func
                    .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: false,
                    max_len: aligned_len,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                let meta = self.get_or_create_metadata(src_dst);
                meta.string_slot = Some(slot);
                meta.string_len_bound = Some(aligned_len.saturating_sub(1));
                meta.field_type = Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: aligned_len,
                });
            }

            "kfunc-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "kfunc-call does not accept flags".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "kfunc-call requires a literal kfunc name as the first positional argument"
                            .into(),
                    )
                })?;

                let kfunc = self
                    .get_metadata(name_reg)
                    .and_then(|m| m.literal_string.clone())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call requires first positional argument to be a string literal"
                                .into(),
                        )
                    })?;

                let btf_id = if let Some((_, reg)) = self.named_args.get("btf-id") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "kfunc-call --btf-id must be a compile-time integer literal".into(),
                            )
                        })?;
                    Some(u32::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call --btf-id must be >= 0".into(),
                        )
                    })?)
                } else {
                    None
                };

                for key in self.named_args.keys() {
                    if key != "btf-id" {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "kfunc-call does not accept named argument '{}'",
                            key
                        )));
                    }
                }

                let mut args = Vec::new();
                if let Some(input) = self.pipeline_input {
                    args.push(input);
                } else if src_dst_had_value {
                    args.push(dst_vreg);
                }

                for (arg_vreg, _) in self.positional_args.iter().skip(1) {
                    args.push(*arg_vreg);
                }

                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF kfunc calls support at most 5 arguments".into(),
                    ));
                }

                self.emit(MirInst::CallKfunc {
                    dst: dst_vreg,
                    kfunc,
                    btf_id,
                    args,
                });
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
                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;

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
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "where requires a closure argument".into(),
                    ));
                }
            }

            "each" => {
                // each { closure } - transform pipeline values
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Look up the closure IR
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;

                    // For lists, we can map each element
                    let meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                    if let Some(meta) = meta {
                        if let Some((_slot, max_len)) = meta.list_buffer {
                            // Create a new list for output
                            let out_slot = self.func.alloc_stack_slot(
                                align_to_eight(8 + max_len * 8),
                                8,
                                StackSlotKind::ListBuffer,
                            );
                            self.emit(MirInst::ListNew {
                                dst: dst_vreg,
                                buffer: out_slot,
                                max_len,
                            });

                            for i in 0..max_len {
                                let elem_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::ListGet {
                                    dst: elem_vreg,
                                    list: input_vreg,
                                    idx: MirValue::Const(i as i64),
                                });

                                // Transform element with closure
                                let transformed =
                                    self.inline_closure_with_in(block_id, closure_ir, elem_vreg)?;
                                self.emit(MirInst::ListPush {
                                    list: dst_vreg,
                                    item: transformed,
                                });
                            }

                            // Copy metadata for output list
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.list_buffer = Some((out_slot, max_len));
                            out_meta.field_type = meta.field_type;
                            return Ok(());
                        }
                    }

                    // Default: apply closure and return transformed value
                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(result_vreg),
                    });

                    // Copy metadata from input to output
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "each requires a closure argument".into(),
                    ));
                }
            }

            "skip" => {
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Skip expects a positional argument for count
                let skip_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(0);

                if skip_count <= 0 {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    return Ok(());
                }

                // Create a counter vreg to track how many items have been skipped
                let counter = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: counter,
                    src: MirValue::Const(0),
                });

                let loop_header = self.func.alloc_block();
                let loop_body = self.func.alloc_block();
                let loop_exit = self.func.alloc_block();

                self.terminate(MirInst::LoopHeader {
                    counter,
                    limit: skip_count,
                    body: loop_body,
                    exit: loop_exit,
                });

                self.current_block = loop_body;
                self.terminate(MirInst::LoopBack {
                    counter,
                    step: 1,
                    header: loop_header,
                });

                self.current_block = loop_exit;

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(input_vreg),
                });

                if let Some(reg) = input_reg {
                    if let Some(meta) = self.get_metadata(reg).cloned() {
                        let out_meta = self.get_or_create_metadata(src_dst);
                        out_meta.field_type = meta.field_type;
                        out_meta.string_slot = meta.string_slot;
                        out_meta.record_fields = meta.record_fields;
                    }
                }
            }

            "first" | "last" => {
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                let take_count = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1);

                if take_count <= 0 {
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    return Ok(());
                }

                if cmd_name == "first" {
                    // Just pass the first element through
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    // For 'last', we need to loop to the end (not practical in eBPF)
                    // So we'll just return the input value for now
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                }
            }

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Command '{}' not supported in eBPF",
                    cmd_name
                )));
            }
        }

        self.clear_call_state();
        Ok(())
    }

    fn get_or_create_subfunction(
        &mut self,
        decl_id: DeclId,
    ) -> Result<SubfunctionId, CompileError> {
        if let Some(&subfn_id) = self.subfunction_registry.get(&decl_id) {
            return Ok(subfn_id);
        }

        let hir = self.user_functions.get(&decl_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "User-defined function {} not found",
                decl_id.get()
            ))
        })?;

        if !self.subfunction_in_progress.insert(decl_id) {
            return Err(CompileError::UnsupportedInstruction(
                "Recursive user-defined functions are not supported in eBPF".into(),
            ));
        }

        let param_vars = self.subfunction_params(decl_id, hir);
        let sig = self.decl_signatures.get(&decl_id);
        let input_reg = Self::infer_pipeline_input_reg(hir);
        let uses_in = Self::uses_in_variable(hir);
        let needs_input = input_reg.is_some() || uses_in;
        let name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        let mut subfn = MirFunction::with_name(name);
        let sig_param_count = sig.map(Self::sig_param_count);
        let param_count = sig_param_count.unwrap_or(param_vars.len());
        subfn.param_count = param_count + usize::from(needs_input);

        let old_func = std::mem::replace(&mut self.func, subfn);
        let old_reg_map = std::mem::take(&mut self.reg_map);
        let old_reg_metadata = std::mem::take(&mut self.reg_metadata);
        let old_current_block = self.current_block;
        let old_pipeline_input = self.pipeline_input.take();
        let old_pipeline_input_reg = self.pipeline_input_reg.take();
        let old_positional_args = std::mem::take(&mut self.positional_args);
        let old_named_flags = std::mem::take(&mut self.named_flags);
        let old_named_args = std::mem::take(&mut self.named_args);
        let old_var_mappings = std::mem::take(&mut self.var_mappings);
        let old_loop_contexts = std::mem::take(&mut self.loop_contexts);
        let old_hir_block_map = std::mem::take(&mut self.hir_block_map);
        let old_loop_body_inits = std::mem::take(&mut self.loop_body_inits);
        let old_type_hints = std::mem::replace(
            &mut self.current_type_hints,
            self.decl_type_hints
                .get(&decl_id)
                .cloned()
                .unwrap_or_default(),
        );
        let old_vreg_hints = std::mem::take(&mut self.vreg_type_hints);
        let old_ctx_param = self.ctx_param;

        self.ctx_param = None;

        let param_base = Self::infer_param_base_var_id(hir);
        if needs_input {
            let vreg = self.func.alloc_vreg();
            if let Some(reg) = input_reg {
                self.reg_map.insert(reg.get(), vreg);
            }
            if uses_in {
                self.var_mappings.insert(IN_VARIABLE_ID, vreg);
            }
        }

        if let Some(base) = param_base {
            let base = base.get();
            for i in 0..param_count {
                let vreg = self.func.alloc_vreg();
                let var_id = VarId::new(base + i);
                self.var_mappings.insert(var_id, vreg);
            }
        } else {
            for var_id in &param_vars {
                let vreg = self.func.alloc_vreg();
                self.var_mappings.insert(*var_id, vreg);
            }
            for _ in param_vars.len()..param_count {
                let _unused = self.func.alloc_vreg();
            }
        }

        let result = self.lower_block(hir);

        let subfn = std::mem::replace(&mut self.func, old_func);
        let subfn_hints = std::mem::replace(&mut self.vreg_type_hints, old_vreg_hints);

        self.reg_map = old_reg_map;
        self.reg_metadata = old_reg_metadata;
        self.current_block = old_current_block;
        self.pipeline_input = old_pipeline_input;
        self.pipeline_input_reg = old_pipeline_input_reg;
        self.positional_args = old_positional_args;
        self.named_flags = old_named_flags;
        self.named_args = old_named_args;
        self.var_mappings = old_var_mappings;
        self.loop_contexts = old_loop_contexts;
        self.hir_block_map = old_hir_block_map;
        self.loop_body_inits = old_loop_body_inits;
        self.current_type_hints = old_type_hints;
        self.ctx_param = old_ctx_param;

        self.subfunction_in_progress.remove(&decl_id);

        if let Err(err) = result {
            return Err(err);
        }

        let subfn_id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(subfn);
        self.subfunction_hints.push(subfn_hints);
        self.subfunction_registry.insert(decl_id, subfn_id);

        Ok(subfn_id)
    }

    pub fn finish(self) -> MirProgram {
        let (program, _) = self.finish_with_hints();
        program
    }

    pub fn finish_with_hints(self) -> (MirProgram, MirTypeHints) {
        let mut program = MirProgram::new(self.func);
        program.subfunctions = self.subfunctions;
        let mut hints = MirTypeHints {
            main: self.vreg_type_hints,
            subfunctions: self.subfunction_hints,
        };
        if hints.subfunctions.len() < program.subfunctions.len() {
            hints
                .subfunctions
                .resize_with(program.subfunctions.len(), HashMap::new);
        }
        (program, hints)
    }
}

/// Lower HIR to MIR
///
/// This is the main entry point for the HIR → MIR conversion.
///
/// The `decl_names` parameter maps DeclId to command names for the eBPF helper
/// commands (emit, count, histogram, etc.). In plugin context, this is built
/// by querying the engine via `find_decl()`.
pub struct MirLoweringResult {
    pub program: MirProgram,
    pub type_hints: MirTypeHints,
}

pub fn lower_hir_to_mir_with_hints(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    type_info: Option<&HirTypeInfo>,
    user_functions: &HashMap<DeclId, HirFunction>,
    decl_signatures: &HashMap<DeclId, UserFunctionSig>,
) -> Result<MirLoweringResult, CompileError> {
    let hir_type_hints = type_info.map(mir_hints_from_hir);
    let mut lowering = HirToMirLowering::new(
        probe_ctx,
        decl_names,
        &hir.closures,
        &hir.captures,
        hir.ctx_param,
        hir_type_hints.as_ref(),
        user_functions,
        decl_signatures,
    );
    lowering.lower_block(&hir.main)?;
    let (program, type_hints) = lowering.finish_with_hints();
    Ok(MirLoweringResult {
        program,
        type_hints,
    })
}

pub fn lower_hir_to_mir(
    hir: &HirProgram,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
) -> Result<MirProgram, CompileError> {
    let empty_user_functions = HashMap::new();
    let empty_signatures = HashMap::new();
    let result = lower_hir_to_mir_with_hints(
        hir,
        probe_ctx,
        decl_names,
        None,
        &empty_user_functions,
        &empty_signatures,
    )?;
    Ok(result.program)
}

/// Lower Nushell IR to MIR
///
/// This preserves the old entry point by converting IR → HIR → MIR.
pub fn lower_ir_to_mir(
    ir_block: &IrBlock,
    probe_ctx: Option<&ProbeContext>,
    decl_names: &HashMap<DeclId, String>,
    closure_irs: &HashMap<nu_protocol::BlockId, IrBlock>,
    captures: &[(String, i64)],
    ctx_param: Option<VarId>,
) -> Result<MirProgram, CompileError> {
    let hir_program = lower_ir_to_hir(
        ir_block.clone(),
        closure_irs.clone(),
        captures.to_vec(),
        ctx_param,
    )?;
    lower_hir_to_mir(&hir_program, probe_ctx, decl_names)
}

// NOTE: SubfunctionLowering has been removed as dead code.
// It was intended for BPF-to-BPF subfunction support but was never integrated.
// If BPF-to-BPF subfunctions are needed in the future, refer to git history
// for the implementation (struct SubfunctionLowering with ~200 lines of code).

#[cfg(test)]
mod tests;
