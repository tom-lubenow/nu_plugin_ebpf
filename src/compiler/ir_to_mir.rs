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

mod calls;
mod closures;
mod core_utils;
mod expr_lowering;
mod subfunctions;
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
