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
mod control_flow;
mod core_utils;
mod entry;
mod expr_lowering;
mod subfunctions;
mod user_functions;
pub use entry::{
    MirLoweringResult, lower_hir_to_mir, lower_hir_to_mir_with_hints, lower_ir_to_mir,
};

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

// NOTE: SubfunctionLowering has been removed as dead code.
// It was intended for BPF-to-BPF subfunction support but was never integrated.
// If BPF-to-BPF subfunctions are needed in the future, refer to git history
// for the implementation (struct SubfunctionLowering with ~200 lines of code).

#[cfg(test)]
mod tests;
