//! High-level intermediate representation (HIR).
//!
//! HIR is a structured, compiler-owned AST that normalizes Nushell IR:
//! - DataSlice-backed fields are converted into owned bytes.
//! - Implicit call-argument stacks are made explicit.
//! - Control flow is expressed with block terminators instead of indices.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, FixedOffset};
use nu_protocol::ast::{CellPath, Expression, Operator, Pattern, RangeInclusion};
use nu_protocol::ir::{Instruction, IrAstRef, IrBlock, Literal, RedirectMode};
use nu_protocol::{BlockId as NuBlockId, DeclId, Filesize, RegId, Span, Type, Value, VarId};

use super::CompileError;

mod lowering;
pub use lowering::lower_ir_to_hir;

#[derive(Debug, Clone)]
pub struct HirProgram {
    pub main: HirFunction,
    pub closures: HashMap<NuBlockId, HirFunction>,
    /// Source-recovered parameter order for nested closures whose compiled IR
    /// only contains variables that are actually used.
    pub closure_param_sources: HashMap<NuBlockId, HirClosureParamSource>,
    pub captures: Vec<(VarId, Value)>,
    pub ctx_param: Option<VarId>,
    /// Leading annotated `mut` bindings in the attached closure that should be
    /// lowered as compiler-managed mutable globals instead of per-invocation locals.
    pub annotated_mut_globals: Vec<AnnotatedMutGlobal>,
}

#[derive(Debug, Clone)]
pub struct HirClosureParamSource {
    pub params: Vec<HirClosureParam>,
}

#[derive(Debug, Clone)]
pub struct HirClosureParam {
    pub name: String,
    pub var_id: Option<VarId>,
}

#[derive(Debug, Clone)]
pub struct AnnotatedMutGlobal {
    pub var_id: VarId,
    pub declared_type: Type,
    pub initial_value: Value,
}

impl HirProgram {
    pub fn new(
        main: HirFunction,
        closures: HashMap<NuBlockId, HirFunction>,
        captures: Vec<(VarId, Value)>,
        ctx_param: Option<VarId>,
    ) -> Self {
        Self {
            main,
            closures,
            closure_param_sources: HashMap::new(),
            captures,
            ctx_param,
            annotated_mut_globals: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HirBlockId(pub usize);

#[derive(Debug, Clone)]
pub struct HirFunction {
    pub blocks: Vec<HirBlock>,
    pub entry: HirBlockId,
    pub spans: Vec<Span>,
    pub ast: Vec<Option<IrAstRef>>,
    pub comments: Vec<Box<str>>,
    pub register_count: u32,
    pub file_count: u32,
}

#[derive(Debug, Clone)]
pub struct HirBlock {
    pub id: HirBlockId,
    pub stmts: Vec<HirStmt>,
    pub terminator: HirTerminator,
}

#[derive(Debug, Clone)]
pub enum HirTerminator {
    Goto {
        target: HirBlockId,
    },
    Jump {
        target: HirBlockId,
    },
    BranchIf {
        cond: RegId,
        if_true: HirBlockId,
        if_false: HirBlockId,
    },
    BranchIfEmpty {
        src: RegId,
        if_true: HirBlockId,
        if_false: HirBlockId,
    },
    Match {
        pattern: Box<Pattern>,
        src: RegId,
        if_true: HirBlockId,
        if_false: HirBlockId,
    },
    Iterate {
        dst: RegId,
        stream: RegId,
        body: HirBlockId,
        end: HirBlockId,
    },
    Return {
        src: RegId,
    },
    ReturnEarly {
        src: RegId,
    },
    Unreachable,
}

#[derive(Debug, Clone, Default)]
pub struct HirCallArgs {
    pub positional: Vec<RegId>,
    pub rest: Vec<RegId>,
    pub named: Vec<(Vec<u8>, RegId)>,
    pub flags: Vec<Vec<u8>>,
    pub parser_info: Vec<(Vec<u8>, Box<Expression>)>,
}

#[derive(Debug, Clone)]
pub enum HirStmt {
    LoadLiteral {
        dst: RegId,
        lit: HirLiteral,
    },
    LoadValue {
        dst: RegId,
        val: Box<Value>,
    },
    Move {
        dst: RegId,
        src: RegId,
    },
    Clone {
        dst: RegId,
        src: RegId,
    },
    Collect {
        src_dst: RegId,
    },
    Span {
        src_dst: RegId,
    },
    Drop {
        src: RegId,
    },
    Drain {
        src: RegId,
    },
    DrainIfEnd {
        src: RegId,
    },
    LoadVariable {
        dst: RegId,
        var_id: VarId,
    },
    StoreVariable {
        var_id: VarId,
        src: RegId,
    },
    DropVariable {
        var_id: VarId,
    },
    LoadEnv {
        dst: RegId,
        key: Vec<u8>,
    },
    LoadEnvOpt {
        dst: RegId,
        key: Vec<u8>,
    },
    StoreEnv {
        key: Vec<u8>,
        src: RegId,
    },
    RedirectOut {
        mode: RedirectMode,
    },
    RedirectErr {
        mode: RedirectMode,
    },
    CheckErrRedirected {
        src: RegId,
    },
    OpenFile {
        file_num: u32,
        path: RegId,
        append: bool,
    },
    WriteFile {
        file_num: u32,
        src: RegId,
    },
    CloseFile {
        file_num: u32,
    },
    Call {
        decl_id: DeclId,
        src_dst: RegId,
        args: HirCallArgs,
    },
    StringAppend {
        src_dst: RegId,
        val: RegId,
    },
    GlobFrom {
        src_dst: RegId,
        no_expand: bool,
    },
    ListPush {
        src_dst: RegId,
        item: RegId,
    },
    ListSpread {
        src_dst: RegId,
        items: RegId,
    },
    RecordInsert {
        src_dst: RegId,
        key: RegId,
        val: RegId,
    },
    RecordSpread {
        src_dst: RegId,
        items: RegId,
    },
    Not {
        src_dst: RegId,
    },
    BinaryOp {
        lhs_dst: RegId,
        op: Operator,
        rhs: RegId,
    },
    FollowCellPath {
        src_dst: RegId,
        path: RegId,
    },
    CloneCellPath {
        dst: RegId,
        src: RegId,
        path: RegId,
    },
    UpsertCellPath {
        src_dst: RegId,
        path: RegId,
        new_value: RegId,
    },
    OnError {
        target: HirBlockId,
    },
    OnErrorInto {
        target: HirBlockId,
        dst: RegId,
    },
    PopErrorHandler,
    CheckMatchGuard {
        src: RegId,
    },
}

#[derive(Debug, Clone)]
pub enum HirLiteral {
    Bool(bool),
    Int(i64),
    Float(f64),
    Filesize(Filesize),
    Duration(i64),
    Binary(Vec<u8>),
    Block(NuBlockId),
    Closure(NuBlockId),
    RowCondition(NuBlockId),
    Range {
        start: RegId,
        step: RegId,
        end: RegId,
        inclusion: RangeInclusion,
    },
    List {
        capacity: usize,
    },
    Record {
        capacity: usize,
    },
    Filepath {
        val: Vec<u8>,
        no_expand: bool,
    },
    Directory {
        val: Vec<u8>,
        no_expand: bool,
    },
    GlobPattern {
        val: Vec<u8>,
        no_expand: bool,
    },
    String(Vec<u8>),
    RawString(Vec<u8>),
    CellPath(Box<CellPath>),
    Date(Box<DateTime<FixedOffset>>),
    Nothing,
}

impl HirLiteral {
    pub fn from_constant_value(value: &Value) -> Option<Self> {
        match value {
            Value::Bool { val, .. } => Some(Self::Bool(*val)),
            Value::Int { val, .. } => Some(Self::Int(*val)),
            Value::Binary { val, .. } => Some(Self::Binary(val.clone())),
            Value::String { val, .. } => Some(Self::String(val.as_bytes().to_vec())),
            Value::Glob { val, no_expand, .. } => Some(Self::GlobPattern {
                val: val.as_bytes().to_vec(),
                no_expand: *no_expand,
            }),
            Value::Filesize { val, .. } => Some(Self::Filesize(*val)),
            Value::Duration { val, .. } => Some(Self::Duration(*val)),
            Value::Nothing { .. } => Some(Self::Nothing),
            _ => None,
        }
    }

    pub fn to_constant_value(&self) -> Option<Value> {
        let span = Span::unknown();
        match self {
            HirLiteral::Bool(val) => Some(Value::bool(*val, span)),
            HirLiteral::Int(val) => Some(Value::int(*val, span)),
            HirLiteral::Filesize(val) => Some(Value::filesize(*val, span)),
            HirLiteral::Duration(val) => Some(Value::duration(*val, span)),
            HirLiteral::Nothing => Some(Value::nothing(span)),
            HirLiteral::Binary(bytes) => Some(Value::binary(bytes.clone(), span)),
            HirLiteral::String(bytes) | HirLiteral::RawString(bytes) => {
                String::from_utf8(bytes.clone())
                    .ok()
                    .map(|s| Value::string(s, span))
            }
            HirLiteral::GlobPattern { val, no_expand } => String::from_utf8(val.clone())
                .ok()
                .map(|s| Value::glob(s, *no_expand, span)),
            HirLiteral::Filepath { val, .. } | HirLiteral::Directory { val, .. } => {
                String::from_utf8(val.clone())
                    .ok()
                    .map(|s| Value::string(s, span))
            }
            _ => None,
        }
    }
}

pub fn is_numeric_constant_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Bool { .. }
            | Value::Int { .. }
            | Value::Filesize { .. }
            | Value::Duration { .. }
            | Value::Nothing { .. }
    )
}

pub fn supports_numeric_constant_list(value: &Value) -> bool {
    matches!(value, Value::List { vals, .. } if vals.iter().all(is_numeric_constant_value))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FixedArrayConstantElementShape {
    ScalarI64,
    Binary(usize),
    String(usize),
    NumericList(usize),
    FixedArray {
        elem: Box<FixedArrayConstantElementShape>,
        len: usize,
    },
    Record(Vec<(String, FixedArrayConstantElementShape)>),
}

const FIXED_ARRAY_STRING_MAX_SIZE: usize = 128;

fn fixed_array_string_shape_len(byte_len: usize) -> usize {
    let content_len = byte_len.min(FIXED_ARRAY_STRING_MAX_SIZE.saturating_sub(1));
    let aligned_len = (content_len + 1).saturating_add(7) & !7;
    8 + aligned_len.min(FIXED_ARRAY_STRING_MAX_SIZE).max(16)
}

fn fixed_array_constant_list_shape(values: &[Value]) -> Option<FixedArrayConstantElementShape> {
    let (first, rest) = values.split_first()?;
    let first_shape = fixed_array_constant_element_shape(first)?;
    if rest
        .iter()
        .all(|value| fixed_array_constant_element_shape(value).as_ref() == Some(&first_shape))
    {
        Some(FixedArrayConstantElementShape::FixedArray {
            elem: Box::new(first_shape),
            len: values.len(),
        })
    } else {
        None
    }
}

fn fixed_array_constant_element_shape(value: &Value) -> Option<FixedArrayConstantElementShape> {
    if is_numeric_constant_value(value) {
        return Some(FixedArrayConstantElementShape::ScalarI64);
    }

    match value {
        Value::Binary { val, .. } => Some(FixedArrayConstantElementShape::Binary(val.len())),
        Value::String { val, .. } | Value::Glob { val, .. } => Some(
            FixedArrayConstantElementShape::String(fixed_array_string_shape_len(val.len())),
        ),
        Value::List { vals, .. } if vals.iter().all(is_numeric_constant_value) => {
            Some(FixedArrayConstantElementShape::NumericList(vals.len()))
        }
        Value::List { vals, .. } => fixed_array_constant_list_shape(vals),
        Value::Record { val, .. } => val
            .iter()
            .map(|(name, field)| {
                fixed_array_constant_element_shape(field)
                    .map(|field_shape| (name.clone(), field_shape))
            })
            .collect::<Option<Vec<_>>>()
            .map(FixedArrayConstantElementShape::Record),
        _ => None,
    }
}

pub fn supports_fixed_array_constant_list(value: &Value) -> bool {
    let Value::List { vals, .. } = value else {
        return false;
    };
    fixed_array_constant_list_shape(vals).is_some()
}

pub fn supports_constant_value(value: &Value) -> bool {
    fn supports_nested_constant_value(value: &Value) -> bool {
        if HirLiteral::from_constant_value(value).is_some() {
            return true;
        }

        match value {
            value if supports_numeric_constant_list(value) => true,
            value if supports_fixed_array_constant_list(value) => true,
            Value::Record { val, .. } => val
                .iter()
                .all(|(_, field)| supports_nested_constant_value(field)),
            _ => false,
        }
    }

    supports_nested_constant_value(value)
}

/// Infer the context parameter VarId from IR instructions.
///
/// Closure parameters are variables that are loaded but never stored to within the closure.
/// The first such variable (by order of first load) is the context parameter.
pub fn infer_ctx_param(ir_block: &IrBlock) -> Option<VarId> {
    // Real Nushell closures often materialize the first parameter by collecting the
    // incoming pipeline value, cloning it, and storing that clone into a variable
    // before any later `LoadVariable` uses. Recognize that leading setup pattern
    // first so attached closures can still treat `$ctx` as the real context param.
    let mut collected_regs: HashSet<RegId> = HashSet::new();
    for instruction in &ir_block.instructions {
        match instruction {
            Instruction::Collect { src_dst } => {
                collected_regs.insert(*src_dst);
            }
            Instruction::Clone { dst, src } if collected_regs.contains(src) => {
                collected_regs.insert(*dst);
            }
            Instruction::StoreVariable { var_id, src } if collected_regs.contains(src) => {
                return Some(*var_id);
            }
            Instruction::RedirectOut { .. } | Instruction::RedirectErr { .. } => {}
            _ => break,
        }
    }

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

/// Extract all DeclIds referenced by Call instructions in an IR block.
pub fn extract_call_decl_ids(ir_block: &IrBlock) -> Vec<DeclId> {
    let mut decl_ids = Vec::new();

    for instruction in &ir_block.instructions {
        if let Instruction::Call { decl_id, .. } = instruction {
            if !decl_ids.contains(decl_id) {
                decl_ids.push(*decl_id);
            }
        }
    }

    decl_ids
}

#[cfg(test)]
mod tests;
