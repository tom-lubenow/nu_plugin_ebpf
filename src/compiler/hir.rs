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
use nu_protocol::{BlockId as NuBlockId, DeclId, Filesize, RegId, Span, Value, VarId};

use super::CompileError;

mod lowering;
pub use lowering::lower_ir_to_hir;

#[derive(Debug, Clone)]
pub struct HirProgram {
    pub main: HirFunction,
    pub closures: HashMap<NuBlockId, HirFunction>,
    pub captures: Vec<(String, i64)>,
    pub ctx_param: Option<VarId>,
}

impl HirProgram {
    pub fn new(
        main: HirFunction,
        closures: HashMap<NuBlockId, HirFunction>,
        captures: Vec<(String, i64)>,
        ctx_param: Option<VarId>,
    ) -> Self {
        Self {
            main,
            closures,
            captures,
            ctx_param,
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
