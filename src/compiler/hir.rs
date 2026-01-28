//! High-level intermediate representation (HIR).
//!
//! HIR is a structured, compiler-owned AST that normalizes Nushell IR:
//! - DataSlice-backed fields are converted into owned bytes.
//! - Implicit call-argument stacks are made explicit.
//! - Control flow is expressed with block terminators instead of indices.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, FixedOffset};
use nu_protocol::ast::{CellPath, Expression, Operator, Pattern, RangeInclusion};
use nu_protocol::ir::{DataSlice, Instruction, IrAstRef, IrBlock, Literal, RedirectMode};
use nu_protocol::{BlockId as NuBlockId, DeclId, Filesize, RegId, Span, Value, VarId};

use super::CompileError;

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
    Goto { target: HirBlockId },
    Jump { target: HirBlockId },
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
    Return { src: RegId },
    ReturnEarly { src: RegId },
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
    LoadLiteral { dst: RegId, lit: HirLiteral },
    LoadValue { dst: RegId, val: Box<Value> },
    Move { dst: RegId, src: RegId },
    Clone { dst: RegId, src: RegId },
    Collect { src_dst: RegId },
    Span { src_dst: RegId },
    Drop { src: RegId },
    Drain { src: RegId },
    DrainIfEnd { src: RegId },
    LoadVariable { dst: RegId, var_id: VarId },
    StoreVariable { var_id: VarId, src: RegId },
    DropVariable { var_id: VarId },
    LoadEnv { dst: RegId, key: Vec<u8> },
    LoadEnvOpt { dst: RegId, key: Vec<u8> },
    StoreEnv { key: Vec<u8>, src: RegId },
    RedirectOut { mode: RedirectMode },
    RedirectErr { mode: RedirectMode },
    CheckErrRedirected { src: RegId },
    OpenFile {
        file_num: u32,
        path: RegId,
        append: bool,
    },
    WriteFile { file_num: u32, src: RegId },
    CloseFile { file_num: u32 },
    Call {
        decl_id: DeclId,
        src_dst: RegId,
        args: HirCallArgs,
    },
    StringAppend { src_dst: RegId, val: RegId },
    GlobFrom { src_dst: RegId, no_expand: bool },
    ListPush { src_dst: RegId, item: RegId },
    ListSpread { src_dst: RegId, items: RegId },
    RecordInsert {
        src_dst: RegId,
        key: RegId,
        val: RegId,
    },
    RecordSpread { src_dst: RegId, items: RegId },
    Not { src_dst: RegId },
    BinaryOp {
        lhs_dst: RegId,
        op: Operator,
        rhs: RegId,
    },
    FollowCellPath { src_dst: RegId, path: RegId },
    CloneCellPath { dst: RegId, src: RegId, path: RegId },
    UpsertCellPath {
        src_dst: RegId,
        path: RegId,
        new_value: RegId,
    },
    OnError { target: HirBlockId },
    OnErrorInto { target: HirBlockId, dst: RegId },
    PopErrorHandler,
    CheckMatchGuard { src: RegId },
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
    List { capacity: usize },
    Record { capacity: usize },
    Filepath { val: Vec<u8>, no_expand: bool },
    Directory { val: Vec<u8>, no_expand: bool },
    GlobPattern { val: Vec<u8>, no_expand: bool },
    String(Vec<u8>),
    RawString(Vec<u8>),
    CellPath(Box<CellPath>),
    Date(Box<DateTime<FixedOffset>>),
    Nothing,
}

fn bytes_from_slice(data: &[u8], slice: DataSlice) -> Vec<u8> {
    let start = slice.start as usize;
    let end = start.saturating_add(slice.len as usize);
    data.get(start..end).unwrap_or_default().to_vec()
}

impl HirLiteral {
    fn from_ir(lit: Literal, data: &[u8]) -> Self {
        match lit {
            Literal::Bool(val) => HirLiteral::Bool(val),
            Literal::Int(val) => HirLiteral::Int(val),
            Literal::Float(val) => HirLiteral::Float(val),
            Literal::Filesize(val) => HirLiteral::Filesize(val),
            Literal::Duration(val) => HirLiteral::Duration(val),
            Literal::Binary(slice) => HirLiteral::Binary(bytes_from_slice(data, slice)),
            Literal::Block(id) => HirLiteral::Block(id),
            Literal::Closure(id) => HirLiteral::Closure(id),
            Literal::RowCondition(id) => HirLiteral::RowCondition(id),
            Literal::Range {
                start,
                step,
                end,
                inclusion,
            } => HirLiteral::Range {
                start,
                step,
                end,
                inclusion,
            },
            Literal::List { capacity } => HirLiteral::List { capacity },
            Literal::Record { capacity } => HirLiteral::Record { capacity },
            Literal::Filepath { val, no_expand } => HirLiteral::Filepath {
                val: bytes_from_slice(data, val),
                no_expand,
            },
            Literal::Directory { val, no_expand } => HirLiteral::Directory {
                val: bytes_from_slice(data, val),
                no_expand,
            },
            Literal::GlobPattern { val, no_expand } => HirLiteral::GlobPattern {
                val: bytes_from_slice(data, val),
                no_expand,
            },
            Literal::String(slice) => HirLiteral::String(bytes_from_slice(data, slice)),
            Literal::RawString(slice) => HirLiteral::RawString(bytes_from_slice(data, slice)),
            Literal::CellPath(path) => HirLiteral::CellPath(path),
            Literal::Date(val) => HirLiteral::Date(val),
            Literal::Nothing => HirLiteral::Nothing,
        }
    }
}

struct CallArgsBuilder {
    args: HirCallArgs,
}

impl CallArgsBuilder {
    fn new() -> Self {
        Self {
            args: HirCallArgs::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.args.positional.is_empty()
            && self.args.rest.is_empty()
            && self.args.named.is_empty()
            && self.args.flags.is_empty()
            && self.args.parser_info.is_empty()
    }

    fn take(&mut self) -> HirCallArgs {
        let mut out = HirCallArgs::default();
        std::mem::swap(&mut out, &mut self.args);
        out
    }
}

impl HirFunction {
    pub fn from_ir_block(ir: IrBlock) -> Result<Self, CompileError> {
        let IrBlock {
            instructions,
            spans,
            data,
            ast,
            comments,
            register_count,
            file_count,
        } = ir;

        let block_starts = compute_block_starts(&instructions);
        let block_ids = assign_block_ids(&block_starts);

        let entry = *block_ids
            .get(&0)
            .ok_or_else(|| CompileError::UnsupportedInstruction("HIR entry block missing".into()))?;

        let mut blocks: Vec<HirBlock> = Vec::new();
        let mut current_block_id = entry;
        let mut current_start = 0usize;
        let mut stmts: Vec<HirStmt> = Vec::new();
        let mut terminator: Option<HirTerminator> = None;
        let mut args_builder = CallArgsBuilder::new();

        for (idx, inst) in instructions.into_iter().enumerate() {
            if idx != current_start && block_starts.contains(&idx) {
                if !args_builder.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "Call arguments split by control flow".into(),
                    ));
                }
                if terminator.is_none() {
                    let target = block_ids[&idx];
                    terminator = Some(HirTerminator::Goto { target });
                }
                blocks.push(HirBlock {
                    id: current_block_id,
                    stmts: std::mem::take(&mut stmts),
                    terminator: terminator
                        .take()
                        .unwrap_or(HirTerminator::Unreachable),
                });
                current_block_id = block_ids[&idx];
                current_start = idx;
            }

            match inst {
                Instruction::Unreachable => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    terminator = Some(HirTerminator::Unreachable);
                }
                Instruction::LoadLiteral { dst, lit } => {
                    stmts.push(HirStmt::LoadLiteral {
                        dst,
                        lit: HirLiteral::from_ir(lit, &data),
                    });
                }
                Instruction::LoadValue { dst, val } => {
                    stmts.push(HirStmt::LoadValue { dst, val });
                }
                Instruction::Move { dst, src } => {
                    stmts.push(HirStmt::Move { dst, src });
                }
                Instruction::Clone { dst, src } => {
                    stmts.push(HirStmt::Clone { dst, src });
                }
                Instruction::Collect { src_dst } => {
                    stmts.push(HirStmt::Collect { src_dst });
                }
                Instruction::Span { src_dst } => {
                    stmts.push(HirStmt::Span { src_dst });
                }
                Instruction::Drop { src } => {
                    stmts.push(HirStmt::Drop { src });
                }
                Instruction::Drain { src } => {
                    stmts.push(HirStmt::Drain { src });
                }
                Instruction::DrainIfEnd { src } => {
                    stmts.push(HirStmt::DrainIfEnd { src });
                }
                Instruction::LoadVariable { dst, var_id } => {
                    stmts.push(HirStmt::LoadVariable { dst, var_id });
                }
                Instruction::StoreVariable { var_id, src } => {
                    stmts.push(HirStmt::StoreVariable { var_id, src });
                }
                Instruction::DropVariable { var_id } => {
                    stmts.push(HirStmt::DropVariable { var_id });
                }
                Instruction::LoadEnv { dst, key } => {
                    stmts.push(HirStmt::LoadEnv {
                        dst,
                        key: bytes_from_slice(&data, key),
                    });
                }
                Instruction::LoadEnvOpt { dst, key } => {
                    stmts.push(HirStmt::LoadEnvOpt {
                        dst,
                        key: bytes_from_slice(&data, key),
                    });
                }
                Instruction::StoreEnv { key, src } => {
                    stmts.push(HirStmt::StoreEnv {
                        key: bytes_from_slice(&data, key),
                        src,
                    });
                }
                Instruction::PushPositional { src } => {
                    args_builder.args.positional.push(src);
                }
                Instruction::AppendRest { src } => {
                    args_builder.args.rest.push(src);
                }
                Instruction::PushFlag { name } | Instruction::PushShortFlag { short: name } => {
                    args_builder.args.flags.push(bytes_from_slice(&data, name));
                }
                Instruction::PushNamed { name, src }
                | Instruction::PushShortNamed { short: name, src } => {
                    args_builder.args.named.push((bytes_from_slice(&data, name), src));
                }
                Instruction::PushParserInfo { name, info } => {
                    args_builder
                        .args
                        .parser_info
                        .push((bytes_from_slice(&data, name), info));
                }
                Instruction::RedirectOut { mode } => {
                    stmts.push(HirStmt::RedirectOut { mode });
                }
                Instruction::RedirectErr { mode } => {
                    stmts.push(HirStmt::RedirectErr { mode });
                }
                Instruction::CheckErrRedirected { src } => {
                    stmts.push(HirStmt::CheckErrRedirected { src });
                }
                Instruction::OpenFile {
                    file_num,
                    path,
                    append,
                } => {
                    stmts.push(HirStmt::OpenFile {
                        file_num,
                        path,
                        append,
                    });
                }
                Instruction::WriteFile { file_num, src } => {
                    stmts.push(HirStmt::WriteFile { file_num, src });
                }
                Instruction::CloseFile { file_num } => {
                    stmts.push(HirStmt::CloseFile { file_num });
                }
                Instruction::Call { decl_id, src_dst } => {
                    let args = args_builder.take();
                    stmts.push(HirStmt::Call {
                        decl_id,
                        src_dst,
                        args,
                    });
                }
                Instruction::StringAppend { src_dst, val } => {
                    stmts.push(HirStmt::StringAppend { src_dst, val });
                }
                Instruction::GlobFrom { src_dst, no_expand } => {
                    stmts.push(HirStmt::GlobFrom { src_dst, no_expand });
                }
                Instruction::ListPush { src_dst, item } => {
                    stmts.push(HirStmt::ListPush { src_dst, item });
                }
                Instruction::ListSpread { src_dst, items } => {
                    stmts.push(HirStmt::ListSpread { src_dst, items });
                }
                Instruction::RecordInsert { src_dst, key, val } => {
                    stmts.push(HirStmt::RecordInsert { src_dst, key, val });
                }
                Instruction::RecordSpread { src_dst, items } => {
                    stmts.push(HirStmt::RecordSpread { src_dst, items });
                }
                Instruction::Not { src_dst } => {
                    stmts.push(HirStmt::Not { src_dst });
                }
                Instruction::BinaryOp { lhs_dst, op, rhs } => {
                    stmts.push(HirStmt::BinaryOp { lhs_dst, op, rhs });
                }
                Instruction::FollowCellPath { src_dst, path } => {
                    stmts.push(HirStmt::FollowCellPath { src_dst, path });
                }
                Instruction::CloneCellPath { dst, src, path } => {
                    stmts.push(HirStmt::CloneCellPath { dst, src, path });
                }
                Instruction::UpsertCellPath {
                    src_dst,
                    path,
                    new_value,
                } => {
                    stmts.push(HirStmt::UpsertCellPath {
                        src_dst,
                        path,
                        new_value,
                    });
                }
                Instruction::Jump { index } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    let target = block_ids[&index];
                    terminator = Some(HirTerminator::Jump { target });
                }
                Instruction::BranchIf { cond, index } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    let if_true = block_ids[&index];
                    let if_false = block_ids
                        .get(&(idx + 1))
                        .copied()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "Missing fallthrough block for BranchIf".into(),
                            )
                        })?;
                    terminator = Some(HirTerminator::BranchIf {
                        cond,
                        if_true,
                        if_false,
                    });
                }
                Instruction::BranchIfEmpty { src, index } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    let if_true = block_ids[&index];
                    let if_false = block_ids
                        .get(&(idx + 1))
                        .copied()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "Missing fallthrough block for BranchIfEmpty".into(),
                            )
                        })?;
                    terminator = Some(HirTerminator::BranchIfEmpty {
                        src,
                        if_true,
                        if_false,
                    });
                }
                Instruction::Match { pattern, src, index } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    let if_true = block_ids[&index];
                    let if_false = block_ids
                        .get(&(idx + 1))
                        .copied()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "Missing fallthrough block for Match".into(),
                            )
                        })?;
                    terminator = Some(HirTerminator::Match {
                        pattern,
                        src,
                        if_true,
                        if_false,
                    });
                }
                Instruction::CheckMatchGuard { src } => {
                    stmts.push(HirStmt::CheckMatchGuard { src });
                }
                Instruction::Iterate {
                    dst,
                    stream,
                    end_index,
                } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    let body = block_ids
                        .get(&(idx + 1))
                        .copied()
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "Missing loop body block for Iterate".into(),
                            )
                        })?;
                    let end = block_ids[&end_index];
                    terminator = Some(HirTerminator::Iterate {
                        dst,
                        stream,
                        body,
                        end,
                    });
                }
                Instruction::OnError { index } => {
                    let target = block_ids[&index];
                    stmts.push(HirStmt::OnError { target });
                }
                Instruction::OnErrorInto { index, dst } => {
                    let target = block_ids[&index];
                    stmts.push(HirStmt::OnErrorInto { target, dst });
                }
                Instruction::PopErrorHandler => {
                    stmts.push(HirStmt::PopErrorHandler);
                }
                Instruction::ReturnEarly { src } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    terminator = Some(HirTerminator::ReturnEarly { src });
                }
                Instruction::Return { src } => {
                    if !args_builder.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "Call arguments split by control flow".into(),
                        ));
                    }
                    terminator = Some(HirTerminator::Return { src });
                }
            }
        }

        if !args_builder.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "Call arguments left without a call".into(),
            ));
        }

        if terminator.is_none() {
            return Err(CompileError::UnsupportedInstruction(
                "HIR block missing terminator".into(),
            ));
        }

        blocks.push(HirBlock {
            id: current_block_id,
            stmts,
            terminator: terminator.unwrap(),
        });

        Ok(HirFunction {
            blocks,
            entry,
            spans,
            ast,
            comments,
            register_count,
            file_count,
        })
    }
}

fn compute_block_starts(instructions: &[Instruction]) -> HashSet<usize> {
    let mut starts = HashSet::new();
    starts.insert(0);

    for (idx, inst) in instructions.iter().enumerate() {
        if let Some(target) = inst.branch_target() {
            starts.insert(target);
        }

        if matches!(
            inst,
            Instruction::Jump { .. }
                | Instruction::BranchIf { .. }
                | Instruction::BranchIfEmpty { .. }
                | Instruction::Match { .. }
                | Instruction::Iterate { .. }
                | Instruction::Return { .. }
                | Instruction::ReturnEarly { .. }
                | Instruction::Unreachable
        ) {
            if idx + 1 < instructions.len() {
                starts.insert(idx + 1);
            }
        }
    }

    starts
}

fn assign_block_ids(starts: &HashSet<usize>) -> HashMap<usize, HirBlockId> {
    let mut indices: Vec<usize> = starts.iter().copied().collect();
    indices.sort_unstable();

    let mut map = HashMap::new();
    for (id, idx) in indices.into_iter().enumerate() {
        map.insert(idx, HirBlockId(id));
    }
    map
}

/// Lower Nushell IR into the HIR container.
pub fn lower_ir_to_hir(
    main: IrBlock,
    closures: HashMap<NuBlockId, IrBlock>,
    captures: Vec<(String, i64)>,
    ctx_param: Option<VarId>,
) -> Result<HirProgram, CompileError> {
    let main = HirFunction::from_ir_block(main)?;
    let mut closure_hir = HashMap::new();
    for (id, ir) in closures {
        let func = HirFunction::from_ir_block(ir)?;
        closure_hir.insert(id, func);
    }
    Ok(HirProgram::new(main, closure_hir, captures, ctx_param))
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
mod tests {
    use super::*;
    use nu_protocol::RegId;
    use nu_protocol::DeclId;
    use nu_protocol::ir::{DataSlice, Instruction};
    use std::sync::Arc;

    #[test]
    fn test_hir_call_args_folded() {
        let data: Arc<[u8]> = Arc::from(b"emit".as_slice());
        let ir = IrBlock {
            instructions: vec![
                Instruction::PushFlag {
                    name: DataSlice { start: 0, len: 4 },
                },
                Instruction::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(0),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![],
            data,
            ast: vec![],
            comments: vec![],
            register_count: 1,
            file_count: 0,
        };

        let hir = HirFunction::from_ir_block(ir).unwrap();
        let block = &hir.blocks[0];
        match &block.stmts[0] {
            HirStmt::Call { args, .. } => {
                assert_eq!(args.flags.len(), 1);
                assert_eq!(args.flags[0], b"emit");
            }
            _ => panic!("Expected Call with folded args"),
        }
    }
}
