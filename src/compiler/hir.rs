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
    /// The register used as Nushell pipeline input for this call, when the
    /// source IR had a live `src_dst` value before the call executed.
    pub pipeline_input: Option<RegId>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileTimeValueFlow {
    Direct,
    AggregateBuilder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedLayoutValueConsumer {
    TypedGlobalDefine,
    GlobalSet,
    MapPut,
    MapPutKey,
    MapPush,
    MapGetKey,
    MapDeleteKey,
    MapContainsProbe,
    BinaryBytesTransform,
    BitsBinaryTransform,
    BytesPredicate,
    BytesIndexOf,
    BytesReverse,
    BytesCollect,
    StrJoin,
    Length,
    EmptyPredicate,
    Get,
    FirstLast,
    Slice,
    Reverse,
    AppendPrepend,
    Uniq,
    Sort,
    Find,
    SplitList,
    Compact,
    Values,
    StringTransform,
    Describe,
    Fill,
    Seq,
    MathAbs,
    MathRounding,
    MathAverage,
    MathMedian,
    MathFloatUnary,
    MathLog,
    MathVarianceStddev,
    MathSumProduct,
    MathMinMax,
}

pub fn compile_time_value_flows_to_fixed_layout_consumer(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
    consumer: FixedLayoutValueConsumer,
    flow: CompileTimeValueFlow,
) -> bool {
    compile_time_value_flows_to_fixed_layout_consumer_inner(
        stmts, stmt_index, dst, decl_names, consumer, flow, true, false,
    )
}

pub fn compile_time_value_flows_to_fixed_layout_consumer_without_transforms(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
    consumer: FixedLayoutValueConsumer,
    flow: CompileTimeValueFlow,
) -> bool {
    compile_time_value_flows_to_fixed_layout_consumer_inner(
        stmts, stmt_index, dst, decl_names, consumer, flow, false, false,
    )
}

pub fn compile_time_value_flows_to_fixed_layout_consumer_through_list_transforms(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
    consumer: FixedLayoutValueConsumer,
    flow: CompileTimeValueFlow,
) -> bool {
    compile_time_value_flows_to_fixed_layout_consumer_inner(
        stmts, stmt_index, dst, decl_names, consumer, flow, true, true,
    )
}

fn compile_time_value_flows_to_fixed_layout_consumer_inner(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
    consumer: FixedLayoutValueConsumer,
    flow: CompileTimeValueFlow,
    allow_aggregate_transforms: bool,
    list_transforms_only: bool,
) -> bool {
    let Some(rest) = stmts.get(stmt_index.saturating_add(1)..) else {
        return false;
    };
    let mut tracked_regs = HashSet::from([dst]);
    let mut tracked_vars = HashSet::new();

    for (offset, stmt) in rest.iter().enumerate() {
        match stmt {
            HirStmt::LoadLiteral {
                dst: loaded_dst, ..
            }
            | HirStmt::LoadValue {
                dst: loaded_dst, ..
            } => {
                if tracked_regs.remove(loaded_dst)
                    && tracked_regs.is_empty()
                    && tracked_vars.is_empty()
                {
                    return false;
                }
            }
            HirStmt::Move {
                dst: moved_dst,
                src,
            }
            | HirStmt::Clone {
                dst: moved_dst,
                src,
            } => {
                if tracked_regs.contains(src) {
                    tracked_regs.insert(*moved_dst);
                } else if tracked_regs.remove(moved_dst)
                    && tracked_regs.is_empty()
                    && tracked_vars.is_empty()
                {
                    return false;
                }
            }
            HirStmt::StoreVariable { var_id, src } => {
                if tracked_regs.contains(src) {
                    tracked_vars.insert(*var_id);
                } else if tracked_vars.remove(var_id)
                    && tracked_regs.is_empty()
                    && tracked_vars.is_empty()
                {
                    return false;
                }
            }
            HirStmt::LoadVariable { dst, var_id } => {
                if tracked_vars.contains(var_id) {
                    tracked_regs.insert(*dst);
                } else if tracked_regs.remove(dst)
                    && tracked_regs.is_empty()
                    && tracked_vars.is_empty()
                {
                    return false;
                }
            }
            HirStmt::DropVariable { var_id } => {
                if tracked_vars.remove(var_id) && tracked_regs.is_empty() && tracked_vars.is_empty()
                {
                    return false;
                }
            }
            HirStmt::Drain { src } | HirStmt::DrainIfEnd { src } | HirStmt::Drop { src } => {
                if tracked_regs.remove(src) && tracked_regs.is_empty() && tracked_vars.is_empty() {
                    return false;
                }
            }
            HirStmt::ListPush { src_dst, item }
                if flow == CompileTimeValueFlow::AggregateBuilder =>
            {
                if tracked_regs.contains(src_dst) {
                    continue;
                }
                if tracked_regs.contains(item) {
                    tracked_regs.insert(*src_dst);
                }
            }
            HirStmt::ListSpread { src_dst, items }
                if flow == CompileTimeValueFlow::AggregateBuilder =>
            {
                if tracked_regs.contains(src_dst) {
                    continue;
                }
                if tracked_regs.contains(items) {
                    tracked_regs.insert(*src_dst);
                }
            }
            HirStmt::RecordInsert { src_dst, key, val }
                if flow == CompileTimeValueFlow::AggregateBuilder =>
            {
                if tracked_regs.contains(src_dst) {
                    continue;
                }
                if tracked_regs.contains(val) {
                    tracked_regs.insert(*src_dst);
                    continue;
                }
                if tracked_regs.contains(key) {
                    return false;
                }
            }
            HirStmt::RecordSpread { src_dst, items }
                if flow == CompileTimeValueFlow::AggregateBuilder =>
            {
                if tracked_regs.contains(src_dst) {
                    continue;
                }
                if tracked_regs.contains(items) {
                    tracked_regs.insert(*src_dst);
                }
            }
            HirStmt::Call {
                decl_id,
                src_dst,
                args,
            } => {
                if compile_time_value_consumer_matches(
                    decl_names.get(decl_id).map(String::as_str),
                    *src_dst,
                    args,
                    consumer,
                    &tracked_regs,
                ) {
                    let mut post_consumer_regs = tracked_regs.clone();
                    remove_call_consumed_compile_time_regs(&mut post_consumer_regs, *src_dst, args);
                    return !compile_time_value_used_after(
                        &rest[offset.saturating_add(1)..],
                        &post_consumer_regs,
                        &tracked_vars,
                    );
                }

                if allow_aggregate_transforms
                    && compile_time_aggregate_transform_preserves_tracked_input(
                        decl_names.get(decl_id).map(String::as_str),
                        *src_dst,
                        args,
                        &tracked_regs,
                        list_transforms_only,
                    )
                {
                    tracked_regs.insert(*src_dst);
                    continue;
                }

                if tracked_regs.contains(src_dst)
                    || call_args_touch_compile_time_value(args, &tracked_regs)
                {
                    return false;
                }
            }
            stmt if stmt_touches_compile_time_value(stmt, &tracked_regs, &tracked_vars) => {
                return false;
            }
            _ => {}
        }
    }

    false
}

pub fn compile_time_value_flows_to_fixed_layout_aggregate_consumer(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
) -> bool {
    [
        FixedLayoutValueConsumer::TypedGlobalDefine,
        FixedLayoutValueConsumer::GlobalSet,
        FixedLayoutValueConsumer::MapPut,
        FixedLayoutValueConsumer::MapPutKey,
        FixedLayoutValueConsumer::MapPush,
        FixedLayoutValueConsumer::MapGetKey,
        FixedLayoutValueConsumer::MapDeleteKey,
        FixedLayoutValueConsumer::MapContainsProbe,
        FixedLayoutValueConsumer::BinaryBytesTransform,
        FixedLayoutValueConsumer::BytesPredicate,
        FixedLayoutValueConsumer::BytesIndexOf,
        FixedLayoutValueConsumer::BytesReverse,
        FixedLayoutValueConsumer::BytesCollect,
        FixedLayoutValueConsumer::StrJoin,
        FixedLayoutValueConsumer::Length,
        FixedLayoutValueConsumer::EmptyPredicate,
        FixedLayoutValueConsumer::Describe,
        FixedLayoutValueConsumer::Get,
        FixedLayoutValueConsumer::FirstLast,
        FixedLayoutValueConsumer::Slice,
        FixedLayoutValueConsumer::Reverse,
        FixedLayoutValueConsumer::AppendPrepend,
        FixedLayoutValueConsumer::Uniq,
        FixedLayoutValueConsumer::Sort,
        FixedLayoutValueConsumer::Find,
        FixedLayoutValueConsumer::SplitList,
        FixedLayoutValueConsumer::Compact,
        FixedLayoutValueConsumer::Values,
        FixedLayoutValueConsumer::StringTransform,
    ]
    .into_iter()
    .any(|consumer| {
        compile_time_value_flows_to_fixed_layout_consumer(
            stmts,
            stmt_index,
            dst,
            decl_names,
            consumer,
            CompileTimeValueFlow::AggregateBuilder,
        )
    })
}

pub fn compile_time_value_flows_to_bits_binary_transform_aggregate_consumer(
    stmts: &[HirStmt],
    stmt_index: usize,
    dst: RegId,
    decl_names: &HashMap<DeclId, String>,
) -> bool {
    compile_time_value_flows_to_fixed_layout_consumer(
        stmts,
        stmt_index,
        dst,
        decl_names,
        FixedLayoutValueConsumer::BitsBinaryTransform,
        CompileTimeValueFlow::AggregateBuilder,
    )
}

pub fn compile_time_list_push_item_is_constant(
    stmts: &[HirStmt],
    stmt_index: usize,
    item: RegId,
) -> bool {
    let mut constant_regs = HashSet::new();
    let mut constant_vars = HashSet::new();

    for stmt in stmts.iter().take(stmt_index) {
        match stmt {
            HirStmt::LoadLiteral { dst, lit } => {
                if lit.to_constant_value().is_some() {
                    constant_regs.insert(*dst);
                } else {
                    constant_regs.remove(dst);
                }
            }
            HirStmt::LoadValue { dst, .. } => {
                constant_regs.insert(*dst);
            }
            HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
                if constant_regs.contains(src) {
                    constant_regs.insert(*dst);
                } else {
                    constant_regs.remove(dst);
                }
            }
            HirStmt::StoreVariable { var_id, src } => {
                if constant_regs.contains(src) {
                    constant_vars.insert(*var_id);
                } else {
                    constant_vars.remove(var_id);
                }
            }
            HirStmt::LoadVariable { dst, var_id } => {
                if constant_vars.contains(var_id) {
                    constant_regs.insert(*dst);
                } else {
                    constant_regs.remove(dst);
                }
            }
            HirStmt::DropVariable { var_id } => {
                constant_vars.remove(var_id);
            }
            HirStmt::Drop { src } | HirStmt::Drain { src } | HirStmt::DrainIfEnd { src } => {
                constant_regs.remove(src);
            }
            HirStmt::LoadEnv { dst, .. }
            | HirStmt::LoadEnvOpt { dst, .. }
            | HirStmt::OnErrorInto { dst, .. } => {
                constant_regs.remove(dst);
            }
            HirStmt::Call { src_dst, .. }
            | HirStmt::StringAppend { src_dst, .. }
            | HirStmt::GlobFrom { src_dst, .. }
            | HirStmt::ListPush { src_dst, .. }
            | HirStmt::ListSpread { src_dst, .. }
            | HirStmt::RecordInsert { src_dst, .. }
            | HirStmt::RecordSpread { src_dst, .. }
            | HirStmt::Not { src_dst }
            | HirStmt::BinaryOp {
                lhs_dst: src_dst, ..
            }
            | HirStmt::FollowCellPath { src_dst, .. }
            | HirStmt::UpsertCellPath { src_dst, .. } => {
                constant_regs.remove(src_dst);
            }
            HirStmt::CloneCellPath { dst, .. } => {
                constant_regs.remove(dst);
            }
            HirStmt::Collect { src_dst }
            | HirStmt::Span { src_dst }
            | HirStmt::CheckErrRedirected { src: src_dst } => {
                constant_regs.remove(src_dst);
            }
            HirStmt::StoreEnv { .. }
            | HirStmt::RedirectOut { .. }
            | HirStmt::RedirectErr { .. }
            | HirStmt::OpenFile { .. }
            | HirStmt::WriteFile { .. }
            | HirStmt::CloseFile { .. }
            | HirStmt::OnError { .. }
            | HirStmt::PopErrorHandler
            | HirStmt::CheckMatchGuard { .. } => {}
        }
    }

    constant_regs.contains(&item)
}

fn remove_call_consumed_compile_time_regs(
    regs: &mut HashSet<RegId>,
    src_dst: RegId,
    args: &HirCallArgs,
) {
    regs.remove(&src_dst);
    if let Some(reg) = args.pipeline_input {
        regs.remove(&reg);
    }
    for reg in args
        .positional
        .iter()
        .chain(args.rest.iter())
        .chain(args.named.iter().map(|(_, reg)| reg))
    {
        regs.remove(reg);
    }
}

fn compile_time_value_consumer_matches(
    decl_name: Option<&str>,
    src_dst: RegId,
    args: &HirCallArgs,
    consumer: FixedLayoutValueConsumer,
    tracked_regs: &HashSet<RegId>,
) -> bool {
    match consumer {
        FixedLayoutValueConsumer::TypedGlobalDefine => {
            decl_name == Some("global-define")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args
                    .named
                    .iter()
                    .any(|(name, _)| name.as_slice() == b"type")
                && !args.flags.iter().any(|flag| flag.as_slice() == b"zero")
        }
        FixedLayoutValueConsumer::GlobalSet => {
            decl_name == Some("global-set")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapPut => {
            decl_name == Some("map-put")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 2
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind" | b"flags"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapPutKey => {
            decl_name == Some("map-put")
                && call_args_tracked_only_in_positional(src_dst, args, tracked_regs, 1)
                && args.positional.len() == 2
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind" | b"flags"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapPush => {
            decl_name == Some("map-push")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind" | b"flags"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapGetKey => {
            decl_name == Some("map-get")
                && call_args_tracked_only_in_pipeline_or_positional(src_dst, args, tracked_regs, 1)
                && matches!(args.positional.len(), 1 | 2)
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapDeleteKey => {
            decl_name == Some("map-delete")
                && call_args_tracked_only_in_pipeline_or_positional(src_dst, args, tracked_regs, 1)
                && matches!(args.positional.len(), 1 | 2)
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MapContainsProbe => {
            decl_name == Some("map-contains")
                && call_args_tracked_only_in_pipeline_or_positional(src_dst, args, tracked_regs, 1)
                && matches!(args.positional.len(), 1 | 2)
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| matches!(name.as_slice(), b"kind"))
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::BinaryBytesTransform => {
            matches!(
                decl_name,
                Some("bytes at" | "bytes add" | "bytes remove" | "bytes replace")
            ) && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.rest.is_empty()
                && match decl_name {
                    Some("bytes at") => {
                        args.positional.len() == 1 && args.named.is_empty() && args.flags.is_empty()
                    }
                    Some("bytes add") => {
                        args.positional.len() == 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| name.as_slice() == b"index")
                            && args.flags.iter().all(|flag| flag.as_slice() == b"end")
                    }
                    Some("bytes remove") => {
                        args.positional.len() == 1
                            && args.named.is_empty()
                            && args
                                .flags
                                .iter()
                                .all(|flag| matches!(flag.as_slice(), b"all" | b"end"))
                    }
                    Some("bytes replace") => {
                        args.positional.len() == 2
                            && args.named.is_empty()
                            && args.flags.iter().all(|flag| flag.as_slice() == b"all")
                    }
                    _ => false,
                }
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::BitsBinaryTransform => {
            call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.rest.is_empty()
                && args.parser_info.is_empty()
                && match decl_name {
                    Some("bits and" | "bits or" | "bits xor") => {
                        args.positional.len() == 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| matches!(name.as_slice(), b"endian" | b"e"))
                            && args.flags.is_empty()
                    }
                    Some("bits not") => {
                        args.positional.is_empty()
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| matches!(name.as_slice(), b"number-bytes" | b"n"))
                            && args
                                .flags
                                .iter()
                                .all(|flag| matches!(flag.as_slice(), b"signed" | b"s"))
                    }
                    Some("bits shl" | "bits shr" | "bits rol" | "bits ror") => {
                        args.positional.len() == 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| matches!(name.as_slice(), b"number-bytes" | b"n"))
                            && args
                                .flags
                                .iter()
                                .all(|flag| matches!(flag.as_slice(), b"signed" | b"s"))
                    }
                    _ => false,
                }
        }
        FixedLayoutValueConsumer::BytesPredicate => {
            matches!(decl_name, Some("bytes starts-with" | "bytes ends-with"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::BytesIndexOf => {
            decl_name == Some("bytes index-of")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args
                    .flags
                    .iter()
                    .all(|flag| matches!(flag.as_slice(), b"all" | b"end"))
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::BytesReverse => {
            decl_name == Some("bytes reverse")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::BytesCollect => {
            decl_name == Some("bytes collect")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() <= 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::StrJoin => {
            decl_name == Some("str join")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() <= 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Length => {
            call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.parser_info.is_empty()
                && match decl_name {
                    Some("length") => args.flags.is_empty(),
                    Some("bytes length") => args.flags.is_empty(),
                    Some("str length") => args.flags.iter().all(|flag| {
                        matches!(
                            flag.as_slice(),
                            b"utf-8-bytes" | b"chars" | b"grapheme-clusters"
                        )
                    }),
                    _ => false,
                }
        }
        FixedLayoutValueConsumer::EmptyPredicate => {
            matches!(decl_name, Some("is-empty" | "is-not-empty"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Get => {
            decl_name == Some("get")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::FirstLast => {
            matches!(decl_name, Some("first" | "last"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() <= 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Slice => {
            matches!(decl_name, Some("take" | "skip" | "drop"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && match decl_name {
                    Some("take") => args.positional.len() == 1,
                    Some("skip" | "drop") => args.positional.len() <= 1,
                    _ => false,
                }
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Reverse => {
            decl_name == Some("reverse")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::AppendPrepend => {
            matches!(decl_name, Some("append" | "prepend"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Uniq => {
            decl_name == Some("uniq")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Sort => {
            decl_name == Some("sort")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.iter().all(|flag| flag.as_slice() == b"reverse")
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Find => {
            decl_name == Some("find")
                && call_args_tracked_only_in_pipeline_or_positional(src_dst, args, tracked_regs, 0)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::SplitList => {
            decl_name == Some("split list")
                && call_args_tracked_only_in_pipeline_or_positional(src_dst, args, tracked_regs, 0)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| name.as_slice() == b"split")
                && args.flags.iter().all(|flag| flag.as_slice() == b"regex")
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Compact => {
            decl_name == Some("compact")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.iter().all(|flag| flag.as_slice() == b"empty")
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Values => {
            decl_name == Some("values")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::StringTransform => {
            let Some(decl_name) = decl_name else {
                return false;
            };
            call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.rest.is_empty()
                && args.parser_info.is_empty()
                && match decl_name {
                    "str trim" => {
                        args.positional.is_empty()
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| name.as_slice() == b"char")
                            && args
                                .flags
                                .iter()
                                .all(|flag| matches!(flag.as_slice(), b"left" | b"right"))
                    }
                    "str substring" => {
                        args.positional.len() == 1
                            && args.named.is_empty()
                            && args.flags.iter().all(|flag| {
                                matches!(flag.as_slice(), b"utf-8-bytes" | b"grapheme-clusters")
                            })
                    }
                    "str replace" => {
                        args.positional.len() == 2
                            && args.named.is_empty()
                            && args.flags.iter().all(|flag| {
                                matches!(
                                    flag.as_slice(),
                                    b"all" | b"regex" | b"multiline" | b"no-expand"
                                )
                            })
                    }
                    "str starts-with" | "str ends-with" | "str contains" => {
                        args.positional.len() == 1
                            && args.named.is_empty()
                            && args
                                .flags
                                .iter()
                                .all(|flag| flag.as_slice() == b"ignore-case")
                    }
                    "str index-of" => {
                        args.positional.len() == 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| name.as_slice() == b"range")
                            && args.flags.iter().all(|flag| {
                                matches!(
                                    flag.as_slice(),
                                    b"end" | b"utf-8-bytes" | b"grapheme-clusters"
                                )
                            })
                    }
                    "split row" => {
                        args.positional.len() == 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| name.as_slice() == b"number")
                            && args.flags.iter().all(|flag| flag.as_slice() == b"regex")
                    }
                    "split chars" => {
                        args.positional.is_empty()
                            && args.named.is_empty()
                            && args.flags.iter().all(|flag| {
                                matches!(flag.as_slice(), b"code-points" | b"grapheme-clusters")
                            })
                    }
                    "split words" => {
                        args.positional.is_empty()
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| name.as_slice() == b"min-word-length")
                            && args.flags.iter().all(|flag| {
                                matches!(flag.as_slice(), b"utf-8-bytes" | b"grapheme-clusters")
                            })
                    }
                    "fill" => {
                        args.positional.is_empty()
                            && args.named.iter().all(|(name, _)| {
                                matches!(
                                    name.as_slice(),
                                    b"width" | b"w" | b"alignment" | b"a" | b"character" | b"c"
                                )
                            })
                            && args.flags.is_empty()
                    }
                    "str downcase"
                    | "str upcase"
                    | "str reverse"
                    | "str capitalize"
                    | "str camel-case"
                    | "str kebab-case"
                    | "str pascal-case"
                    | "str screaming-snake-case"
                    | "str snake-case"
                    | "str title-case" => {
                        args.positional.is_empty() && args.named.is_empty() && args.flags.is_empty()
                    }
                    _ => false,
                }
        }
        FixedLayoutValueConsumer::Describe => {
            decl_name == Some("describe")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Fill => {
            decl_name == Some("fill")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.named.iter().all(|(name, _)| {
                    matches!(
                        name.as_slice(),
                        b"width" | b"w" | b"alignment" | b"a" | b"character" | b"c"
                    )
                })
                && args.rest.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::Seq => {
            decl_name == Some("seq")
                && args.pipeline_input.is_none()
                && !tracked_regs.contains(&src_dst)
                && args.positional.iter().any(|reg| tracked_regs.contains(reg))
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathAbs => {
            decl_name == Some("math abs")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathRounding => {
            matches!(decl_name, Some("math ceil" | "math floor" | "math round"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && match decl_name {
                    Some("math round") => {
                        args.named.len() <= 1
                            && args
                                .named
                                .iter()
                                .all(|(name, _)| matches!(name.as_slice(), b"precision" | b"p"))
                    }
                    _ => args.named.is_empty(),
                }
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathAverage => {
            decl_name == Some("math avg")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathMedian => {
            decl_name == Some("math median")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathFloatUnary => {
            matches!(
                decl_name,
                Some(
                    "math arccos"
                        | "math arccosh"
                        | "math arcsin"
                        | "math arcsinh"
                        | "math arctan"
                        | "math arctanh"
                        | "math cos"
                        | "math cosh"
                        | "math exp"
                        | "math ln"
                        | "math sin"
                        | "math sinh"
                        | "math sqrt"
                        | "math tan"
                        | "math tanh"
                )
            ) && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.iter().all(|flag| {
                    matches!(flag.as_slice(), b"degrees" | b"d")
                        && matches!(
                            decl_name,
                            Some(
                                "math arccos"
                                    | "math arcsin"
                                    | "math arctan"
                                    | "math cos"
                                    | "math sin"
                                    | "math tan"
                            )
                        )
                })
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathLog => {
            decl_name == Some("math log")
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathVarianceStddev => {
            matches!(decl_name, Some("math stddev" | "math variance"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args
                    .flags
                    .iter()
                    .all(|flag| matches!(flag.as_slice(), b"sample" | b"s"))
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathSumProduct => {
            matches!(decl_name, Some("math sum" | "math product"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
        FixedLayoutValueConsumer::MathMinMax => {
            matches!(decl_name, Some("math min" | "math max"))
                && call_args_tracked_only_in_pipeline(src_dst, args, tracked_regs)
                && args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
        }
    }
}

fn call_args_tracked_only_in_pipeline(
    src_dst: RegId,
    args: &HirCallArgs,
    regs: &HashSet<RegId>,
) -> bool {
    (args.pipeline_input.is_some_and(|reg| regs.contains(&reg))
        || (args.pipeline_input.is_none() && regs.contains(&src_dst)))
        && !call_args_non_pipeline_touch_compile_time_value(args, regs)
}

fn call_args_tracked_only_in_positional(
    src_dst: RegId,
    args: &HirCallArgs,
    regs: &HashSet<RegId>,
    index: usize,
) -> bool {
    args.positional
        .get(index)
        .is_some_and(|reg| regs.contains(reg))
        && !args.pipeline_input.is_some_and(|reg| regs.contains(&reg))
        && !regs.contains(&src_dst)
        && !args
            .positional
            .iter()
            .enumerate()
            .any(|(arg_index, reg)| arg_index != index && regs.contains(reg))
        && !args.rest.iter().any(|reg| regs.contains(reg))
        && !args.named.iter().any(|(_, reg)| regs.contains(reg))
}

fn call_args_tracked_only_in_pipeline_or_positional(
    src_dst: RegId,
    args: &HirCallArgs,
    regs: &HashSet<RegId>,
    index: usize,
) -> bool {
    call_args_tracked_only_in_pipeline(src_dst, args, regs)
        || call_args_tracked_only_in_positional(src_dst, args, regs, index)
}

fn call_args_non_pipeline_touch_compile_time_value(
    args: &HirCallArgs,
    regs: &HashSet<RegId>,
) -> bool {
    args.positional.iter().any(|reg| regs.contains(reg))
        || args.rest.iter().any(|reg| regs.contains(reg))
        || args.named.iter().any(|(_, reg)| regs.contains(reg))
}

fn call_args_touch_compile_time_value(args: &HirCallArgs, regs: &HashSet<RegId>) -> bool {
    args.pipeline_input.is_some_and(|reg| regs.contains(&reg))
        || call_args_non_pipeline_touch_compile_time_value(args, regs)
}

fn compile_time_aggregate_transform_preserves_tracked_input(
    decl_name: Option<&str>,
    src_dst: RegId,
    args: &HirCallArgs,
    regs: &HashSet<RegId>,
    list_transforms_only: bool,
) -> bool {
    match decl_name {
        Some("append" | "prepend") => {
            args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("take") => {
            args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("skip" | "drop") => {
            args.positional.len() <= 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("first" | "last") => {
            (if list_transforms_only {
                args.positional.len() == 1
            } else {
                args.positional.len() <= 1
            }) && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("get") => {
            !list_transforms_only
                && args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("find") => {
            args.positional.len() == 1
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("compact") => {
            args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.iter().all(|flag| flag.as_slice() == b"empty")
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("reverse") => {
            args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("uniq") => {
            args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.is_empty()
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("sort") => {
            args.positional.is_empty()
                && args.rest.is_empty()
                && args.named.is_empty()
                && args.flags.iter().all(|flag| flag.as_slice() == b"reverse")
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        Some("split list") => {
            args.positional.len() == 1
                && args.rest.is_empty()
                && args
                    .named
                    .iter()
                    .all(|(name, _)| name.as_slice() == b"split")
                && args.flags.iter().all(|flag| flag.as_slice() == b"regex")
                && args.parser_info.is_empty()
                && call_args_tracked_only_in_pipeline(src_dst, args, regs)
        }
        _ => false,
    }
}

fn stmt_touches_compile_time_value(
    stmt: &HirStmt,
    regs: &HashSet<RegId>,
    vars: &HashSet<VarId>,
) -> bool {
    match stmt {
        HirStmt::Collect { src_dst }
        | HirStmt::Span { src_dst }
        | HirStmt::Drain { src: src_dst }
        | HirStmt::DrainIfEnd { src: src_dst }
        | HirStmt::CheckErrRedirected { src: src_dst }
        | HirStmt::GlobFrom { src_dst, .. }
        | HirStmt::Not { src_dst } => regs.contains(src_dst),
        HirStmt::StringAppend { src_dst, val } => regs.contains(src_dst) || regs.contains(val),
        HirStmt::ListPush { src_dst, item } => regs.contains(src_dst) || regs.contains(item),
        HirStmt::ListSpread { src_dst, items } => regs.contains(src_dst) || regs.contains(items),
        HirStmt::RecordInsert { src_dst, key, val } => {
            regs.contains(src_dst) || regs.contains(key) || regs.contains(val)
        }
        HirStmt::RecordSpread { src_dst, items } => regs.contains(src_dst) || regs.contains(items),
        HirStmt::BinaryOp {
            lhs_dst: src_dst,
            rhs,
            ..
        } => regs.contains(src_dst) || regs.contains(rhs),
        HirStmt::FollowCellPath { src_dst, path } => regs.contains(src_dst) || regs.contains(path),
        HirStmt::UpsertCellPath {
            src_dst,
            path,
            new_value,
        } => regs.contains(src_dst) || regs.contains(path) || regs.contains(new_value),
        HirStmt::Drop { src }
        | HirStmt::StoreEnv { src, .. }
        | HirStmt::WriteFile { src, .. }
        | HirStmt::CheckMatchGuard { src } => regs.contains(src),
        HirStmt::OpenFile { path, .. } => regs.contains(path),
        HirStmt::CloneCellPath { dst, src, path } => {
            regs.contains(dst) || regs.contains(src) || regs.contains(path)
        }
        HirStmt::LoadEnv { dst, .. }
        | HirStmt::LoadEnvOpt { dst, .. }
        | HirStmt::OnErrorInto { dst, .. } => regs.contains(dst),
        HirStmt::LoadVariable { dst, var_id } => regs.contains(dst) || vars.contains(var_id),
        HirStmt::StoreVariable { var_id, src } => vars.contains(var_id) || regs.contains(src),
        HirStmt::DropVariable { var_id } => vars.contains(var_id),
        HirStmt::Call { src_dst, args, .. } => {
            regs.contains(src_dst) || call_args_touch_compile_time_value(args, regs)
        }
        HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
            regs.contains(dst) || regs.contains(src)
        }
        HirStmt::LoadLiteral { dst, .. } | HirStmt::LoadValue { dst, .. } => regs.contains(dst),
        HirStmt::CloseFile { .. }
        | HirStmt::RedirectOut { .. }
        | HirStmt::RedirectErr { .. }
        | HirStmt::OnError { .. }
        | HirStmt::PopErrorHandler => false,
    }
}

fn compile_time_value_used_after(
    stmts: &[HirStmt],
    regs: &HashSet<RegId>,
    vars: &HashSet<VarId>,
) -> bool {
    let mut tracked_regs = regs.clone();
    let mut tracked_vars = vars.clone();

    for stmt in stmts {
        match stmt {
            HirStmt::Drain { src } | HirStmt::DrainIfEnd { src } | HirStmt::Drop { src }
                if tracked_regs.remove(src) =>
            {
                continue;
            }
            HirStmt::LoadLiteral { dst, .. } | HirStmt::LoadValue { dst, .. }
                if tracked_regs.remove(dst) =>
            {
                continue;
            }
            HirStmt::LoadVariable { dst, var_id } => {
                if tracked_vars.contains(var_id) {
                    return true;
                }
                if tracked_regs.remove(dst) {
                    continue;
                }
            }
            HirStmt::StoreVariable { var_id, src } => {
                if tracked_regs.contains(src) {
                    return true;
                }
                if tracked_vars.remove(var_id) {
                    continue;
                }
            }
            HirStmt::DropVariable { var_id } if tracked_vars.remove(var_id) => continue,
            HirStmt::Move { dst, src } | HirStmt::Clone { dst, src } => {
                if tracked_regs.contains(src) {
                    return true;
                }
                if tracked_regs.remove(dst) {
                    continue;
                }
            }
            HirStmt::Call { src_dst, args, .. } => {
                if call_args_touch_compile_time_value(args, &tracked_regs) {
                    return true;
                }
                if tracked_regs.remove(src_dst) {
                    continue;
                }
            }
            _ if stmt_touches_compile_time_value(stmt, &tracked_regs, &tracked_vars) => {
                return true;
            }
            _ => {}
        }
    }

    false
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
            HirLiteral::Float(val) => Some(Value::float(*val, span)),
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
    infer_ctx_param_excluding(ir_block, &HashSet::new())
}

/// Infer the context parameter VarId while excluding known captured variables.
///
/// Nushell omits unused closure parameters from the IR. In a closure like
/// `{|ctx| $captured }`, the first load-only variable may be a capture, not the
/// declared context parameter. Excluding captures prevents us from typing an
/// ordinary captured constant as the kernel context pointer.
pub fn infer_ctx_param_excluding(
    ir_block: &IrBlock,
    excluded_vars: &HashSet<VarId>,
) -> Option<VarId> {
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
            Instruction::StoreVariable { var_id, src }
                if collected_regs.contains(src) && !excluded_vars.contains(var_id) =>
            {
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
            if !stored_vars.contains(var_id)
                && !excluded_vars.contains(var_id)
                && !first_loaded.contains(var_id)
            {
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
        match instruction {
            Instruction::LoadLiteral { lit, .. } => match lit {
                Literal::Closure(block_id)
                | Literal::Block(block_id)
                | Literal::RowCondition(block_id) => {
                    if !block_ids.contains(block_id) {
                        block_ids.push(*block_id);
                    }
                }
                _ => {}
            },
            Instruction::PushParserInfo { info, .. } => {
                if let Some(block_id) = info.as_block()
                    && !block_ids.contains(&block_id)
                {
                    block_ids.push(block_id);
                }
            }
            _ => {}
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
