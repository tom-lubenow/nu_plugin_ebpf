//! `ebpf attach` command - attach an eBPF probe

use std::collections::{HashMap, HashSet};

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::casing::Casing;
use nu_protocol::engine::Closure;
use nu_protocol::ir::IrBlock;
use nu_protocol::{
    BlockId, Category, DeclId, Example, IntoSpanned, LabeledError, PipelineData, Record, Signature,
    Span, Spanned, SyntaxShape, Type, Value, record,
};

use crate::EbpfPlugin;
use crate::compiler::{
    EbpfProgram, ProbeContext, UserFunctionSig, UserParam, UserParamKind,
    compile_mir_to_ebpf_with_hints,
    hir::HirFunction,
    hir_type_infer, infer_ctx_param, lower_hir_to_mir_with_hints, lower_ir_to_hir,
    mir::{
        AddressSpace, BinOpKind, CtxField, MirFunction, MirInst, MirType, MirTypeHints, MirValue,
    },
    passes::optimize_with_ssa,
};
use crate::kernel_btf::{KernelBtf, TypeInfo};

/// Known eBPF helper commands that need to be mapped by decl_id
const EBPF_COMMANDS: &[&str] = &[
    "emit",
    "count",
    "histogram",
    "start-timer",
    "stop-timer",
    "read-str",
    "read-kernel-str",
    "kfunc-call",
    // Also include common nushell commands used in closures
    "where",
    "each",
    "skip",
    "first",
    "last",
    "get",
    "select",
    "reject",
    "default",
    "if",
    "match",
];

/// Build a mapping from DeclId to command name for known commands
fn build_decl_names(engine: &EngineInterface) -> Result<HashMap<DeclId, String>, LabeledError> {
    let mut decl_names = HashMap::new();

    for &cmd_name in EBPF_COMMANDS {
        if let Some(decl_id) = engine.find_decl(cmd_name).map_err(|e| {
            LabeledError::new("Failed to look up command").with_label(
                format!("Could not find '{}': {}", cmd_name, e),
                Span::unknown(),
            )
        })? {
            decl_names.insert(decl_id, cmd_name.to_string());
        }
    }

    Ok(decl_names)
}

/// Recursively fetch IR for all closures referenced in an IR block
fn fetch_closure_irs(
    engine: &EngineInterface,
    ir_block: &IrBlock,
    closure_irs: &mut HashMap<BlockId, IrBlock>,
    span: Span,
) -> Result<(), LabeledError> {
    use crate::compiler::extract_closure_block_ids;

    let block_ids = extract_closure_block_ids(ir_block);

    for block_id in block_ids {
        if closure_irs.contains_key(&block_id) {
            continue; // Already fetched
        }

        let nested_ir = engine.get_block_ir(block_id).map_err(|e| {
            LabeledError::new("Failed to get IR for nested closure")
                .with_label(format!("Block {}: {}", block_id.get(), e), span)
        })?;

        // Recursively fetch any closures referenced by this closure
        fetch_closure_irs(engine, &nested_ir, closure_irs, span)?;

        closure_irs.insert(block_id, nested_ir);
    }

    Ok(())
}

fn parse_view_ir_json(json: &str, span: Span) -> Result<IrBlock, LabeledError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        LabeledError::new("Failed to parse 'view ir --json' output").with_label(e.to_string(), span)
    })?;
    let ir_value = value.get("ir_block").ok_or_else(|| {
        LabeledError::new("Missing ir_block in 'view ir --json' output")
            .with_label("Expected ir_block field", span)
    })?;
    let ir_block: IrBlock = serde_json::from_value(ir_value.clone()).map_err(|e| {
        LabeledError::new("Failed to decode 'view ir --json' block").with_label(e.to_string(), span)
    })?;
    Ok(ir_block)
}

fn fetch_decl_ir(
    engine: &EngineInterface,
    decl_id: DeclId,
    span: Span,
) -> Result<IrBlock, LabeledError> {
    let view_ir_decl = engine
        .find_decl("view ir")
        .map_err(|e| {
            LabeledError::new("Failed to look up 'view ir'").with_label(e.to_string(), span)
        })?
        .ok_or_else(|| {
            LabeledError::new("Required command 'view ir' not found")
                .with_label("User-defined functions require view ir", span)
        })?;

    let mut eval = EvaluatedCall::new(span);
    eval.add_flag("json".into_spanned(span));
    eval.add_flag("decl-id".into_spanned(span));
    eval.add_positional(Value::int(decl_id.get() as i64, span));

    let data = engine
        .call_decl(view_ir_decl, eval, PipelineData::empty(), true, false)
        .map_err(|e| {
            LabeledError::new("Failed to run 'view ir'").with_label(e.to_string(), span)
        })?;
    let value = data.into_value(span).map_err(|e| {
        LabeledError::new("Failed to decode 'view ir' output").with_label(e.to_string(), span)
    })?;
    let json = match value {
        Value::String { val, .. } => val,
        _ => {
            return Err(LabeledError::new("Unexpected 'view ir' output type")
                .with_label("Expected string output from view ir --json", span));
        }
    };

    parse_view_ir_json(&json, span)
}

fn collect_user_function_irs(
    engine: &EngineInterface,
    ir_block: &IrBlock,
    closure_irs: &mut HashMap<BlockId, IrBlock>,
    decl_names: &HashMap<DeclId, String>,
    span: Span,
) -> Result<HashMap<DeclId, IrBlock>, LabeledError> {
    use crate::compiler::extract_call_decl_ids;

    let mut pending = Vec::new();
    let mut seen = HashSet::new();

    let scan_block = |block: &IrBlock, seen: &mut HashSet<DeclId>, pending: &mut Vec<DeclId>| {
        for decl_id in extract_call_decl_ids(block) {
            if decl_names.contains_key(&decl_id) {
                continue;
            }
            if seen.insert(decl_id) {
                pending.push(decl_id);
            }
        }
    };

    scan_block(ir_block, &mut seen, &mut pending);
    for ir in closure_irs.values() {
        scan_block(ir, &mut seen, &mut pending);
    }

    let mut user_irs = HashMap::new();
    let mut scanned_closures: HashSet<BlockId> = closure_irs.keys().copied().collect();

    while let Some(decl_id) = pending.pop() {
        let ir = fetch_decl_ir(engine, decl_id, span)?;
        scan_block(&ir, &mut seen, &mut pending);

        fetch_closure_irs(engine, &ir, closure_irs, span)?;
        for (block_id, closure_ir) in closure_irs.iter() {
            if scanned_closures.insert(*block_id) {
                scan_block(closure_ir, &mut seen, &mut pending);
            }
        }

        user_irs.insert(decl_id, ir);
    }

    Ok(user_irs)
}

fn signature_from_record(record: &Record) -> Option<UserFunctionSig> {
    let sig_val = record.cased(Casing::Sensitive).get("signatures")?;
    let sig_record = match sig_val {
        Value::Record { val, .. } => val,
        _ => return None,
    };
    let any_val = sig_record.cased(Casing::Sensitive).get("any")?;
    let params = match any_val {
        Value::List { vals, .. } => vals,
        _ => return None,
    };
    let mut out = Vec::new();
    for param in params {
        let record = match param {
            Value::Record { val, .. } => val,
            _ => continue,
        };
        let param_type = record
            .cased(Casing::Sensitive)
            .get("parameter_type")
            .and_then(|v| match v {
                Value::String { val, .. } => Some(val.as_str()),
                _ => None,
            })?;
        let name = record
            .cased(Casing::Sensitive)
            .get("parameter_name")
            .and_then(|v| match v {
                Value::String { val, .. } => Some(val.clone()),
                Value::Nothing { .. } => None,
                _ => None,
            });
        let optional = record
            .cased(Casing::Sensitive)
            .get("is_optional")
            .and_then(|v| match v {
                Value::Bool { val, .. } => Some(*val),
                _ => None,
            })
            .unwrap_or(false);
        let kind = match param_type {
            "input" => UserParamKind::Input,
            "positional" => UserParamKind::Positional,
            "named" => UserParamKind::Named,
            "switch" => UserParamKind::Switch,
            "rest" => UserParamKind::Rest,
            "output" => continue,
            _ => continue,
        };
        out.push(UserParam {
            name,
            kind,
            optional,
        });
    }
    Some(UserFunctionSig { params: out })
}

fn fetch_user_function_signatures(
    engine: &EngineInterface,
    decl_ids: &HashSet<DeclId>,
    span: Span,
) -> Result<HashMap<DeclId, UserFunctionSig>, LabeledError> {
    if decl_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let scope_decl = engine
        .find_decl("scope commands")
        .map_err(|e| {
            LabeledError::new("Failed to look up 'scope commands'").with_label(e.to_string(), span)
        })?
        .ok_or_else(|| {
            LabeledError::new("Required command 'scope commands' not found")
                .with_label("User-defined functions require scope commands", span)
        })?;

    let call = EvaluatedCall::new(span);
    let data = engine
        .call_decl(scope_decl, call, PipelineData::empty(), true, false)
        .map_err(|e| {
            LabeledError::new("Failed to run 'scope commands'").with_label(e.to_string(), span)
        })?;
    let value = data.into_value(span).map_err(|e| {
        LabeledError::new("Failed to decode 'scope commands' output")
            .with_label(e.to_string(), span)
    })?;

    let list = match value {
        Value::List { vals, .. } => vals,
        _ => {
            return Err(LabeledError::new("Unexpected 'scope commands' output type")
                .with_label("Expected list output from scope commands", span));
        }
    };

    let mut sigs = HashMap::new();
    for item in list {
        let record = match item {
            Value::Record { val, .. } => val,
            _ => continue,
        };
        let decl_id = record
            .cased(Casing::Sensitive)
            .get("decl_id")
            .and_then(|v| match v {
                Value::Int { val, .. } => Some(DeclId::new(*val as usize)),
                _ => None,
            });
        let decl_id = match decl_id {
            Some(id) => id,
            None => continue,
        };
        if !decl_ids.contains(&decl_id) {
            continue;
        }
        if let Some(sig) = signature_from_record(&record) {
            sigs.insert(decl_id, sig);
        }
    }

    Ok(sigs)
}

fn pointer_hint(address_space: AddressSpace) -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space,
    }
}

fn byte_array_mir_type(size: usize) -> Option<MirType> {
    if size == 0 {
        return None;
    }
    Some(MirType::Array {
        elem: Box::new(MirType::U8),
        len: size,
    })
}

fn opaque_struct_mir_type(
    name: &str,
    size: usize,
    kernel_btf_type_id: Option<u32>,
) -> Option<MirType> {
    Some(MirType::Struct {
        name: Some(name.to_string()),
        kernel_btf_type_id,
        fields: vec![crate::compiler::mir::StructField {
            name: "__opaque".to_string(),
            ty: byte_array_mir_type(size)?,
            offset: 0,
            synthetic: false,
        }],
    })
}

fn mir_type_from_type_info(type_info: &TypeInfo) -> Option<MirType> {
    match type_info {
        TypeInfo::Int { size, signed } => Some(match (*size, *signed) {
            (1, false) => MirType::U8,
            (1, true) => MirType::I8,
            (2, false) => MirType::U16,
            (2, true) => MirType::I16,
            (4, false) => MirType::U32,
            (4, true) => MirType::I32,
            (8, false) => MirType::U64,
            (8, true) => MirType::I64,
            _ => return None,
        }),
        TypeInfo::Ptr { target, is_user } => Some(MirType::Ptr {
            pointee: Box::new(mir_type_from_type_info(target).unwrap_or(MirType::U8)),
            address_space: if *is_user {
                AddressSpace::User
            } else {
                AddressSpace::Kernel
            },
        }),
        TypeInfo::Array { element, len } => Some(MirType::Array {
            elem: Box::new(mir_type_from_type_info(element)?),
            len: *len,
        }),
        TypeInfo::Struct {
            name,
            btf_type_id,
            fields,
            size,
        } => {
            if *size == 0 {
                return None;
            }
            if fields.is_empty() {
                return opaque_struct_mir_type(name, *size, *btf_type_id);
            }

            let mut out = Vec::with_capacity(fields.len() + 1);
            let mut cursor = 0usize;
            let mut pad_index = 0usize;
            for field in fields {
                if field.size == 0 || field.offset >= *size || field.offset < cursor {
                    continue;
                }
                if field.offset > cursor {
                    out.push(crate::compiler::mir::StructField {
                        name: format!("__layout_pad{}", pad_index),
                        ty: byte_array_mir_type(field.offset - cursor)?,
                        offset: cursor,
                        synthetic: false,
                    });
                    pad_index += 1;
                }
                let ty = mir_type_from_type_info(&field.type_info)
                    .or_else(|| byte_array_mir_type(field.size))
                    .filter(|ty| ty.size() == field.size)
                    .or_else(|| byte_array_mir_type(field.size))?;
                let field_end = field.offset.checked_add(field.size)?;
                if field_end > *size {
                    continue;
                }
                out.push(crate::compiler::mir::StructField {
                    name: field.name.clone(),
                    ty,
                    offset: field.offset,
                    synthetic: false,
                });
                cursor = field_end;
            }
            if out.is_empty() {
                return opaque_struct_mir_type(name, *size, *btf_type_id);
            }
            if cursor < *size {
                out.push(crate::compiler::mir::StructField {
                    name: format!("__layout_pad{}", pad_index),
                    ty: byte_array_mir_type(*size - cursor)?,
                    offset: cursor,
                    synthetic: false,
                });
            }
            Some(MirType::Struct {
                name: Some(name.clone()),
                kernel_btf_type_id: *btf_type_id,
                fields: out,
            })
        }
        _ => None,
    }
}

fn runtime_trampoline_root_type(type_info: &TypeInfo) -> Option<MirType> {
    match type_info {
        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => Some(MirType::Ptr {
            pointee: Box::new(
                mir_type_from_type_info(type_info).unwrap_or(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: type_info.size(),
                }),
            ),
            address_space: AddressSpace::Stack,
        }),
        _ => mir_type_from_type_info(type_info),
    }
}

fn recover_ctx_field_hint(
    probe_ctx: Option<&ProbeContext>,
    field: &CtxField,
    has_backing_slot: bool,
) -> Option<MirType> {
    if has_backing_slot {
        return Some(pointer_hint(AddressSpace::Stack));
    }

    match field {
        CtxField::Comm => Some(MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            }),
            address_space: AddressSpace::Stack,
        }),
        CtxField::Arg(idx) => {
            let ctx = probe_ctx?;
            if matches!(
                ctx.probe_type,
                crate::compiler::EbpfProgramType::Fentry | crate::compiler::EbpfProgramType::Fexit
            ) {
                let type_info = KernelBtf::get()
                    .function_trampoline_arg_type_info(&ctx.target, *idx as usize)
                    .ok()
                    .flatten()?;
                runtime_trampoline_root_type(&type_info)
            } else if ctx.is_userspace() {
                Some(pointer_hint(AddressSpace::User))
            } else {
                None
            }
        }
        CtxField::RetVal => {
            let ctx = probe_ctx?;
            if !matches!(ctx.probe_type, crate::compiler::EbpfProgramType::Fexit) {
                return None;
            }
            let type_info = KernelBtf::get()
                .function_trampoline_ret_type_info(&ctx.target)
                .ok()
                .flatten()?;
            runtime_trampoline_root_type(&type_info)
        }
        _ => None,
    }
}

fn recover_function_type_hints(
    func: &MirFunction,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut HashMap<crate::compiler::mir::VReg, MirType>,
    stack_slot_hints: &HashMap<crate::compiler::mir::StackSlotId, MirType>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            for inst in block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
            {
                let recovered = match inst {
                    MirInst::Copy { dst, src } => match src {
                        MirValue::VReg(src_vreg) => {
                            hints.get(src_vreg).cloned().map(|ty| (*dst, ty))
                        }
                        MirValue::StackSlot(slot) => Some((
                            *dst,
                            stack_slot_hints
                                .get(slot)
                                .cloned()
                                .map(|ty| MirType::Ptr {
                                    pointee: Box::new(ty),
                                    address_space: AddressSpace::Stack,
                                })
                                .unwrap_or_else(|| pointer_hint(AddressSpace::Stack)),
                        )),
                        MirValue::Const(_) => None,
                    },
                    MirInst::Load { dst, ty, .. } | MirInst::LoadSlot { dst, ty, .. } => {
                        (!matches!(ty, MirType::Unknown)).then(|| (*dst, ty.clone()))
                    }
                    MirInst::LoadCtxField { dst, field, slot } => slot
                        .and_then(|slot| {
                            stack_slot_hints.get(&slot).cloned().map(|ty| {
                                (
                                    *dst,
                                    MirType::Ptr {
                                        pointee: Box::new(ty),
                                        address_space: AddressSpace::Stack,
                                    },
                                )
                            })
                        })
                        .or_else(|| {
                            recover_ctx_field_hint(probe_ctx, field, slot.is_some())
                                .map(|ty| (*dst, ty))
                        }),
                    MirInst::MapLookup { dst, .. } => Some((*dst, pointer_hint(AddressSpace::Map))),
                    MirInst::BinOp { dst, op, lhs, rhs }
                        if matches!(op, BinOpKind::Add | BinOpKind::Sub) =>
                    {
                        let lhs_ptr = match lhs {
                            MirValue::VReg(vreg) => hints.get(vreg),
                            _ => None,
                        };
                        let rhs_ptr = match rhs {
                            MirValue::VReg(vreg) => hints.get(vreg),
                            _ => None,
                        };
                        lhs_ptr
                            .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                            .cloned()
                            .or_else(|| {
                                if matches!(op, BinOpKind::Add) {
                                    rhs_ptr
                                        .filter(|ty| matches!(ty, MirType::Ptr { .. }))
                                        .cloned()
                                } else {
                                    None
                                }
                            })
                            .map(|ty| (*dst, ty))
                    }
                    _ => None,
                };

                if let Some((dst, ty)) = recovered
                    && hints.get(&dst).is_none()
                {
                    hints.insert(dst, ty);
                    changed = true;
                }
            }
        }
    }
}

fn recover_optimized_type_hints(
    program: &crate::compiler::mir::MirProgram,
    probe_ctx: Option<&ProbeContext>,
    hints: &mut MirTypeHints,
) {
    recover_function_type_hints(
        &program.main,
        probe_ctx,
        &mut hints.main,
        &hints.main_stack_slots,
    );
    if hints.subfunctions.len() < program.subfunctions.len() {
        hints
            .subfunctions
            .resize_with(program.subfunctions.len(), HashMap::new);
    }
    if hints.subfunction_stack_slots.len() < program.subfunctions.len() {
        hints
            .subfunction_stack_slots
            .resize_with(program.subfunctions.len(), HashMap::new);
    }
    for ((subfn, subfn_hints), subfn_stack_slot_hints) in program
        .subfunctions
        .iter()
        .zip(hints.subfunctions.iter_mut())
        .zip(hints.subfunction_stack_slots.iter())
    {
        recover_function_type_hints(subfn, None, subfn_hints, subfn_stack_slot_hints);
    }
}

#[derive(Clone)]
pub struct EbpfAttach;

impl PluginCommand for EbpfAttach {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf attach"
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel function, tracepoint, or userspace function."
    }

    fn extra_description(&self) -> &str {
        r#"This command compiles a Nushell closure to eBPF bytecode and attaches
it to the specified probe point. The closure runs in the kernel whenever
the probe point is hit.

Supported attach types:
  - kprobe, kretprobe
  - fentry, fexit
  - tracepoint, raw_tracepoint
  - uprobe, uretprobe

Context parameter syntax (recommended):
  The closure can take a context parameter to access probe information:

  Universal fields (all probe types):
    {|ctx| $ctx.pid }     - Get process ID (thread ID)
    {|ctx| $ctx.tgid }    - Get thread group ID (process ID)
    {|ctx| $ctx.uid }     - Get user ID
    {|ctx| $ctx.gid }     - Get group ID
    {|ctx| $ctx.comm }    - Get process command name (first 16 bytes)
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds

  Function fields:
    {|ctx| $ctx.arg0 }    - Get function argument 0
    {|ctx| $ctx.arg1 }    - Get function argument 1
    {|ctx| $ctx.retval }  - Get return value (kretprobe/uretprobe/fexit)

    Note: kprobe/uprobe expose pt_regs-style ctx.arg0-5. fentry/fexit use
    kernel BTF. Scalar/pointer trampoline args and returns work directly.
    By-value trampoline args and pointer-backed trampoline args/returns
    support scalar/pointer field projection like ctx.arg0.some_field.
    Pointer-backed projections use null-guarded bpf_probe_read_{kernel,user}
    and can cross intermediate and repeated pointer hops like ctx.arg0.foo.bar
    or ctx.arg0.fdt.fd.f_inode.i_ino. Fixed-size arrays can be indexed with
    numeric path segments like ctx.arg0.comm.0, and pointer-backed sequences
    can now also be indexed with constant numeric segments such as
    `ctx.arg0.fdt.fd.0.f_inode.i_ino` or `let fd = $ctx.arg0.fdt.fd;
    $fd.0.f_inode.i_ino`. Numeric `get` now supports the same typed
    kernel/user pointer traversal through a register value, for example
    `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
    Bounded ascending `for` loops over static integer ranges now lower to
    verifier-safe loops, so `for i in 0..0 { ... get $i ... }` works;
    descending ranges are still rejected.
    Terminal array leaves and unsupported aggregate leaves are exposed as
    stack-backed byte buffers. Representable terminal
    struct leaves keep their field layouts for count/counter decoding, and
    single-value emit can now stream those struct leaves as records. Nested
    array/record fields inside emitted values also decode recursively when the
    compiler can preserve their layouts. emit still preserves unsupported
    aggregate layouts as binary payloads, and count can use them as byte-buffer
    keys. ebpf counters decodes those keys using any schema the compiler still
    has: arrays and typed structs can surface as strings, lists, or records;
    opaque aggregate layouts still display as binary. Plain trampoline ctx.argN
    and ctx.retval loads also preserve their typed pointer or aggregate layouts
    across bindings, for example `let files = $ctx.arg0;
    $files.fdt.fd.f_inode.i_ino` or `let inode = $ctx.arg0.f_inode;
    $inode.i_sb.s_flags`. 16-byte byte-array/string keys such as ctx.arg0.comm
    continue to display as strings.
    Aggregate fexit returns still depend on kernel trampoline support;
    some kernels reject struct returns entirely.

  Tracepoint fields:
    Access fields specific to each tracepoint. Fields are read from tracefs.
    Example for syscalls/sys_enter_openat:
      {|ctx| $ctx.dfd }      - Directory file descriptor
      {|ctx| $ctx.filename } - Pointer to filename string
      {|ctx| $ctx.flags }    - Open flags

Output commands:
  emit              - Send value to userspace via ring buffer
  read-str          - Read string from userspace memory pointer
  read-kernel-str   - Read string from kernel memory (rare)

Aggregation commands:
  count             - Count occurrences by key
  histogram         - Add value to log2 histogram

Timing commands:
  start-timer       - Record timestamp (use with --pin for cross-probe timing)
  stop-timer        - Calculate elapsed nanoseconds since start-timer

Advanced commands:
  kfunc-call        - Call a typed kernel kfunc by name (optional --btf-id)

Flags:
  --stream (-s)     Stream events in real-time. The command blocks and yields
                    events as they occur. Use Ctrl-C to stop, or pipe to
                    `first N` to capture a fixed number of events.

  --dry-run (-n)    Generate eBPF bytecode without loading into kernel.
                    Returns the compiled ELF binary. Useful for:
                    - Debugging compilation issues
                    - Inspecting generated bytecode (pipe to `save prog.o`)
                    - Validating closures before deployment

  --pin (-p) GROUP  Pin maps to /sys/fs/bpf/nushell/GROUP/ for sharing between
                    probes. Essential for timing measurements where kprobe and
                    kretprobe need to share the timestamp map:

                    let entry = ebpf attach --pin timing 'kprobe:vfs_read' {
                        start-timer
                    }
                    let exit = ebpf attach --pin timing 'kretprobe:vfs_read' {
                        stop-timer | histogram
                    }

                    Maps are automatically unpinned when all probes detach.

Limits:
  - eBPF stack: 512 bytes (complex closures may overflow)
  - String reads: 128 bytes max (longer strings truncated)
  - Map entries: 10,240 max per map (count, histogram, timers)
  - Ring buffer: 256 KB (high event rates may drop events)
  - Stack traces: 127 frames max

Discovering tracepoints:
  ls /sys/kernel/tracing/events/              # List categories
  ls /sys/kernel/tracing/events/syscalls/     # List syscall tracepoints
  cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format  # View fields

Requirements:
  - Linux kernel 4.18+ for the basic tracing paths
  - Linux kernel 5.5+ with /sys/kernel/btf/vmlinux for fentry/fexit
  - CAP_BPF + CAP_PERFMON capabilities, or root access
  - Run `ebpf setup` to configure capabilities"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf attach")
            .input_output_types(vec![
                (Type::Nothing, Type::Int),     // Returns probe ID (default)
                (Type::Nothing, Type::Binary),  // Returns ELF with --dry-run
                (Type::Nothing, Type::table()), // Streams events with --stream
            ])
            .required(
                "probe",
                SyntaxShape::String,
                "The probe point (e.g., 'kprobe:sys_clone' or 'fentry:ksys_read').",
            )
            .required(
                "closure",
                SyntaxShape::Closure(None),
                "The closure to compile and run as eBPF bytecode in the kernel.",
            )
            .switch(
                "stream",
                "Stream events directly (Ctrl-C to stop)",
                Some('s'),
            )
            .switch(
                "dry-run",
                "Generate bytecode but don't load into kernel",
                Some('n'),
            )
            .named(
                "pin",
                SyntaxShape::String,
                "Pin maps to share between probes (e.g., --pin mygroup)",
                Some('p'),
            )
            .category(Category::Experimental)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec![
            "bpf",
            "kernel",
            "trace",
            "probe",
            "kprobe",
            "fentry",
            "fexit",
            "tracepoint",
            "uprobe",
            "uretprobe",
            "userspace",
        ]
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }",
                description: "Stream events from sys_clone (Ctrl-C to stop)",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10",
                description: "Capture first 10 sys_read events",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.filename | emit }",
                description: "Stream filenames from openat syscalls using tracepoint",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fentry:do_sys_openat2' {|ctx| if $ctx.arg1 != 0 { $ctx.arg1 | read-str --max-len 64 | emit } } | first 5",
                description: "Capture the first 5 fentry filenames using BTF-backed trampoline args",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'fexit:ksys_read' {|ctx| $ctx.retval | emit } | first 5",
                description: "Capture the first 5 fexit return values using BTF-backed trampolines",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_attach(engine, call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_attach(
    engine: &EngineInterface,
    call: &EvaluatedCall,
) -> Result<PipelineData, LabeledError> {
    use crate::loader::{LoadError, get_state, parse_probe_spec};

    let probe_spec: String = call.req(0)?;
    let closure: Spanned<Closure> = call.req(1)?;
    let dry_run = call.has_flag("dry-run")?;
    let stream = call.has_flag("stream")?;
    let pin_group: Option<String> = call.get_flag("pin")?;

    // Parse the probe specification (includes validation)
    let (prog_type, target) = parse_probe_spec(&probe_spec).map_err(|e| match &e {
        crate::loader::LoadError::FunctionNotFound { name, suggestions } => {
            let help = if suggestions.is_empty() {
                format!("Check the function name. Use 'sudo cat /sys/kernel/tracing/available_filter_functions | grep {name}' to find available functions.")
            } else {
                format!("Did you mean: {}?", suggestions.join(", "))
            };
            LabeledError::new(format!("Kernel function '{}' not found", name))
                .with_label("This function is not available for probing", call.head)
                .with_help(help)
        }
        crate::loader::LoadError::TracepointNotFound { category, name } => {
            LabeledError::new(format!("Tracepoint '{}/{}' not found", category, name))
                .with_label("This tracepoint does not exist", call.head)
                .with_help(format!(
                    "Use 'sudo ls /sys/kernel/tracing/events/{}' to see available tracepoints",
                    category
                ))
        }
        crate::loader::LoadError::UnsupportedTrampolineTarget {
            probe_type,
            target,
            reason,
        } => {
            let mut err =
                LabeledError::new(format!("Unsupported {} target '{}'", probe_type, target))
                    .with_label(reason.clone(), call.head);
            if let Some(help) = match probe_type.as_str() {
                "fentry" | "fexit" => Some(
                    "fentry/fexit require kernel BTF and a trampoline-compatible target signature. Try a scalar/pointer-return target or use kprobe/kretprobe for broader coverage",
                ),
                _ => None,
            } {
                err = err.with_help(help);
            }
            err
        }
        crate::loader::LoadError::NeedsSudo => {
            LabeledError::new("Elevated privileges required")
                .with_label("eBPF operations require root or CAP_BPF capability", call.head)
                .with_help("Run nushell with sudo: sudo nu")
        }
        _ => LabeledError::new("Invalid probe specification")
            .with_label(e.to_string(), call.head)
            .with_help("Use format like 'kprobe:sys_clone' or 'tracepoint:syscalls/sys_enter_read'"),
    })?;

    let probe_context = ProbeContext::new(prog_type, &target);

    // Get IR block from engine via plugin protocol
    let ir_block = engine.get_block_ir(closure.item.block_id).map_err(|e| {
        LabeledError::new("Failed to get IR for closure").with_label(e.to_string(), closure.span)
    })?;

    // Build decl_id -> command name mapping for known commands
    let decl_names = build_decl_names(engine)?;

    // Fetch IR for any nested closures (used by where, each, etc.)
    let mut closure_irs = HashMap::new();
    fetch_closure_irs(engine, &ir_block, &mut closure_irs, call.head)?;

    // Fetch IR for any user-defined functions referenced by the closure or nested closures.
    let user_ir_blocks =
        collect_user_function_irs(engine, &ir_block, &mut closure_irs, &decl_names, call.head)?;

    // Convert captures to (String, i64) pairs for integer captures
    let captures: Vec<(String, i64)> = closure
        .item
        .captures
        .iter()
        .filter_map(|(var_id, value)| {
            if let Value::Int { val, .. } = value {
                Some((format!("var_{}", var_id.get()), *val))
            } else {
                None
            }
        })
        .collect();

    // Infer the context parameter from IR - it's the first variable that's loaded
    // but never stored (i.e., a parameter rather than a local variable)
    let ctx_param = infer_ctx_param(&ir_block);

    let hir_program = lower_ir_to_hir(ir_block, closure_irs, captures, ctx_param).map_err(|e| {
        LabeledError::new("eBPF compilation failed")
            .with_label(e.to_string(), call.head)
            .with_help("The closure may use unsupported operations")
    })?;

    let mut user_functions = HashMap::new();
    for (decl_id, ir) in user_ir_blocks.iter() {
        let func = HirFunction::from_ir_block(ir.clone()).map_err(|e| {
            LabeledError::new("eBPF compilation failed")
                .with_label(e.to_string(), call.head)
                .with_help("User-defined function uses unsupported operations")
        })?;
        user_functions.insert(*decl_id, func);
    }

    let user_decl_ids: HashSet<DeclId> = user_functions.keys().copied().collect();
    let user_signatures = fetch_user_function_signatures(engine, &user_decl_ids, call.head)?;

    let hir_types = match hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    ) {
        Ok(types) => types,
        Err(errors) => {
            if let Some(err) = errors.into_iter().next() {
                return Err(LabeledError::new("eBPF compilation failed")
                    .with_label(err.to_string(), call.head)
                    .with_help("The closure may use unsupported operations"));
            }
            unreachable!("infer_hir_types returned empty error list");
        }
    };

    // Lower HIR to MIR
    let lower_result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_context),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &user_signatures,
    )
    .map_err(|e| {
        LabeledError::new("eBPF compilation failed")
            .with_label(e.to_string(), call.head)
            .with_help("The closure may use unsupported operations")
    })?;
    let mut mir_program = lower_result.program;
    let mut type_hints = lower_result.type_hints;

    // Run SSA-based optimizations
    optimize_with_ssa(&mut mir_program.main);
    for subfn in &mut mir_program.subfunctions {
        optimize_with_ssa(subfn);
    }
    recover_optimized_type_hints(&mir_program, Some(&probe_context), &mut type_hints);

    // Compile MIR to eBPF
    let compile_result =
        compile_mir_to_ebpf_with_hints(&mir_program, Some(&probe_context), Some(&type_hints))
            .map_err(|e| {
                LabeledError::new("eBPF compilation failed")
                    .with_label(e.to_string(), call.head)
                    .with_help("Check that the closure uses supported BPF operations")
            })?;

    let mut program = EbpfProgram::with_maps(
        prog_type,
        &target,
        "nushell_ebpf",
        compile_result.bytecode,
        compile_result.main_size,
        compile_result.maps,
        compile_result.relocations,
        compile_result.subfunction_symbols,
        compile_result.event_schema,
        compile_result.bytes_counter_key_schema,
    );

    if pin_group.is_some() {
        program = program.with_pinning();
    }

    if dry_run {
        let elf = program.to_elf().map_err(|e| {
            LabeledError::new("Failed to generate ELF").with_label(e.to_string(), call.head)
        })?;
        return Ok(PipelineData::Value(Value::binary(elf, call.head), None));
    }

    // Load and attach
    let state = get_state();
    let probe_id = state
        .attach_with_pin(&program, pin_group.as_deref())
        .map_err(|e| {
            let help = match &e {
                LoadError::PermissionDenied => {
                    Some("Try running with sudo or grant CAP_BPF capability")
                }
                _ => None,
            };
            let mut err = LabeledError::new("Failed to attach eBPF probe")
                .with_label(e.to_string(), call.head);
            if let Some(h) = help {
                err = err.with_help(h);
            }
            err
        })?;

    if stream {
        // For streaming, we return values one at a time
        // In a plugin, we can use PipelineData with an iterator
        let span = call.head;
        let iter = EventStreamIterator::new(probe_id, span);
        Ok(PipelineData::ListStream(
            nu_protocol::ListStream::new(iter, span, engine.signals().clone()),
            None,
        ))
    } else {
        Ok(PipelineData::Value(
            Value::int(probe_id as i64, call.head),
            None,
        ))
    }
}

/// Iterator that streams events from an attached eBPF probe
#[cfg(target_os = "linux")]
struct EventStreamIterator {
    probe_id: u32,
    span: Span,
    pending_events: std::collections::VecDeque<Value>,
}

#[cfg(target_os = "linux")]
impl EventStreamIterator {
    fn new(probe_id: u32, span: Span) -> Self {
        Self {
            probe_id,
            span,
            pending_events: std::collections::VecDeque::new(),
        }
    }

    fn poll_batch(&mut self) {
        use crate::loader::{BpfEventData, get_state};
        use std::time::Duration;

        let state = get_state();
        if let Ok(events) = state.poll_events(self.probe_id, Duration::from_millis(100)) {
            for e in events {
                let value = match e.data {
                    BpfEventData::Record(fields) => {
                        let mut rec = Record::new();
                        for (name, value) in fields {
                            let val = Self::field_value_to_nu_value(value, self.span);
                            rec.push(name, val);
                        }
                        rec.push("cpu", Value::int(e.cpu as i64, self.span));
                        Value::record(rec, self.span)
                    }
                    _ => {
                        let value = match e.data {
                            BpfEventData::Int(v) => Value::int(v, self.span),
                            BpfEventData::String(s) => Value::string(s, self.span),
                            BpfEventData::Bytes(b) => Value::binary(b, self.span),
                            BpfEventData::Record(_) => unreachable!(),
                        };
                        Value::record(
                            record! {
                                "value" => value,
                                "cpu" => Value::int(e.cpu as i64, self.span),
                            },
                            self.span,
                        )
                    }
                };
                self.pending_events.push_back(value);
            }
        }
    }

    fn field_value_to_nu_value(value: crate::loader::BpfFieldValue, span: Span) -> Value {
        match value {
            crate::loader::BpfFieldValue::Int(v) => Value::int(v, span),
            crate::loader::BpfFieldValue::String(s) => Value::string(s, span),
            crate::loader::BpfFieldValue::Bytes(b) => Value::binary(b, span),
            crate::loader::BpfFieldValue::Array(values) => Value::list(
                values
                    .into_iter()
                    .map(|value| Self::field_value_to_nu_value(value, span))
                    .collect(),
                span,
            ),
            crate::loader::BpfFieldValue::Record(fields) => {
                let mut rec = Record::new();
                for (name, value) in fields {
                    rec.push(name, Self::field_value_to_nu_value(value, span));
                }
                Value::record(rec, span)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Iterator for EventStreamIterator {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Return any pending events first
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }

        // Keep polling until we get an event
        // This is a blocking iterator - it will keep trying until events arrive
        loop {
            self.poll_batch();
            if let Some(event) = self.pending_events.pop_front() {
                return Some(event);
            }
            // Small sleep to avoid busy-waiting
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for EventStreamIterator {
    fn drop(&mut self) {
        use crate::loader::get_state;
        let _ = get_state().detach(self.probe_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::recover_optimized_type_hints;
    use crate::compiler::hir::{
        HirBlock, HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram, HirStmt,
        HirTerminator,
    };
    use crate::compiler::hir_to_mir::lower_hir_to_mir_with_hints;
    use crate::compiler::passes::optimize_with_ssa;
    use crate::compiler::{
        CounterKeySchema, CounterKeySchemaField, EbpfProgramType, ProbeContext,
        compile_mir_to_ebpf_with_hints,
    };
    use nu_protocol::DeclId;
    use nu_protocol::ast::{CellPath, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::{RegId, Span, VarId};

    fn make_ctx_path_program(cell_path: CellPath) -> HirProgram {
        let ctx_var = VarId::new(0);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(cell_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 4],
            ast: vec![None; 4],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn string_member(name: &str) -> PathMember {
        PathMember::test_string(name.to_string(), false, Casing::Sensitive)
    }

    fn make_ctx_path_call_program(cell_path: CellPath, decl_id: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(cell_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 4],
            ast: vec![None; 4],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_path_program(binding: CellPath, access: CellPath) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(2),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 7],
            ast: vec![None; 7],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_get_program(
        binding: CellPath,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: bound_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: bound_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 9],
            ast: vec![None; 9],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    #[test]
    fn test_recover_optimized_type_hints_for_pointer_hop_trampoline_projection() {
        let hir = make_ctx_path_program(CellPath {
            members: vec![
                string_member("arg0"),
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("pointer-hop field projection should lower");

        optimize_with_ssa(&mut lowering.program.main);
        recover_optimized_type_hints(
            &lowering.program,
            Some(&probe_ctx),
            &mut lowering.type_hints,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized pointer-hop field projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_struct_leaf_counter_schema() {
        let hir = make_ctx_path_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("f_path")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("struct-leaf count should lower");

        optimize_with_ssa(&mut lowering.program.main);
        recover_optimized_type_hints(
            &lowering.program,
            Some(&probe_ctx),
            &mut lowering.type_hints,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized struct-leaf count should compile");
        assert_eq!(
            result.bytes_counter_key_schema,
            Some(CounterKeySchema::Record {
                name: Some("path".to_string()),
                fields: vec![
                    CounterKeySchemaField {
                        name: "mnt".to_string(),
                        schema: CounterKeySchema::Int {
                            size: 8,
                            signed: false,
                        },
                        offset: 0,
                    },
                    CounterKeySchemaField {
                        name: "dentry".to_string(),
                        schema: CounterKeySchema::Int {
                            size: 8,
                            signed: false,
                        },
                        offset: 8,
                    },
                ],
                total_size: 16,
            })
        );
    }

    #[test]
    fn test_recover_optimized_type_hints_for_direct_pointer_index_projection() {
        let hir = make_ctx_path_program(CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
                PathMember::Int {
                    val: 0,
                    span: Span::test_data(),
                    optional: false,
                },
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("direct pointer-index projection should lower");

        optimize_with_ssa(&mut lowering.program.main);
        recover_optimized_type_hints(
            &lowering.program,
            Some(&probe_ctx),
            &mut lowering.type_hints,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized direct pointer-index projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_bound_pointer_index_projection() {
        let hir = make_bound_ctx_path_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("fd"),
                ],
            },
            CellPath {
                members: vec![
                    PathMember::Int {
                        val: 0,
                        span: Span::test_data(),
                        optional: false,
                    },
                    string_member("f_inode"),
                    string_member("i_ino"),
                ],
            },
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("bound pointer-index projection should lower");

        optimize_with_ssa(&mut lowering.program.main);
        recover_optimized_type_hints(
            &lowering.program,
            Some(&probe_ctx),
            &mut lowering.type_hints,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized bound pointer-index projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_bound_numeric_get_projection() {
        let hir = make_bound_ctx_get_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("fd"),
                ],
            },
            CellPath {
                members: vec![string_member("f_inode"), string_member("i_ino")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("bound numeric get projection should lower");

        optimize_with_ssa(&mut lowering.program.main);
        recover_optimized_type_hints(
            &lowering.program,
            Some(&probe_ctx),
            &mut lowering.type_hints,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized bound numeric get projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }
}
