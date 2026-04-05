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
    EbpfProgram, ProbeContext, ProgramIntrinsic, UserFunctionSig, UserParam, UserParamKind,
    compile_mir_to_ebpf_with_hints_and_readonly_globals, hir::HirFunction,
    hir::supports_constant_value, hir_type_infer, infer_ctx_param,
    lower_hir_to_mir_with_hints_and_maps, lower_ir_to_hir, passes::optimize_with_ssa_hints,
};

/// Common Nushell commands used in eBPF closures.
const NU_CLOSURE_COMMANDS: &[&str] = &[
    "where", "each", "skip", "first", "last", "get", "select", "reject", "default", "if", "match",
];

/// Build a mapping from DeclId to command name for known commands
fn build_decl_names(engine: &EngineInterface) -> Result<HashMap<DeclId, String>, LabeledError> {
    let mut decl_names = HashMap::new();

    for cmd_name in ProgramIntrinsic::command_names() {
        if let Some(decl_id) = engine.find_decl(cmd_name).map_err(|e| {
            LabeledError::new("Failed to look up command").with_label(
                format!("Could not find '{}': {}", cmd_name, e),
                Span::unknown(),
            )
        })? {
            decl_names.insert(decl_id, cmd_name.to_string());
        }
    }

    for &cmd_name in NU_CLOSURE_COMMANDS {
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

fn lower_capture_literals(
    closure: &Spanned<Closure>,
) -> Result<Vec<(nu_protocol::VarId, Value)>, LabeledError> {
    let mut captures = Vec::with_capacity(closure.item.captures.len());
    for (var_id, value) in &closure.item.captures {
        if !supports_constant_value(value) {
            return Err(LabeledError::new("Unsupported captured value in eBPF closure")
                .with_label(
                    format!(
                        "captured variable {} has unsupported type {}; supported captured constants are int, bool, string, binary, glob, filesize, duration, nothing, top-level numeric scalar lists, and recursively constant records",
                        var_id.get(),
                        value.get_type()
                    ),
                    closure.span,
                )
                .with_help(
                    "Bind the value to a supported scalar/string constant before attaching, or inline it directly in the closure",
                ));
        }
        captures.push((*var_id, value.clone()));
    }
    Ok(captures)
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

#[derive(Clone)]
pub struct EbpfAttach;

impl PluginCommand for EbpfAttach {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf attach"
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel hook such as a probe, tracepoint, userspace function, or packet hook."
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
  - xdp
  - tc

Context parameter syntax (recommended):
  The closure can take a context parameter to access program context information:

  Universal tracing fields (all tracing attach types):
    {|ctx| $ctx.pid }     - Get process ID (thread ID)
    {|ctx| $ctx.tgid }    - Get thread group ID (process ID)
    {|ctx| $ctx.uid }     - Get user ID
    {|ctx| $ctx.gid }     - Get group ID
    {|ctx| $ctx.comm }    - Get process command name (first 16 bytes)
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds

  Packet-context fields:
    {|ctx| $ctx.cpu }     - Get current CPU ID
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds
    {|ctx| $ctx.packet_len } - Get packet length from xdp_md or __sk_buff
    {|ctx| $ctx.data }    - Get packet data pointer
    {|ctx| $ctx.data_end } - Get packet end pointer
    {|ctx| $ctx.ingress_ifindex } - Get ingress interface index
    {|ctx| ($ctx.data | get 0) } - Read the first packet byte with an auto-generated data_end guard
    {|ctx| $ctx.data.u16be.6 } - Read a big-endian 16-bit packet scalar (here: bytes 12..13)
    {|ctx| $ctx.data.eth.ethertype } - Read the Ethernet ethertype through a typed packet header view
    {|ctx| $ctx.data.eth.payload.ipv4.protocol } - Step past Ethernet or a single VLAN tag, then parse IPv4
    {|ctx| $ctx.data.eth.payload.ipv4.payload.tcp.payload.0 } - Step through variable IPv4/TCP headers and read the first TCP payload byte
    XDP-only extras:
    {|ctx| $ctx.ifindex } - Get ingress interface index
    {|ctx| $ctx.rx_queue_index } - Get RX queue index
    {|ctx| $ctx.egress_ifindex } - Get egress interface index
    Note: XDP closures currently need to return an explicit numeric action code
    such as `2` (XDP_PASS). TC closures currently need to return an explicit
    numeric classifier action code such as `0` (TC_ACT_OK). Packet reads currently support scalar byte access
    through `get`/indexing, direct `u16be`/`u32be` cell-path scalar loads,
    and typed header views `eth`, `ipv4`, `udp`, and `tcp`. Those views also
    support `payload` stepping: `eth.payload` skips Ethernet and a single
    VLAN tag when present, `ipv4.payload` uses the runtime IHL, and
    `tcp.payload` uses the runtime data offset. IPv4/TCP options are skipped
    correctly by those payload steps, but deeper option parsing and stacked
    VLAN tags are still not modeled.

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
    kernel/user pointer traversal through a register value, and also supports
    stack-backed fixed arrays such as `let idx = ($ctx.pid mod 2);
    ($ctx.arg0.comm | get $idx)`. Pointer-valued examples include
    `let idx = 0; let fd = ($ctx.arg0.fdt.fd | get $idx); $fd.f_inode.i_ino`.
    Bounded ascending `for` loops over static integer ranges now lower to
    verifier-safe loops, so `for i in 0..0 { ... get $i ... }` works.
    Bounded arithmetic on those indices, such as
    `let j = (($i + 1) mod 2)`, is preserved too. The same range tracking
    now works for typed unsigned runtime fields such as
    `let idx = ($ctx.arg0.fdt.max_fds mod 2)`. Branch-sensitive narrowing
    also works for both bound and repeated direct paths, for example
    `let max = $ctx.arg0.fdt.max_fds; if $max > 0 { let idx = ($max - 1);
    ... }` or `if $ctx.arg0.fdt.max_fds > 0 { let idx =
    ($ctx.arg0.fdt.max_fds - 1); ... }`. Descending ranges are still
    rejected. Typed BTF bitfields are also projected through those same
    paths, including after numeric `get`, for example `let idx =
    ($ctx.pid mod 2); let clamp = ($ctx.arg0.uclamp_req | get $idx);
    $clamp.value`.
    Terminal array leaves and unsupported aggregate leaves are exposed as
    stack-backed byte buffers. Representable terminal struct leaves keep their
    field layouts, including BTF bitfield members, for count/counter decoding,
    and single-value emit can now stream those struct leaves as records.
    Nested array/record fields inside emitted values also decode recursively
    when the compiler can preserve their layouts. emit still preserves
    unsupported aggregate layouts as binary payloads, and count can use them
    as byte-buffer keys. ebpf counters decodes those keys using any schema the
    compiler still has: arrays and typed structs can surface as strings,
    lists, or records; opaque aggregate layouts still display as binary. Plain
    trampoline ctx.argN and ctx.retval loads also preserve their typed pointer
    or aggregate layouts
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
  global-get        - Load a named compiler-managed program global
  global-set        - Store the pipeline input into a named compiler-managed program global

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

    let captures = lower_capture_literals(&closure)?;

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
    let state = get_state();
    let external_map_value_types = pin_group
        .as_deref()
        .map(|group| {
            state
                .pinned_generic_map_value_types(group)
                .map_err(|e| match e {
                    LoadError::LockPoisoned => LabeledError::new("Failed to attach eBPF probe")
                        .with_label("loader state lock poisoned", call.head),
                    other => LabeledError::new("Failed to attach eBPF probe")
                        .with_label(other.to_string(), call.head),
                })
        })
        .transpose()?;

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
    let lower_result = lower_hir_to_mir_with_hints_and_maps(
        &hir_program,
        Some(&probe_context),
        &decl_names,
        Some(&hir_types),
        external_map_value_types.as_ref(),
        &user_functions,
        &user_signatures,
    )
    .map_err(|e| {
        LabeledError::new("eBPF compilation failed")
            .with_label(e.to_string(), call.head)
            .with_help("The closure may use unsupported operations")
    })?;
    let crate::compiler::MirLoweringResult {
        program: mut mir_program,
        mut type_hints,
        generic_map_value_types,
        readonly_globals,
        data_globals,
        bss_globals,
    } = lower_result;

    // Run SSA-based optimizations
    optimize_with_ssa_hints(
        &mut mir_program.main,
        Some(&probe_context),
        &mut type_hints.main,
        &type_hints.main_stack_slots,
        &type_hints.generic_map_value_types,
    );
    if type_hints.subfunctions.len() < mir_program.subfunctions.len() {
        type_hints
            .subfunctions
            .resize_with(mir_program.subfunctions.len(), HashMap::new);
    }
    if type_hints.subfunction_stack_slots.len() < mir_program.subfunctions.len() {
        type_hints
            .subfunction_stack_slots
            .resize_with(mir_program.subfunctions.len(), HashMap::new);
    }
    for (subfn, subfn_hints, subfn_stack_slots) in mir_program
        .subfunctions
        .iter_mut()
        .zip(type_hints.subfunctions.iter_mut())
        .zip(type_hints.subfunction_stack_slots.iter())
        .map(|((subfn, subfn_hints), subfn_stack_slots)| (subfn, subfn_hints, subfn_stack_slots))
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            subfn_hints,
            subfn_stack_slots,
            &type_hints.generic_map_value_types,
        );
    }

    // Compile MIR to eBPF
    let compile_result = compile_mir_to_ebpf_with_hints_and_readonly_globals(
        &mir_program,
        Some(&probe_context),
        Some(&type_hints),
        readonly_globals,
    )
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
        generic_map_value_types,
    )
    .with_readonly_globals(compile_result.readonly_globals)
    .with_data_globals(data_globals)
    .with_bss_globals(bss_globals);

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

    use crate::compiler::hir::{
        HirBlock, HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram, HirStmt,
        HirTerminator,
    };
    use crate::compiler::hir_to_mir::{
        lower_hir_to_mir_with_hints, lower_hir_to_mir_with_hints_and_maps,
    };
    use crate::compiler::mir::{AddressSpace, MapKind, MapRef, StructField};
    use crate::compiler::passes::optimize_with_ssa_hints;
    use crate::compiler::{
        CounterKeySchema, CounterKeySchemaField, EbpfProgramType, MirType, ProbeContext,
        compile_mir_to_ebpf_with_hints,
    };
    use nu_protocol::DeclId;
    use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember};
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

    fn make_map_put_get_projection_program(
        map_put_decl: DeclId,
        map_get_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("arg0"), string_member("f_path")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(5),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(6),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(6),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("dentry"), string_member("d_flags")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::Call {
                            decl_id: count_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 21],
            ast: vec![None; 21],
            comments: vec![],
            register_count: 7,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_map_get_whole_value_program(map_get_decl: DeclId, terminal_decl: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::Call {
                            decl_id: terminal_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 10],
            ast: vec![None; 10],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_map_get_record_emit_program(map_get_decl: DeclId, emit_decl: DeclId) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadLiteral {
                            dst: RegId::new(0),
                            lit: HirLiteral::Record { capacity: 1 },
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::String(b"path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(2),
                            var_id: lookup_var,
                        },
                        HirStmt::RecordInsert {
                            src_dst: RegId::new(0),
                            key: RegId::new(1),
                            val: RegId::new(2),
                        },
                        HirStmt::Call {
                            decl_id: emit_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    }],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 16],
            ast: vec![None; 16],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_identity_user_function() -> HirFunction {
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(10),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 2],
            ast: vec![None; 2],
            comments: vec![],
            register_count: 1,
            file_count: 0,
        }
    }

    fn make_project_inode_flags_user_function() -> HirFunction {
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: VarId::new(10),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("f_inode"), string_member("i_flags")],
                        })),
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
        }
    }

    fn make_map_get_user_function_emit_program(
        map_get_decl: DeclId,
        user_decl: DeclId,
        emit_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(3),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(3))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(4),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(2),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(1),
                            var_id: lookup_var,
                        },
                        HirStmt::Call {
                            decl_id: user_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(1)],
                                ..Default::default()
                            },
                        },
                        HirStmt::Call {
                            decl_id: emit_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    }],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 14],
            ast: vec![None; 14],
            comments: vec![],
            register_count: 5,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_trampoline_user_function_count_program(
        user_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
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
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("arg0")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id: user_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            ..Default::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: count_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 6],
            ast: vec![None; 6],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn cached_path_struct_schema() -> HashMap<MapRef, MirType> {
        HashMap::from([(
            MapRef {
                name: "cached_path".to_string(),
                kind: MapKind::Hash,
            },
            MirType::Struct {
                name: Some("path".to_string()),
                kernel_btf_type_id: None,
                fields: vec![
                    StructField {
                        name: "mnt".to_string(),
                        ty: MirType::U64,
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    },
                    StructField {
                        name: "dentry".to_string(),
                        ty: MirType::Ptr {
                            pointee: Box::new(MirType::Struct {
                                name: Some("dentry".to_string()),
                                kernel_btf_type_id: None,
                                fields: vec![StructField {
                                    name: "d_flags".to_string(),
                                    ty: MirType::U32,
                                    offset: 0,
                                    synthetic: false,
                                    bitfield: None,
                                }],
                            }),
                            address_space: AddressSpace::Kernel,
                        },
                        offset: 8,
                        synthetic: false,
                        bitfield: None,
                    },
                ],
            },
        )])
    }

    fn make_map_copy_projection_program(
        map_put_decl: DeclId,
        map_get_decl: DeclId,
        count_decl: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let lookup_var = VarId::new(1);
        let copied_var = VarId::new(2);
        let func = HirFunction {
            blocks: vec![
                HirBlock {
                    id: HirBlockId(0),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("arg0"), string_member("f_path")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(2),
                            lit: HirLiteral::String(b"cached_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(4),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("pid")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(5),
                            lit: HirLiteral::String(b"hash".to_vec()),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(2)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: lookup_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(6),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(6),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(1),
                        if_false: HirBlockId(3),
                    },
                },
                HirBlock {
                    id: HirBlockId(1),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: lookup_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(7),
                            lit: HirLiteral::String(b"copied_path".to_vec()),
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(3),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(3),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_put_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(7), RegId::new(3)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: ctx_var,
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(4),
                        },
                        HirStmt::Call {
                            decl_id: map_get_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs {
                                positional: vec![RegId::new(7)],
                                named: vec![(b"kind".to_vec(), RegId::new(5))],
                                ..Default::default()
                            },
                        },
                        HirStmt::StoreVariable {
                            var_id: copied_var,
                            src: RegId::new(0),
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(8),
                            lit: HirLiteral::Int(0),
                        },
                        HirStmt::BinaryOp {
                            lhs_dst: RegId::new(0),
                            op: Operator::Comparison(Comparison::NotEqual),
                            rhs: RegId::new(8),
                        },
                    ],
                    terminator: HirTerminator::BranchIf {
                        cond: RegId::new(0),
                        if_true: HirBlockId(2),
                        if_false: HirBlockId(3),
                    },
                },
                HirBlock {
                    id: HirBlockId(2),
                    stmts: vec![
                        HirStmt::LoadVariable {
                            dst: RegId::new(0),
                            var_id: copied_var,
                        },
                        HirStmt::LoadLiteral {
                            dst: RegId::new(1),
                            lit: HirLiteral::CellPath(Box::new(CellPath {
                                members: vec![string_member("dentry"), string_member("d_flags")],
                            })),
                        },
                        HirStmt::FollowCellPath {
                            src_dst: RegId::new(0),
                            path: RegId::new(1),
                        },
                        HirStmt::Call {
                            decl_id: count_decl,
                            src_dst: RegId::new(0),
                            args: HirCallArgs::default(),
                        },
                    ],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
                HirBlock {
                    id: HirBlockId(3),
                    stmts: vec![],
                    terminator: HirTerminator::Return { src: RegId::new(0) },
                },
            ],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 30],
            ast: vec![None; 30],
            comments: vec![],
            register_count: 9,
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

    fn make_bound_ctx_runtime_get_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let idx_var = VarId::new(2);
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
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
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
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 13],
            ast: vec![None; 13],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_runtime_get_then_call_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let idx_var = VarId::new(1);
        let value_var = VarId::new(2);
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
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
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
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id: DeclId::new(42),
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: value_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: value_var,
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
            spans: vec![Span::test_data(); 14],
            ast: vec![None; 14],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_bound_ctx_runtime_get_path_program(
        binding: CellPath,
        idx_binding: CellPath,
        modulus: i64,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let bound_var = VarId::new(1);
        let idx_var = VarId::new(2);
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
                        lit: HirLiteral::CellPath(Box::new(idx_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(modulus),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Modulo),
                        rhs: RegId::new(2),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
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
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: idx_var,
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
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 15],
            ast: vec![None; 15],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        };
        HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
    }

    fn make_branch_refined_bound_ctx_get_program(
        scalar_binding: CellPath,
        pointer_binding: CellPath,
        access: CellPath,
        decl_id: DeclId,
    ) -> HirProgram {
        let ctx_var = VarId::new(0);
        let scalar_var = VarId::new(1);
        let idx_var = VarId::new(2);
        let blocks = vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(scalar_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: scalar_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: scalar_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::GreaterThan),
                        rhs: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: scalar_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Subtract),
                        rhs: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: idx_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(pointer_binding)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(2),
                        path: RegId::new(3),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: idx_var,
                    },
                    HirStmt::Call {
                        decl_id,
                        src_dst: RegId::new(2),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::CellPath(Box::new(access)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(2),
                        path: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(2) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ];
        let func = HirFunction {
            blocks,
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 19],
            ast: vec![None; 19],
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

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
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

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
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
                        bitfield: None,
                    },
                    CounterKeySchemaField {
                        name: "dentry".to_string(),
                        schema: CounterKeySchema::Int {
                            size: 8,
                            signed: false,
                        },
                        offset: 8,
                        bitfield: None,
                    },
                ],
                total_size: 16,
            })
        );
    }

    #[test]
    fn test_compile_optimized_typed_map_get_projection() {
        let hir =
            make_map_put_get_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "map-put".to_string());
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("typed map put/get projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed map get projection should compile");

        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
        assert!(
            result.maps.iter().any(|map| map.name == "cached_path"),
            "expected generic map definition for cached_path"
        );
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_whole_struct_count() {
        let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("whole-value typed map-get count should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized whole-value typed map-get count should compile");
        let schema = result
            .bytes_counter_key_schema
            .expect("whole-value count should preserve a record key schema");
        assert!(matches!(
            schema,
            CounterKeySchema::Record { ref fields, .. }
                if fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[1].name == "dentry"
        ));
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_whole_struct_emit() {
        let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("whole-value typed map-get emit should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized whole-value typed map-get emit should compile");
        let schema = result
            .event_schema
            .expect("whole-value emit should preserve a structured event schema");
        assert!(
            schema
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .eq(["mnt", "dentry"].into_iter()),
            "whole-value emit should preserve top-level record fields"
        );
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_record_emit() {
        let hir = make_map_get_record_emit_program(DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        let external_schema = cached_path_struct_schema();

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("record emit around typed map-get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized record emit around typed map-get should compile");
        let schema = result
            .event_schema
            .expect("record emit should preserve a structured event schema");
        assert!(matches!(
            schema.fields.as_slice(),
            [crate::compiler::SchemaField {
                name,
                field_type: crate::compiler::BpfFieldType::Bytes(16),
                value_schema: Some(CounterKeySchema::Record { fields, .. }),
                ..
            }] if name == "path"
                && fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
        ));
    }

    #[test]
    fn test_compile_optimized_external_typed_map_get_user_function_emit() {
        let hir = make_map_get_user_function_emit_program(
            DeclId::new(43),
            DeclId::new(90),
            DeclId::new(44),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "emit".to_string());
        decl_names.insert(DeclId::new(90), "project-entry".to_string());
        let external_schema = cached_path_struct_schema();
        let user_functions = HashMap::from([(DeclId::new(90), make_identity_user_function())]);

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            Some(&external_schema),
            &user_functions,
            &HashMap::new(),
        )
        .expect("typed map-get through user function should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        for ((subfn, hints), stack_slots) in lowering
            .program
            .subfunctions
            .iter_mut()
            .zip(lowering.type_hints.subfunctions.iter_mut())
            .zip(lowering.type_hints.subfunction_stack_slots.iter())
        {
            optimize_with_ssa_hints(
                subfn,
                Some(&probe_ctx),
                hints,
                stack_slots,
                &lowering.type_hints.generic_map_value_types,
            );
        }

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed map-get through user function should compile");
        let schema = result
            .event_schema
            .expect("user-function emit should preserve a structured event schema");
        assert!(
            schema
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .eq(["mnt", "dentry"].into_iter()),
            "user-function emit should preserve top-level record fields, got {:?}",
            schema
        );
    }

    #[test]
    fn test_compile_optimized_typed_trampoline_user_function_projection() {
        let hir = make_trampoline_user_function_count_program(DeclId::new(90), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(44), "count".to_string());
        decl_names.insert(DeclId::new(90), "project-inode-flags".to_string());
        let user_functions =
            HashMap::from([(DeclId::new(90), make_project_inode_flags_user_function())]);

        let mut lowering = lower_hir_to_mir_with_hints_and_maps(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            None,
            &user_functions,
            &HashMap::new(),
        )
        .expect("typed trampoline arg through user function should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
        for ((subfn, hints), stack_slots) in lowering
            .program
            .subfunctions
            .iter_mut()
            .zip(lowering.type_hints.subfunctions.iter_mut())
            .zip(lowering.type_hints.subfunction_stack_slots.iter())
        {
            optimize_with_ssa_hints(
                subfn,
                Some(&probe_ctx),
                hints,
                stack_slots,
                &lowering.type_hints.generic_map_value_types,
            );
        }

        compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized typed trampoline projection through user function should compile");
    }

    #[test]
    fn test_compile_optimized_map_to_map_copy_projection() {
        let hir =
            make_map_copy_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "map-put".to_string());
        decl_names.insert(DeclId::new(43), "map-get".to_string());
        decl_names.insert(DeclId::new(44), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("map-to-map copy projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized map-to-map copy projection should compile");

        assert!(
            result.maps.iter().any(|map| map.name == "copied_path"),
            "expected generic map definition for copied_path"
        );
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
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

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
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

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
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

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized bound numeric get projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_branch_refined_bound_numeric_get_projection() {
        let hir = make_branch_refined_bound_ctx_get_program(
            CellPath {
                members: vec![
                    string_member("arg0"),
                    string_member("fdt"),
                    string_member("max_fds"),
                ],
            },
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
        .expect("branch-refined bound numeric get projection should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized branch-refined bound numeric get projection should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_array_numeric_get() {
        let hir = make_bound_ctx_runtime_get_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("comm")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
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
        .expect("stack-backed array numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed array numeric get should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_projection_after_numeric_get() {
        let hir = make_bound_ctx_runtime_get_path_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            CellPath {
                members: vec![string_member("bucket_id")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
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
        .expect("stack-backed bitfield projection after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield projection after numeric get should compile");
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_count_after_numeric_get()
    {
        let hir = make_bound_ctx_runtime_get_then_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(43),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());
        decl_names.insert(DeclId::new(43), "count".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed bitfield struct count after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield struct count should compile");
        assert!(
            matches!(
                result.bytes_counter_key_schema,
                Some(CounterKeySchema::Record { .. })
            ),
            "bitfield struct count should preserve a record schema"
        );
    }

    #[test]
    fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_emit_after_numeric_get() {
        let hir = make_bound_ctx_runtime_get_then_call_program(
            CellPath {
                members: vec![string_member("arg0"), string_member("uclamp_req")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            2,
            DeclId::new(43),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
        let mut decl_names = HashMap::new();
        decl_names.insert(DeclId::new(42), "get".to_string());
        decl_names.insert(DeclId::new(43), "emit".to_string());

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("stack-backed bitfield struct emit after numeric get should lower");

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .expect("optimized stack-backed bitfield struct emit should compile");
        let schema = result
            .event_schema
            .expect("single-value emit should preserve a schema");
        assert!(
            schema.fields.iter().map(|field| field.name.as_str()).eq([
                "value",
                "bucket_id",
                "active",
                "user_defined"
            ]
            .into_iter()),
            "bitfield struct emit should preserve top-level record fields"
        );
        assert!(
            schema.fields[0].bitfield.is_some() && schema.fields[1].bitfield.is_some(),
            "bitfield struct emit should preserve bitfield metadata"
        );
    }
}
