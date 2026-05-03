//! Helper commands for eBPF closures
//!
//! These commands are used inside eBPF closures to perform actions:
//! - emit: Send a value to userspace via ring buffer
//! - count: Increment a counter by key
//! - histogram: Add value to log2 histogram
//! - start-timer: Start latency measurement
//! - stop-timer: Stop timer and return elapsed nanoseconds
//! - read-str: Read string from userspace memory pointer
//! - read-kernel-str: Read string from kernel memory pointer
//! - helper-call: Escape hatch for invoking a modeled BPF helper by name
//! - kfunc-call: Escape hatch for invoking a typed kernel kfunc by name
//! - tail-call: Transfer control to a program in a named prog-array map
//! - global-define / global-get / global-set: Named compiler-managed per-program globals
//! - map-define: Declare named generic map key/value schemas and capacity
//! - map-get / map-put / map-delete / map-push / map-peek / map-pop / map-contains:
//!   Generic BPF map operations

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value,
};

use crate::EbpfPlugin;

// =============================================================================
// Output commands
// =============================================================================

#[derive(Clone)]
pub struct Emit;

impl PluginCommand for Emit {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "emit"
    }

    fn description(&self) -> &str {
        "Emit a value to the eBPF perf buffer for streaming to userspace."
    }

    fn extra_description(&self) -> &str {
        r#"Supports both single values (integers) and structured records.
When given a record, all fields are emitted as a single structured event.
Representable typed struct values from trampoline projections can also stream
as structured events, including preserved bitfield members and nested
arrays/records when the compiler can preserve their layouts. Typed `map-get`
values keep that same nested layout when inserted into emitted records.

Examples:
  {|ctx| $ctx.pid | emit }
  {|ctx| { pid: $ctx.pid, uid: $ctx.uid } | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("emit")
            .input_output_types(vec![(Type::Int, Type::Int), (Type::Any, Type::Any)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.pid | emit }",
            description: "Emit the PID on each sys_read call",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        // Stub for non-eBPF execution (e.g., help display)
        let value = input.into_value(call.head)?;
        Ok(PipelineData::Value(value, None))
    }
}

#[derive(Clone)]
pub struct ReadStr;

impl PluginCommand for ReadStr {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "read-str"
    }

    fn description(&self) -> &str {
        "Read a string from a memory pointer and emit it (max 128 bytes)."
    }

    fn extra_description(&self) -> &str {
        r#"Reads a null-terminated string from the given pointer.
By default, reads from userspace memory which covers most use cases:
- Syscall arguments (filenames, paths, buffers)
- Uprobe function arguments"#
    }

    fn signature(&self) -> Signature {
        Signature::build("read-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .named(
                "max-len",
                SyntaxShape::Int,
                "Maximum bytes to read (default 128, rounded up to 8 bytes, minimum 16).",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:do_sys_openat2' {|ctx| $ctx.arg1 | read-str }",
            description: "Read filename from syscall argument",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(
            Value::string("<string>", call.head),
            None,
        ))
    }
}

#[derive(Clone)]
pub struct ReadKernelStr;

impl PluginCommand for ReadKernelStr {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "read-kernel-str"
    }

    fn description(&self) -> &str {
        "Read a string from kernel memory pointer and emit it (max 128 bytes)."
    }

    fn extra_description(&self) -> &str {
        r#"Reads a null-terminated string from kernel memory. This is for
advanced use cases where you need to read from internal kernel
data structures. For most cases, use read-str instead."#
    }

    fn signature(&self) -> Signature {
        Signature::build("read-kernel-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .named(
                "max-len",
                SyntaxShape::Int,
                "Maximum bytes to read (default 128, rounded up to 8 bytes, minimum 16).",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:vfs_read' {|ctx| $ctx.arg0 | read-kernel-str }",
            description: "Read from kernel buffer pointer",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(
            Value::string("<kernel string>", call.head),
            None,
        ))
    }
}

#[derive(Clone)]
pub struct HelperCall;

impl PluginCommand for HelperCall {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "helper-call"
    }

    fn description(&self) -> &str {
        "Escape hatch: call a modeled BPF helper by name from an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Advanced helper for invoking modeled BPF helpers by name.
The first positional argument must be a literal helper name such as
`bpf_get_current_pid_tgid` or `bpf_get_socket_cookie`. If the helper takes
arguments, pipeline input becomes arg0 when present.

Use `--kind` only for map-family helpers whose map type is otherwise
ambiguous, for example `bpf_for_each_map_elem`.

Prefer a first-class command or ordinary Nushell syntax when the operation is
already modeled directly."#
    }

    fn signature(&self) -> Signature {
        Signature::build("helper-call")
            .input_output_types(vec![(Type::Any, Type::Any), (Type::Nothing, Type::Any)])
            .required("name", SyntaxShape::String, "BPF helper symbol name")
            .rest(
                "args",
                SyntaxShape::Any,
                "Additional helper arguments (up to 5 total with pipeline input)",
            )
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind for helper calls whose map family is ambiguous",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'kprobe:ksys_read' {|| helper-call bpf_get_current_pid_tgid | count }",
            description: "Call a zero-arg BPF helper and feed its result into a counter",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct KfuncCall;

impl PluginCommand for KfuncCall {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "kfunc-call"
    }

    fn description(&self) -> &str {
        "Escape hatch: call a kernel kfunc by name from an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Advanced helper for invoking BTF-described kernel kfuncs.
The first positional argument must be a literal kfunc name.
If omitted, --btf-id is resolved automatically from kernel BTF.

Prefer a first-class command or ordinary Nushell syntax when the operation is
already modeled directly."#
    }

    fn signature(&self) -> Signature {
        Signature::build("kfunc-call")
            .input_output_types(vec![(Type::Any, Type::Any), (Type::Nothing, Type::Any)])
            .required("name", SyntaxShape::String, "Kernel kfunc symbol name")
            .rest(
                "args",
                SyntaxShape::Any,
                "Additional kfunc arguments (up to 5 total with pipeline input)",
            )
            .named(
                "btf-id",
                SyntaxShape::Int,
                "Optional explicit kernel BTF function ID",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:do_exit' {|ctx| $ctx.arg0 | kfunc-call bpf_task_release }",
            description: "Call a typed kfunc with pipeline input as arg0",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        // Stub for non-eBPF execution (e.g., help display).
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct TailCall;

impl PluginCommand for TailCall {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "tail-call"
    }

    fn description(&self) -> &str {
        "Tail call into a program stored in a named BPF prog-array map."
    }

    fn extra_description(&self) -> &str {
        r#"Transfers control to the program stored at INDEX in the named prog-array
map. On success the current program does not return. If the tail call misses or
exceeds the kernel tail-call limit, the compiler emits a safe fallback return of
0. Use pipeline input as the index, or pass the index as the second positional
argument.

Example:
  $ctx.pid | tail-call dispatch_targets"#
    }

    fn signature(&self) -> Signature {
        Signature::build("tail-call")
            .input_output_types(vec![
                (Type::Int, Type::Nothing),
                (Type::Nothing, Type::Nothing),
            ])
            .required("name", SyntaxShape::String, "Program-array map name")
            .optional(
                "index",
                SyntaxShape::Any,
                "Optional target index; otherwise uses pipeline input",
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| 0 | tail-call dispatch_targets }",
            description: "Tail call to program-array slot 0",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::nothing(call.head), None))
    }
}

#[derive(Clone)]
pub struct MapDefine;

impl PluginCommand for MapDefine {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-define"
    }

    fn description(&self) -> &str {
        "Declare key/value layouts and capacity for a named generic BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Declares named map key/value schemas and optional capacity for later map operations in the same
program and for later pinned peers attached with the same `--pin` group. This
is a compile-time declaration: it does not perform a runtime map operation. It
is useful when a map key or value layout should be fixed before ordinary map
operations, including verifier-sensitive value fields such as `bpf_timer`.

Supported key type specs match `global-define --type` fixed-layout specs.
Supported value type specs use the same fixed-layout specs and also allow
`bpf_timer`, `bpf_spin_lock`, `bpf_wq`, `bpf_refcount`, `kptr:TYPE`,
`bpf_list_head:TYPE:FIELD`, and `bpf_rb_root:TYPE:FIELD` inside map-value
records.
Source-level `record{...}` specs use natural field alignment and aligned array
stride; padding is zero-filled by typed initializers and hidden from emitted
BTF members.
Verifier-managed fields are checked against kernel layout rules: `bpf_spin_lock`
must be a single top-level 4-byte-aligned field in a hash or array map, and
`bpf_timer` must be a single 8-byte-aligned field in a hash, array, or lru-hash
map. `bpf_wq` and `bpf_refcount` are also top-level verifier-managed fields
for hash, array, or lru-hash maps. `kptr:TYPE` declares an 8-byte-aligned
top-level map-value kptr slot for hash, array, or lru-hash maps and emits the
required `__kptr` BTF type tag.
Graph roots use `bpf_list_head:TYPE:FIELD` or `bpf_rb_root:TYPE:FIELD`, where
`TYPE` is the contained object type name and `FIELD` is its list/rbtree node
field; the compiler emits the matching `contains:TYPE:FIELD` BTF declaration
tag. Bare `bpf_list_head`, `bpf_rb_root`, `bpf_list_node`, and `bpf_rb_node`
tokens are intentionally still rejected.
Use `--max-entries` to set a positive map capacity for value-carrying map
families that expose a max_entries resource.

Example:
  map-define timers --kind array --key-type u32 --value-type 'record{timer:bpf_timer,cookie:u64}' --max-entries 1024
  map-define graph_items --kind hash --value-type 'record{root:bpf_list_head:node_data:node,cookie:u64}'
  let entry = (0 | map-get timers --kind array)
  if $entry != 0 { helper-call "bpf_timer_start" $entry.timer 1000 0 }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-define")
            .input_output_types(vec![(Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Map name")
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: hash, array, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash, queue, stack, bloom-filter, sk-storage, task-storage, inode-storage, or cgrp-storage (default hash)",
                None,
            )
            .named(
                "key-type",
                SyntaxShape::String,
                "Optional map key type spec using fixed-layout scalar/bytes/string/list/array/record forms; array-like maps require u32 keys",
                None,
            )
            .named(
                "value-type",
                SyntaxShape::String,
                "Map value type spec using fixed-layout scalar/bytes/string/list/array/record forms; map value records may include bpf_timer, bpf_spin_lock, bpf_wq, bpf_refcount, and kptr:TYPE",
                None,
            )
            .named(
                "max-entries",
                SyntaxShape::Int,
                "Optional positive map capacity; not supported for local-storage map kinds",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'raw_tracepoint:sys_enter' {|ctx| map-define timers --kind array --key-type u32 --value-type 'record{timer:bpf_timer,cookie:u64}' --max-entries 1024; 0 }",
            description: "Declare an array map key, capacity, and a value record containing a bpf_timer field",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapGet;

impl PluginCommand for MapGet {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-get"
    }

    fn description(&self) -> &str {
        "Look up a value in a named generic BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Looks up a key in a named generic map and returns the map-value pointer.
Use pipeline input as the key, or pass an explicit key as the second positional
argument. Aggregate values established by an earlier typed `map-put` in the same
closure can be projected by field after lookup, or used directly with `emit`
and `count` as whole typed values. That typed layout also survives record
construction, so `if $entry != 0 { { path: $entry } | emit }` preserves `path`
as a nested record. The same null-checked layout also survives simple
user-defined function boundaries, so `def project-entry [entry] { $entry }`
can feed `if $entry != 0 { (project-entry $entry) | emit }`. Call-site typed
arguments now also specialize simple user-defined functions, so callees can
project typed fields directly from their parameters. The same typed schema also
carries across active programs that share a pinned map group. The result is a
maybe-null pointer, so guard it before dereferencing.

For `--kind lpm-trie`, the key bytes must already use the kernel LPM layout:
leading `u32` prefix length followed by the trie payload bytes.

For local-storage maps, use `--kind sk-storage`, `--kind task-storage`,
`--kind inode-storage`, or `--kind cgrp-storage`. The pipeline input or second
positional argument is the owning kernel object pointer. `--init VALUE` passes a
typed initial value and defaults `--flags` to `1`
(`BPF_LOCAL_STORAGE_GET_F_CREATE`); omit `--init` for lookup-only behavior.

Example:
  let entry = ($ctx.pid | map-get seen_paths --kind hash)
  if $entry != 0 { $entry | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-get")
            .input_output_types(vec![(Type::Any, Type::Any), (Type::Nothing, Type::Any)])
            .required("name", SyntaxShape::String, "Map name")
            .optional(
                "key",
                SyntaxShape::Any,
                "Optional explicit key; otherwise uses pipeline input",
            )
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: hash, array, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash, sk-storage, task-storage, inode-storage, or cgrp-storage (default hash)",
                None,
            )
            .named(
                "init",
                SyntaxShape::Any,
                "Local-storage initial value; implies create flags unless --flags is provided",
                None,
            )
            .named(
                "flags",
                SyntaxShape::Int,
                "Raw local-storage get flags (default 0, or 1 with --init)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach 'fentry:security_file_open' {|ctx| $ctx.pid | map-get seen_paths --kind hash }",
                description: "Look up the current PID in a named hash map",
                result: None,
            },
            Example {
                example: "ebpf attach 'fentry:security_file_open' {|ctx| $ctx.task | map-get task_state --kind task-storage --init 0 }",
                description: "Get or create task-local storage for the current task",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let value = input.into_value(call.head)?;
        Ok(PipelineData::Value(value, None))
    }
}

#[derive(Clone)]
pub struct GlobalDefine;

impl PluginCommand for GlobalDefine {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "global-define"
    }

    fn description(&self) -> &str {
        "Declare and optionally initialize a named compiler-managed program global."
    }

    fn extra_description(&self) -> &str {
        r#"Declares a named per-program global. By default the input must be a
compile-time constant, which establishes both the fixed layout and the initial
contents in `.data`/`.bss` without performing a runtime store on each event.
With `--zero`, the input is used only for layout inference and the resulting
global is zero-initialized in `.bss`. With `--type`, no input is needed to
declare a zero-initialized global, but a compile-time constant input may also
be provided when you want explicit layout plus explicit initial contents.
Source-level `record{...}` specs use natural field alignment and aligned array
stride; typed initializers zero-fill scalar fields, omitted record fields, and
layout padding.

Leading annotated `mut` bindings are the preferred small private-state path
when ordinary Nushell variable syntax is enough. Named globals remain useful
when you want an explicit shared name or a source-order-independent declaration.

Because this is declarative, later constant `global-define` calls can establish
globals used by earlier `global-get`s.

Examples:
  7 | global-define seen_pid
  $ctx.pid | global-define --zero seen_pid
  global-define --type int seen_pid
  "bash" | global-define --type string:16 seen_comm
  [80 443] | global-define --type 'array{u16:4}' seen_ports
  global-define --type 'record{pid:int,comm:bytes:16}' seen_state
  let state = (global-get seen_pid)"#
    }

    fn signature(&self) -> Signature {
        Signature::build("global-define")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .named(
                "type",
                SyntaxShape::String,
                "Declare a global from a type spec (zero-initialized with no input, or explicitly initialized from a compile-time constant input) using i8/i16/i32/int(i64)/duration/filesize/u8/u16/u32/u64/bool/bytes:N/string:N/list:int:N(list:i64:N)/array{type:N}/record{field:type,...}",
                None,
            )
            .switch(
                "zero",
                "Use the input only for layout inference and zero-initialize the global",
                None,
            )
            .required("name", SyntaxShape::String, "Global name")
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| 7 | global-define seen_pid; global-get seen_pid }",
                description: "Declare a named per-program global with a compile-time constant initializer",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | global-define --zero seen_pid; global-get seen_pid }",
                description: "Declare a zero-initialized named per-program global from a runtime layout exemplar",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type int seen_pid; global-get seen_pid }",
                description: "Declare a zero-initialized named per-program global directly from a type spec",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| 'bash' | global-define --type string:16 seen_comm; global-get seen_comm | count }",
                description: "Declare a fixed-capacity typed global with an explicit compile-time initializer",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type string:32 seen_name; global-get seen_name | count }",
                description: "Declare a zero-initialized string global with a 32-byte content cap",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| [80 443] | global-define --type 'array{u16:4}' seen_ports; global-get seen_ports | get 0 | count }",
                description: "Declare a fixed scalar array global with an explicit compile-time initializer",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type 'record{pid:int,comm:bytes:16}' seen_state; (global-get seen_state).pid | count }",
                description: "Declare a zero-initialized flat record global directly from a type spec",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct GlobalGet;

impl PluginCommand for GlobalGet {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "global-get"
    }

    fn description(&self) -> &str {
        "Load a value from a named compiler-managed program global."
    }

    fn extra_description(&self) -> &str {
        r#"Loads a named per-program global. The layout comes from a same-closure
`global-define` or from a layout-establishing `global-set`, after which later
`global-get` users can project fields or use the whole value with `emit` and
`count`. `global-define` is declarative and source-order independent; if you
skip it, `global-set` can still infer the layout on first use.

Prefer leading annotated `mut` bindings for private state when plain variable
syntax is sufficient. Use named globals when you need an explicit shared name.

Example:
  let state = (global-get seen_path)
  if $state != 0 { $state | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("global-get")
            .input_output_types(vec![(Type::Nothing, Type::Any), (Type::Any, Type::Any)])
            .required("name", SyntaxShape::String, "Global name")
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:sys_read' {|ctx| global-get seen_pid }",
            description: "Load a named per-program global",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        match input {
            PipelineData::Value(value, meta) => Ok(PipelineData::Value(value, meta)),
            _ => Ok(PipelineData::Value(Value::nothing(call.head), None)),
        }
    }
}

#[derive(Clone)]
pub struct GlobalSet;

impl PluginCommand for GlobalSet {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "global-set"
    }

    fn description(&self) -> &str {
        "Store the pipeline input into a named compiler-managed program global."
    }

    fn extra_description(&self) -> &str {
        r#"Stores the pipeline input into a named per-program global. If no
same-closure `global-define` already exists, the first `global-set` for a given
name establishes the fixed layout used by later `global-get` and `global-set`
calls. Compile-time constant first writes seed the global's initial value;
otherwise it starts zeroed.

Prefer leading annotated `mut` bindings for private state when plain variable
syntax is sufficient. Use named globals when you need an explicit shared name.

Example:
  $ctx.pid | global-set seen_pid"#
    }

    fn signature(&self) -> Signature {
        Signature::build("global-set")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Global name")
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | global-set seen_pid }",
            description: "Store a value in a named per-program global",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapPut;

impl PluginCommand for MapPut {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-put"
    }

    fn description(&self) -> &str {
        "Insert or update a value in a named BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Stores the pipeline input as the value for the given key in a named
generic map. The second positional argument is the key. Use `--flags` to pass
raw `bpf_map_update_elem` flags when needed. With `ebpf attach --pin`, the
value layout becomes available to later pinned `map-get` users in the same
group. If the pipeline input is a whole typed `map-get` value, `map-put`
stores the underlying aggregate bytes rather than the pointer wrapper.

For `--kind sockmap` or `--kind sockhash`, the pipeline input must be the
current `sock_ops` context and the key is the second positional argument. This
lowers to `bpf_sock_{map,hash}_update`.

Example:
  $ctx.arg.file.f_path | map-put seen_paths $ctx.pid --kind hash

For `--kind lpm-trie`, the key bytes must already use the kernel LPM layout:
leading `u32` prefix length followed by the trie payload bytes."#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-put")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Map name")
            .required("key", SyntaxShape::Any, "Map key")
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, lru-per-cpu-hash, sockmap, or sockhash (default hash; queue/stack use map-push instead)",
                None,
            )
            .named(
                "flags",
                SyntaxShape::Int,
                "Raw bpf_map_update_elem flags (default 0 / BPF_ANY)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach 'fentry:security_file_open' {|ctx| $ctx.arg.file.f_path | map-put seen_paths $ctx.pid --kind hash }",
                description: "Store a typed struct value in a named hash map",
                result: None,
            },
            Example {
                example: "ebpf attach 'sock_ops:/sys/fs/cgroup' {|ctx| $ctx | map-put active_sockets $ctx.remote_port --kind sockmap }",
                description: "Update a sockmap from the current sock_ops context",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapDelete;

impl PluginCommand for MapDelete {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-delete"
    }

    fn description(&self) -> &str {
        "Delete a key or local-storage entry from a named BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Deletes a key from a named generic map. Use pipeline input as the key,
or pass an explicit key as the second positional argument.

For local-storage maps, use `--kind sk-storage`, `--kind task-storage`,
`--kind inode-storage`, or `--kind cgrp-storage`. The pipeline input or second
positional argument is the owning kernel object pointer.

For `--kind lpm-trie`, the key bytes must already use the kernel LPM layout:
leading `u32` prefix length followed by the trie payload bytes.

Example:
  $ctx.pid | map-delete seen_paths --kind hash"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-delete")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Map name")
            .optional(
                "key",
                SyntaxShape::Any,
                "Optional explicit key; otherwise uses pipeline input",
            )
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: hash, lpm-trie, lru-hash, per-cpu-hash, lru-per-cpu-hash, sk-storage, task-storage, inode-storage, or cgrp-storage (default hash)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | map-delete seen_paths --kind hash }",
            description: "Delete the current PID from a named hash map",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapContains;

impl PluginCommand for MapContains {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-contains"
    }

    fn description(&self) -> &str {
        "Test whether a key/value is present in a named BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Checks whether the pipeline input or explicit key is present in a lookup-capable
generic map. Without `--kind`, the map kind defaults to `hash`; explicit lookup
map kinds include `array`, `lpm-trie`, `lru-hash`, `per-cpu-hash`,
`per-cpu-array`, and `lru-per-cpu-hash`.

With local-storage map kinds (`sk-storage`, `task-storage`, `inode-storage`,
or `cgrp-storage`), the pipeline input or explicit value is the owning kernel
object pointer. The command performs a lookup-only storage get and returns
whether storage already exists.

With `--kind bloom-filter`, the value is a bloom-filter probe value. This wraps
the kernel `bpf_map_peek_elem` membership probe and returns a boolean. Bloom
filters can have false positives but not false negatives.

With `--kind cgroup-array`, the value is a cgroup-array index. On tc_action, tc,
tcx, netkit, and lwt_* programs this wraps `bpf_skb_under_cgroup` for the
current packet; on other programs it wraps the base
`bpf_current_task_under_cgroup` helper for the current task.

Example:
  let exists = ($ctx.pid | map-contains seen_pids)
  let has_state = ($ctx.task | map-contains task_state --kind task-storage)
  let seen = ($ctx.pid | map-contains recent_pids --kind bloom-filter)
  let in_group = (map-contains tracked_cgroups 0 --kind cgroup-array)"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-contains")
            .input_output_types(vec![(Type::Any, Type::Bool), (Type::Nothing, Type::Bool)])
            .required("name", SyntaxShape::String, "Map name")
            .optional(
                "value",
                SyntaxShape::Any,
                "Optional explicit value; otherwise uses pipeline input",
            )
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind; defaults to hash",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| $ctx.pid | map-contains seen_pids }",
                description: "Check hash-map membership for the current PID",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'fentry:security_file_open' {|ctx| $ctx.task | map-contains task_state --kind task-storage }",
                description: "Check whether task-local storage exists for the current task",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| $ctx.pid | map-contains recent_pids --kind bloom-filter }",
                description: "Check bloom-filter membership for the current PID",
                result: None,
            },
            Example {
                example: "ebpf attach --dry-run 'tc:lo:ingress' {|ctx| map-contains tracked_cgroups 0 --kind cgroup-array }",
                description: "Check whether the current packet belongs to cgroup-array slot 0",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::bool(false, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapPush;

impl PluginCommand for MapPush {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-push"
    }

    fn description(&self) -> &str {
        "Push a value into a named queue, stack, or bloom-filter BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Pushes the pipeline input into a named queue, stack, or bloom-filter map.
Use `--kind queue` for FIFO behavior, `--kind stack` for LIFO behavior, or
`--kind bloom-filter` for membership insertion. Unlike `map-put`, these maps do
not take an explicit key. Queue/stack pushed value layouts become available to
later `map-peek` and `map-pop` uses in the same closure, and to pinned peers
when attached with the same `--pin` group.

Example:
  $ctx.pid | map-push recent_pids --kind queue"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-push")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Map name")
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: queue, stack, or bloom-filter (required)",
                None,
            )
            .named(
                "flags",
                SyntaxShape::Int,
                "Raw bpf_map_push_elem flags (default 0)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| $ctx.pid | map-push recent_pids --kind queue }",
            description: "Push the current PID into a named queue map",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct MapPeek;

impl PluginCommand for MapPeek {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-peek"
    }

    fn description(&self) -> &str {
        "Peek the next value from a named queue or stack BPF map without removing it."
    }

    fn extra_description(&self) -> &str {
        r#"Loads the next queue/stack value into a compiler-managed stack buffer and
returns a maybe-null pointer to that buffer. The map value layout must already
be known from an earlier typed `map-push` or from a pinned schema shared with
`ebpf attach --pin`.

Example:
  let top = (map-peek recent_pids --kind stack)
  if $top != 0 { $top | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-peek")
            .input_output_types(vec![(Type::Nothing, Type::Any)])
            .required("name", SyntaxShape::String, "Map name")
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: queue or stack (required)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| let top = (map-peek recent_pids --kind stack); if $top != 0 { $top | emit } }",
            description: "Peek the current top value from a named stack map",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::nothing(call.head), None))
    }
}

#[derive(Clone)]
pub struct MapPop;

impl PluginCommand for MapPop {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-pop"
    }

    fn description(&self) -> &str {
        "Pop the next value from a named queue or stack BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Removes the next queue/stack value, copies it into a compiler-managed
stack buffer, and returns a maybe-null pointer to that buffer. The map value
layout must already be known from an earlier typed `map-push` or from a pinned
schema shared with `ebpf attach --pin`.

Example:
  let next = (map-pop recent_pids --kind queue)
  if $next != 0 { $next | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("map-pop")
            .input_output_types(vec![(Type::Nothing, Type::Any)])
            .required("name", SyntaxShape::String, "Map name")
            .named(
                "kind",
                SyntaxShape::String,
                "Map kind: queue or stack (required)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| let next = (map-pop recent_pids --kind queue); if $next != 0 { $next | emit } }",
            description: "Pop the current front value from a named queue map",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::nothing(call.head), None))
    }
}

// =============================================================================
// Aggregation commands
// =============================================================================

#[derive(Clone)]
pub struct Count;

impl PluginCommand for Count {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "count"
    }

    fn description(&self) -> &str {
        "Count occurrences by key in an eBPF hash map."
    }

    fn extra_description(&self) -> &str {
        r#"Increments a counter for the input key. Use ebpf counters to read results.
Scalar keys display as integers, byte-array/string keys display as strings,
typed aggregate keys can decode as lists/records, and opaque aggregate keys
display as binary values.

Example:
  let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }
  sleep 5sec
  ebpf counters $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("count")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }",
            description: "Count events per PID",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let value = input.into_value(call.head)?;
        Ok(PipelineData::Value(value, None))
    }
}

#[derive(Clone)]
pub struct Histogram;

impl PluginCommand for Histogram {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "histogram"
    }

    fn description(&self) -> &str {
        "Add a value to a log2 histogram in eBPF."
    }

    fn extra_description(&self) -> &str {
        r#"Computes the log2 bucket for the input value and increments that bucket.
Use ebpf histogram to read results.

Example:
  let id = ebpf attach 'kretprobe:sys_read' {|ctx| stop-timer | histogram }
  sleep 5sec
  ebpf histogram $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("histogram")
            .input_output_types(vec![(Type::Int, Type::Int)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kretprobe:sys_read' {|ctx| stop-timer | histogram }",
            description: "Add latency to histogram",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let value = input.into_value(call.head)?;
        Ok(PipelineData::Value(value, None))
    }
}

// =============================================================================
// Timing commands
// =============================================================================

#[derive(Clone)]
pub struct StartTimer;

impl PluginCommand for StartTimer {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "start-timer"
    }

    fn description(&self) -> &str {
        "Start a timer for latency measurement. Pair with stop-timer."
    }

    fn extra_description(&self) -> &str {
        r#"Stores the current kernel timestamp keyed by thread ID.
Use in entry probes (kprobe) and call stop-timer in return probes (kretprobe).

For cross-program timing, use --pin to share the timestamp map:
  ebpf attach --pin lat 'kprobe:func' {|ctx| start-timer }
  ebpf attach --pin lat -s 'kretprobe:func' {|ctx| stop-timer | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("start-timer")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --pin lat 'kprobe:sys_read' {|ctx| start-timer }",
            description: "Start timer in entry probe",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::nothing(call.head), None))
    }
}

#[derive(Clone)]
pub struct StopTimer;

impl PluginCommand for StopTimer {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "stop-timer"
    }

    fn description(&self) -> &str {
        "Stop timer and return elapsed nanoseconds. Pair with start-timer."
    }

    fn extra_description(&self) -> &str {
        r#"Looks up the start timestamp for the current thread, computes elapsed time,
and deletes the map entry. Returns 0 if no matching start-timer was called.

Use in return probes paired with start-timer in entry probes."#
    }

    fn signature(&self) -> Signature {
        Signature::build("stop-timer")
            .input_output_types(vec![(Type::Nothing, Type::Int)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --pin lat -s 'kretprobe:sys_read' {|ctx| stop-timer | emit }",
            description: "Stop timer and emit the latency",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}
