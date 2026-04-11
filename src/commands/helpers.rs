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
//! - helper-call: Invoke a modeled BPF helper by name
//! - kfunc-call: Invoke a typed kernel kfunc by name
//! - global-define / global-get / global-set: Named compiler-managed per-program globals
//! - map-get / map-put / map-delete / map-push: Generic BPF map operations

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
        "Call a modeled BPF helper by name from an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Advanced helper for invoking modeled BPF helpers by name.
The first positional argument must be a literal helper name such as
`bpf_get_current_pid_tgid` or `bpf_get_socket_cookie`. If the helper takes
arguments, pipeline input becomes arg0 when present."#
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
        "Call a kernel kfunc by name from an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Advanced helper for invoking BTF-described kernel kfuncs.
The first positional argument must be a literal kfunc name.
If omitted, --btf-id is resolved automatically from kernel BTF."#
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
                "Map kind: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, or lru-per-cpu-hash (default hash; queue/stack are not valid for map-get)",
                None,
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'fentry:security_file_open' {|ctx| $ctx.pid | map-get seen_paths --kind hash }",
            description: "Look up the current PID in a named hash map",
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
global is zero-initialized in `.bss`. With `--type`, no input is needed at all:
the type string declares a zero-initialized global directly.

Leading annotated `mut` bindings are the preferred small private-state path
when ordinary Nushell variable syntax is enough. Named globals remain useful
when you want an explicit shared name or a source-order-independent declaration.

Because this is declarative, later constant `global-define` calls can establish
globals used by earlier `global-get`s.

Examples:
  7 | global-define seen_pid
  $ctx.pid | global-define --zero seen_pid
  global-define --type i64 seen_pid
  global-define --type 'record{pid:i64,comm:bytes:16}' seen_state
  let state = (global-get seen_pid)"#
    }

    fn signature(&self) -> Signature {
        Signature::build("global-define")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .named(
                "type",
                SyntaxShape::String,
                "Declare a zero-initialized global directly from a type spec (i8/i16/i32/i64/u8/u16/u32/u64/bool/bytes:N/string:N/list:i64:N/record{field:type,...})",
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
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type i64 seen_pid; global-get seen_pid }",
                description: "Declare a zero-initialized named per-program global directly from a type spec",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type string:32 seen_name; global-get seen_name | count }",
                description: "Declare a zero-initialized string global with a 32-byte content cap",
                result: None,
            },
            Example {
                example: "ebpf attach 'kprobe:sys_read' {|ctx| global-define --type 'record{pid:i64,comm:bytes:16}' seen_state; (global-get seen_state).pid | count }",
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
        "Insert or update a value in a named generic BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Stores the pipeline input as the value for the given key in a named
generic map. The second positional argument is the key. Use `--flags` to pass
raw `bpf_map_update_elem` flags when needed. With `ebpf attach --pin`, the
value layout becomes available to later pinned `map-get` users in the same
group. If the pipeline input is a whole typed `map-get` value, `map-put`
stores the underlying aggregate bytes rather than the pointer wrapper.

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
                "Map kind: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, or lru-per-cpu-hash (default hash; queue/stack use map-push instead)",
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
        vec![Example {
            example: "ebpf attach 'fentry:security_file_open' {|ctx| $ctx.arg.file.f_path | map-put seen_paths $ctx.pid --kind hash }",
            description: "Store a typed struct value in a named hash map",
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
pub struct MapDelete;

impl PluginCommand for MapDelete {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-delete"
    }

    fn description(&self) -> &str {
        "Delete a key from a named generic BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Deletes a key from a named generic map. Use pipeline input as the key,
or pass an explicit key as the second positional argument.

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
                "Map kind: hash, array, queue, stack, lpm-trie, lru-hash, per-cpu-hash, per-cpu-array, or lru-per-cpu-hash (default hash; queue/stack are not valid for map-delete)",
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
pub struct MapPush;

impl PluginCommand for MapPush {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "map-push"
    }

    fn description(&self) -> &str {
        "Push a value into a named queue or stack BPF map."
    }

    fn extra_description(&self) -> &str {
        r#"Pushes the pipeline input into a named queue or stack map. Use
`--kind queue` for FIFO behavior or `--kind stack` for LIFO behavior. Unlike
`map-put`, queue/stack maps do not take an explicit key.

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
                "Map kind: queue or stack (required)",
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
