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
//! - kfunc-call: Invoke a typed kernel kfunc by name

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

Example:
  let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }
  sleep 5sec
  ebpf counters $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("count")
            .input_output_types(vec![(Type::Int, Type::Int)])
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
