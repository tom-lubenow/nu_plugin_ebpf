//! Display counter values from the `count` command

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value, record,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfCounters;

impl PluginCommand for EbpfCounters {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf counters"
    }

    fn description(&self) -> &str {
        "Display counter values collected by the count command in an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Reads the counter map from an attached probe that uses the `count` command.
Each row shows a key and the number of times that key was counted.

Example workflow:
  let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }
  sleep 5sec
  ebpf counters $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf counters")
            .required("id", SyntaxShape::Int, "Probe ID to get counters from")
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }; sleep 5sec; ebpf counters $id",
                description: "Count sys_read calls per PID and display results",
                result: None,
            },
            Example {
                example: "ebpf counters $id | sort-by count --reverse",
                description: "Show counters sorted by count descending",
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
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_counters(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_counters(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use crate::loader::get_state;

    let id: i64 = call.req(0)?;
    let id = super::validate_probe_id(id, call.head)?;
    let span = call.head;

    let state = get_state();
    let mut records: Vec<Value> = Vec::new();

    let int_entries = state
        .get_counters(id)
        .map_err(|e| LabeledError::new("Failed to get counters").with_label(e.to_string(), span))?;

    for entry in int_entries {
        records.push(Value::record(
            record! {
                "key" => Value::int(entry.key, span),
                "count" => Value::int(entry.count, span),
            },
            span,
        ));
    }

    let string_entries = state.get_string_counters(id).map_err(|e| {
        LabeledError::new("Failed to get string counters").with_label(e.to_string(), span)
    })?;

    for entry in string_entries {
        records.push(Value::record(
            record! {
                "key" => Value::string(entry.key, span),
                "count" => Value::int(entry.count, span),
            },
            span,
        ));
    }

    Ok(PipelineData::Value(Value::list(records, span), None))
}
