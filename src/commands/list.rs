//! `ebpf list` command - list active eBPF probes

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{Category, Example, LabeledError, PipelineData, Signature, Type, Value, record};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfList;

impl PluginCommand for EbpfList {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf list"
    }

    fn description(&self) -> &str {
        "List all active eBPF probes."
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf list")
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf list",
            description: "List all active eBPF probes",
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
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_list(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_list(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use crate::loader::get_state;

    let state = get_state();
    let probes = state.list();

    let rows: Vec<Value> = probes
        .into_iter()
        .map(|p| {
            Value::record(
                record! {
                    "id" => Value::int(p.id as i64, call.head),
                    "probe" => Value::string(p.probe_spec, call.head),
                    "uptime" => Value::string(format!("{}s", p.uptime_secs), call.head),
                },
                call.head,
            )
        })
        .collect();

    Ok(PipelineData::Value(Value::list(rows, call.head), None))
}
