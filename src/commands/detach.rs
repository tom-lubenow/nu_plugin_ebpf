//! `ebpf detach` command - detach an eBPF probe

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfDetach;

impl PluginCommand for EbpfDetach {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf detach"
    }

    fn description(&self) -> &str {
        "Detach an eBPF probe by its ID."
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf detach")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("id", SyntaxShape::Int, "The probe ID to detach.")
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf detach 1",
            description: "Detach probe with ID 1",
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
            run_detach(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_detach(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use crate::loader::{LoadError, get_state};

    let id: i64 = call.req(0)?;
    let id = super::validate_probe_id(id, call.head)?;

    let state = get_state();
    state.detach(id).map_err(|e| {
        let msg = match &e {
            LoadError::ProbeNotFound(id) => format!("No probe found with ID {id}"),
            _ => e.to_string(),
        };
        LabeledError::new("Failed to detach probe")
            .with_label(msg, call.head)
            .with_help("Use 'ebpf list' to see active probes")
    })?;

    Ok(PipelineData::empty())
}
