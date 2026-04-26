//! `ebpf spec` command - inspect parsed eBPF target metadata.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfSpec;

impl PluginCommand for EbpfSpec {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf spec"
    }

    fn description(&self) -> &str {
        "Parse an eBPF target string and report the modeled program metadata."
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf spec")
            .input_output_types(vec![(Type::Nothing, Type::record())])
            .required(
                "probe",
                SyntaxShape::String,
                "The probe point to parse, for example 'fentry.s:do_sys_openat2' or 'xdp:lo:frags'.",
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf spec 'fentry.s:do_sys_openat2'",
            description: "Inspect parsed target metadata and compatibility requirements",
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
            run_spec(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_spec(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use nu_protocol::{Value, record};

    use crate::program_spec::ProgramSpec;

    let probe: String = call.req(0)?;
    let spec = ProgramSpec::parse(&probe).map_err(|err| {
        LabeledError::new("Invalid eBPF target")
            .with_label(err.to_string(), call.head)
            .with_help("Use a target like 'kprobe:sys_clone', 'tracepoint:syscalls/sys_enter_openat', or 'xdp:lo'")
    })?;
    let program_type = spec.program_type();
    let attach_kind = program_type.attach_kind();
    let live_attach_policy = spec.live_attach_policy();
    let live_attach_note = live_attach_policy.note.unwrap_or("");
    let requirements = spec
        .compatibility_requirements()
        .into_iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "key" => Value::string(requirement.key(), call.head),
                    "description" => Value::string(requirement.description(), call.head),
                },
                call.head,
            )
        })
        .collect();

    Ok(PipelineData::Value(
        Value::record(
            record! {
                "probe" => Value::string(probe, call.head),
                "program_type" => Value::string(program_type.canonical_prefix(), call.head),
                "kernel_program_type" => Value::string(program_type.kernel_prog_type(), call.head),
                "target" => Value::string(spec.target_string(), call.head),
                "section" => Value::string(spec.section_name(), call.head),
                "attach_kind" => Value::string(format!("{attach_kind:?}"), call.head),
                "target_kind" => Value::string(format!("{:?}", program_type.target_kind()), call.head),
                "live_attach_supported" => Value::bool(live_attach_policy.loader_supported, call.head),
                "live_attach_default_allowed" => Value::bool(live_attach_policy.default_allowed, call.head),
                "live_attach_requires_opt_in" => Value::bool(live_attach_policy.requires_opt_in, call.head),
                "live_attach_note" => Value::string(live_attach_note, call.head),
                "compatibility_requirements" => Value::list(requirements, call.head),
            },
            call.head,
        ),
        None,
    ))
}
