//! `ebpf spec` command - inspect parsed eBPF target metadata.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value,
};

#[cfg(target_os = "linux")]
use super::spec_output::spec_record;
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
            .input_output_types(vec![
                (Type::Nothing, Type::record()),
                (Type::Nothing, Type::table()),
            ])
            .optional(
                "probe",
                SyntaxShape::String,
                "The probe point to parse, for example 'fentry.s:do_sys_openat2' or 'xdp:lo:frags'.",
            )
            .switch(
                "list",
                "List representative metadata for every supported program type.",
                Some('l'),
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf spec 'fentry.s:do_sys_openat2'",
                description: "Inspect parsed target metadata and compatibility requirements",
                result: None,
            },
            Example {
                example: "ebpf spec --list",
                description: "List metadata for all modeled program types",
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
            run_spec(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_spec(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use crate::compiler::EbpfProgramType;
    use crate::program_spec::ProgramSpec;

    let list = call.has_flag("list")?;
    let probe: Option<String> = call.opt(0)?;

    if list {
        if probe.is_some() {
            return Err(LabeledError::new("Cannot combine a probe with --list")
                .with_label("remove either the positional probe or --list", call.head));
        }
        let rows = EbpfProgramType::supported_program_types()
            .iter()
            .copied()
            .map(|program_type| {
                let target = ProgramSpec::representative_target_for_program_type(program_type);
                let probe = format!("{}:{target}", program_type.canonical_prefix());
                let spec = ProgramSpec::from_program_type_target(program_type, target)
                    .unwrap_or_else(|err| {
                        panic!(
                            "{} representative target should parse: {err}",
                            program_type.canonical_prefix()
                        )
                    });
                spec_record(probe, spec, call.head, false)
            })
            .collect();
        return Ok(PipelineData::Value(Value::list(rows, call.head), None));
    }

    let Some(probe) = probe else {
        return Err(LabeledError::new("Missing eBPF target")
            .with_label("provide a target string or pass --list", call.head));
    };

    let spec = ProgramSpec::parse(&probe).map_err(|err| {
        LabeledError::new("Invalid eBPF target")
            .with_label(err.to_string(), call.head)
            .with_help("Use a target like 'kprobe:sys_clone', 'tracepoint:syscalls/sys_enter_openat', or 'xdp:lo'")
    })?;

    Ok(PipelineData::Value(
        spec_record(probe, spec, call.head, true),
        None,
    ))
}
