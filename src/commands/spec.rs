//! `ebpf spec` command - inspect parsed eBPF target metadata.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, Span, SyntaxShape, Type, Value,
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
    use crate::program_spec::ProgramSpec;

    let list = call.has_flag("list")?;
    let probe: Option<String> = call.opt(0)?;

    if list {
        if probe.is_some() {
            return Err(LabeledError::new("Cannot combine a probe with --list")
                .with_label("remove either the positional probe or --list", call.head));
        }
        return Ok(PipelineData::Value(
            Value::list(spec_list_records(call.head), call.head),
            None,
        ));
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

#[cfg(target_os = "linux")]
fn spec_list_records(span: Span) -> Vec<Value> {
    use crate::compiler::EbpfProgramType;
    use crate::program_spec::ProgramSpec;

    EbpfProgramType::supported_program_types()
        .iter()
        .copied()
        .map(|program_type| {
            let target = ProgramSpec::representative_target_for_program_type(program_type);
            let probe = format!("{}:{target}", program_type.canonical_prefix());
            let spec =
                ProgramSpec::from_program_type_target(program_type, target).unwrap_or_else(|err| {
                    panic!(
                        "{} representative target should parse: {err}",
                        program_type.canonical_prefix()
                    )
                });
            spec_record(probe, spec, span, false)
        })
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::compiler::EbpfProgramType;
    use crate::program_spec::ProgramSpec;
    use std::collections::HashSet;

    #[test]
    fn test_spec_list_records_cover_supported_program_types() {
        let rows = spec_list_records(Span::test_data());
        assert_eq!(rows.len(), EbpfProgramType::supported_program_types().len());

        let mut seen = HashSet::new();
        for row in rows {
            let record = row.as_record().expect("spec list row should be a record");
            let program_type = record
                .get("program_type")
                .expect("program_type should be present")
                .as_str()
                .expect("program_type should be a string");
            let probe = record
                .get("probe")
                .expect("probe should be present")
                .as_str()
                .expect("probe should be a string");
            let target = record
                .get("target")
                .expect("target should be present")
                .as_str()
                .expect("target should be a string");
            let section = record
                .get("section")
                .expect("section should be present")
                .as_str()
                .expect("section should be a string");
            let section_prefix = record
                .get("section_prefix")
                .expect("section_prefix should be present")
                .as_str()
                .expect("section_prefix should be a string");
            let live_attach_supported = record
                .get("live_attach_supported")
                .expect("live_attach_supported should be present")
                .as_bool()
                .expect("live_attach_supported should be a bool");
            let live_attach_default_allowed = record
                .get("live_attach_default_allowed")
                .expect("live_attach_default_allowed should be present")
                .as_bool()
                .expect("live_attach_default_allowed should be a bool");
            let live_attach_requires_opt_in = record
                .get("live_attach_requires_opt_in")
                .expect("live_attach_requires_opt_in should be present")
                .as_bool()
                .expect("live_attach_requires_opt_in should be a bool");
            let live_attach_status = record
                .get("live_attach_status")
                .expect("live_attach_status should be present")
                .as_str()
                .expect("live_attach_status should be a string");
            let live_attach_unsupported_reason = record
                .get("live_attach_unsupported_reason")
                .expect("live_attach_unsupported_reason should be present");
            let live_attach_opt_in_reason = record
                .get("live_attach_opt_in_reason")
                .expect("live_attach_opt_in_reason should be present");
            let live_attach_default_test_lane = record
                .get("live_attach_default_test_lane")
                .expect("live_attach_default_test_lane should be present")
                .as_str()
                .expect("live_attach_default_test_lane should be a string");
            let live_attach_default_test_lane_description = record
                .get("live_attach_default_test_lane_description")
                .expect("live_attach_default_test_lane_description should be present")
                .as_str()
                .expect("live_attach_default_test_lane_description should be a string");

            let parsed_type = EbpfProgramType::from_spec_prefix(program_type)
                .expect("program_type should be a modeled canonical prefix");
            let representative_target =
                ProgramSpec::representative_target_for_program_type(parsed_type);
            let representative_spec =
                ProgramSpec::from_program_type_target(parsed_type, representative_target)
                    .expect("representative target should parse");
            let live_attach_policy = representative_spec.live_attach_policy();

            assert!(
                seen.insert(program_type.to_string()),
                "duplicate spec list row for {program_type}"
            );
            assert_eq!(program_type, parsed_type.canonical_prefix());
            assert_eq!(probe, format!("{program_type}:{representative_target}"));
            assert_eq!(target, representative_target);
            assert_eq!(section_prefix, parsed_type.section_prefix());
            assert!(!section.is_empty(), "{program_type} should emit a section");
            assert_eq!(
                live_attach_supported, live_attach_policy.loader_supported,
                "{program_type} list row should report loader support from program policy"
            );
            assert_eq!(
                live_attach_default_allowed, live_attach_policy.default_allowed,
                "{program_type} list row should report default live-attach policy"
            );
            assert_eq!(
                live_attach_requires_opt_in, live_attach_policy.requires_opt_in,
                "{program_type} list row should report opt-in policy"
            );
            assert_eq!(
                live_attach_status,
                live_attach_policy.status().key(),
                "{program_type} list row should report structured live-attach status"
            );
            assert_eq!(
                live_attach_default_test_lane,
                representative_spec.live_attach_default_test_lane().key(),
                "{program_type} list row should report loader-aware test lane"
            );
            assert_eq!(
                live_attach_default_test_lane_description,
                representative_spec
                    .live_attach_default_test_lane()
                    .description(),
                "{program_type} list row should report loader-aware test lane description"
            );
            if let Some(reason) = live_attach_policy.unsupported_reason {
                assert_eq!(
                    live_attach_unsupported_reason
                        .as_str()
                        .expect("unsupported reason should be a string"),
                    reason.key(),
                    "{program_type} list row should report structured unsupported reason"
                );
            } else {
                assert!(
                    live_attach_unsupported_reason.is_nothing(),
                    "{program_type} list row should not report an unsupported reason"
                );
            }
            if let Some(reason) = live_attach_policy.opt_in_reason {
                assert_eq!(
                    live_attach_opt_in_reason
                        .as_str()
                        .expect("opt-in reason should be a string"),
                    reason.key(),
                    "{program_type} list row should report structured opt-in reason"
                );
            } else {
                assert!(
                    live_attach_opt_in_reason.is_nothing(),
                    "{program_type} list row should not report an opt-in reason"
                );
            }
        }

        for program_type in EbpfProgramType::supported_program_types() {
            assert!(
                seen.contains(program_type.canonical_prefix()),
                "{} missing from spec list rows",
                program_type.canonical_prefix()
            );
        }
    }
}
