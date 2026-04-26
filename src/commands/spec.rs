//! `ebpf spec` command - inspect parsed eBPF target metadata.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, Span, SyntaxShape, Type, Value,
    record,
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextField {
    field: String,
    names: Vec<&'static str>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecContextWrite {
    field: &'static str,
    kind: &'static str,
    indexed: bool,
}

#[cfg(target_os = "linux")]
fn spec_context_fields(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextField> {
    let mut fields: Vec<(crate::compiler::mir::CtxField, SpecContextField)> = Vec::new();

    for entry in spec.program_type().ctx_field_name_entries() {
        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        if let Some((_, field)) = fields.iter_mut().find(|(field, _)| field == &entry.field) {
            field.names.push(entry.name);
        } else {
            fields.push((
                entry.field.clone(),
                SpecContextField {
                    field: entry.field.display_name(),
                    names: vec![entry.name],
                },
            ));
        }
    }

    fields.into_iter().map(|(_, field)| field).collect()
}

#[cfg(target_os = "linux")]
fn context_field_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_context_fields(spec)
        .into_iter()
        .map(|field| {
            let names = field
                .names
                .into_iter()
                .map(|name| Value::string(name, span))
                .collect();
            Value::record(
                record! {
                    "field" => Value::string(field.field, span),
                    "names" => Value::list(names, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_context_writes(spec: &crate::program_spec::ProgramSpec) -> Vec<SpecContextWrite> {
    spec.ctx_write_surfaces_for_spec()
        .into_iter()
        .map(|surface| SpecContextWrite {
            field: surface.field_name,
            kind: surface.kind,
            indexed: surface.indexed,
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn context_write_records(spec: &crate::program_spec::ProgramSpec, span: Span) -> Vec<Value> {
    spec_context_writes(spec)
        .into_iter()
        .map(|surface| {
            Value::record(
                record! {
                    "field" => Value::string(surface.field, span),
                    "kind" => Value::string(surface.kind, span),
                    "indexed" => Value::bool(surface.indexed, span),
                },
                span,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn spec_record(probe: String, spec: crate::program_spec::ProgramSpec, span: Span) -> Value {
    let program_type = spec.program_type();
    let attach_kind = program_type.attach_kind();
    let live_attach_policy = spec.live_attach_policy();
    let live_attach_note = live_attach_policy.note.unwrap_or("");
    let context_fields = context_field_records(&spec, span);
    let context_writes = context_write_records(&spec, span);
    let capabilities = program_type
        .supported_capabilities()
        .iter()
        .map(|capability| {
            Value::record(
                record! {
                    "key" => Value::string(capability.key(), span),
                    "description" => Value::string(capability.description(), span),
                },
                span,
            )
        })
        .collect();
    let requirements = spec
        .compatibility_requirements()
        .into_iter()
        .map(|requirement| {
            Value::record(
                record! {
                    "key" => Value::string(requirement.key(), span),
                    "description" => Value::string(requirement.description(), span),
                },
                span,
            )
        })
        .collect();
    let return_aliases = program_type
        .return_action_alias_pairs()
        .into_iter()
        .map(|(alias, value)| {
            let const_value = value
                .const_value()
                .map(|value| Value::int(value, span))
                .unwrap_or_else(|| Value::nothing(span));
            Value::record(
                record! {
                    "alias" => Value::string(alias, span),
                    "kind" => Value::string(value.key(), span),
                    "const_value" => const_value,
                },
                span,
            )
        })
        .collect();

    Value::record(
        record! {
            "probe" => Value::string(probe, span),
            "program_type" => Value::string(program_type.canonical_prefix(), span),
            "kernel_program_type" => Value::string(program_type.kernel_prog_type(), span),
            "context_family" => Value::string(program_type.context_family().key(), span),
            "target" => Value::string(spec.target_string(), span),
            "section" => Value::string(spec.section_name(), span),
            "attach_kind" => Value::string(attach_kind.key(), span),
            "target_kind" => Value::string(program_type.target_kind().key(), span),
            "arg_access" => Value::string(program_type.arg_access().key(), span),
            "retval_access" => Value::string(program_type.retval_access().key(), span),
            "live_attach_supported" => Value::bool(live_attach_policy.loader_supported, span),
            "live_attach_default_allowed" => Value::bool(live_attach_policy.default_allowed, span),
            "live_attach_requires_opt_in" => Value::bool(live_attach_policy.requires_opt_in, span),
            "live_attach_note" => Value::string(live_attach_note, span),
            "context_fields" => Value::list(context_fields, span),
            "context_writes" => Value::list(context_writes, span),
            "capabilities" => Value::list(capabilities, span),
            "compatibility_requirements" => Value::list(requirements, span),
            "return_aliases" => Value::list(return_aliases, span),
        },
        span,
    )
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
                spec_record(probe, spec, call.head)
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
        spec_record(probe, spec, call.head),
        None,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::program_spec::ProgramSpec;

    fn field<'a>(fields: &'a [SpecContextField], field_name: &str) -> &'a SpecContextField {
        fields
            .iter()
            .find(|field| field.field == field_name)
            .unwrap_or_else(|| panic!("expected ctx.{field_name} in spec context fields"))
    }

    #[test]
    fn test_spec_context_fields_include_program_specific_aliases() {
        let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        let fields = spec_context_fields(&spec);

        assert!(field(&fields, "ingress_ifindex").names.contains(&"ifindex"));
        assert!(field(&fields, "packet_len").names.contains(&"packet_len"));
    }

    #[test]
    fn test_spec_context_fields_preserve_tracepoint_payload_names() {
        let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
            .expect("tracepoint spec should parse");
        let fields = spec_context_fields(&spec);

        assert!(field(&fields, "cgroup").names.contains(&"current_cgroup"));
        assert!(
            !fields.iter().any(|field| field.names.contains(&"cgroup")),
            "ctx.cgroup is a tracepoint payload field name, so it must not be advertised as a builtin"
        );
    }

    #[test]
    fn test_context_write_records_filter_target_specific_writes() {
        let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
        let tc_ingress_writes = spec_context_writes(&tc_ingress);
        assert!(tc_ingress_writes.iter().any(|surface| {
            surface.field == "sk" && surface.kind == "assign-socket" && !surface.indexed
        }));

        let tc_egress = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
        let tc_egress_writes = spec_context_writes(&tc_egress);
        assert!(
            !tc_egress_writes.iter().any(|surface| surface.field == "sk"),
            "ctx.sk assignment should not be advertised on tc egress"
        );
    }
}
