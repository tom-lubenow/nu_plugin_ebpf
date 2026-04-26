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
    let packet_len = field(&fields, "packet_len");
    assert!(packet_len.names.contains(&"packet_len"));
    assert_eq!(packet_len.semantic_type.as_deref(), Some("u32"));
    assert_eq!(packet_len.runtime_type.as_deref(), Some("u32"));
}

#[test]
fn test_spec_context_fields_include_kernel_btf_runtime_type_labels() {
    let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let fields = spec_context_fields(&spec);

    let task = field(&fields, "task");
    assert!(task.names.contains(&"current_task"));
    assert_eq!(
        task.semantic_type.as_deref(),
        Some("ptr<kernel, struct<task_struct>>")
    );
    assert_eq!(
        task.runtime_type.as_deref(),
        Some("ptr<kernel, struct<task_struct>>")
    );
    assert_eq!(task.kernel_btf_runtime_type, Some("task_struct"));
    assert!(task.pointer_non_null);
    assert!(task.trusted_btf_kernel_pointer);
    assert!(!task.raw_context_pointer);
}

#[test]
fn test_spec_context_fields_include_pointer_verifier_facts() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let fields = spec_context_fields(&spec);

    let socket = field(&fields, "sk");
    assert!(socket.raw_context_pointer);
    assert!(socket.pointer_non_null);
    assert!(!socket.trusted_btf_kernel_pointer);
}

#[test]
fn test_spec_context_fields_include_load_guards() {
    let spec = ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let fields = spec_context_fields(&spec);

    let data = field(&fields, "data");
    assert_eq!(data.load_guard, Some("sock-ops-packet-data"));
    assert_eq!(data.load_guard_witness.as_deref(), Some("op"));
    assert!(
        data.load_guard_description
            .as_deref()
            .is_some_and(|description| description.contains("packet-aware ctx.op"))
    );

    let skb_len = field(&fields, "skb_len");
    assert_eq!(skb_len.load_guard, Some("sock-ops-packet-metadata"));
}

#[test]
fn test_spec_record_includes_packet_context_metadata() {
    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");

    assert_eq!(
        record
            .get("packet_context_kind")
            .expect("packet context kind should be present")
            .as_str()
            .expect("packet context kind should be a string"),
        "xdp_md"
    );
    assert_eq!(
        record
            .get("data_meta_context_kind")
            .expect("data_meta context kind should be present")
            .as_str()
            .expect("data_meta context kind should be a string"),
        "xdp_md"
    );
    assert!(
        record
            .get("direct_packet_writes")
            .expect("direct packet writes should be present")
            .as_bool()
            .expect("direct packet writes should be a bool")
    );

    let kprobe = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let record = spec_record(
        "kprobe:sys_read".to_string(),
        kprobe,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    assert!(
        record
            .get("packet_context_kind")
            .expect("packet context kind should be present")
            .is_nothing()
    );
    assert!(
        !record
            .get("direct_packet_writes")
            .expect("direct packet writes should be present")
            .as_bool()
            .expect("direct packet writes should be a bool")
    );
}

fn projection<'a>(
    projections: &'a [SpecContextProjection],
    path: &str,
) -> &'a SpecContextProjection {
    projections
        .iter()
        .find(|projection| projection.path == path)
        .unwrap_or_else(|| panic!("expected {path} in spec context projections"))
}

#[test]
fn test_spec_context_projections_include_socket_members() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let projections = spec_context_projections(&spec);

    let family = projection(&projections, "sk.family");
    assert_eq!(family.root, "sk");
    assert_eq!(family.name, "family");
    assert_eq!(family.ty, "u32");
    assert_eq!(family.offset, 4);
    assert!(family.supported);
    assert!(family.unsupported_reason.is_none());

    let src_ip4 = projection(&projections, "sk.src_ip4");
    assert!(!src_ip4.supported);
    assert!(
        src_ip4
            .unsupported_reason
            .as_deref()
            .is_some_and(|reason| { reason.contains("cgroup_sock post_bind4") })
    );
}

#[test]
fn test_spec_context_projections_respect_attach_sensitive_socket_members() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:post_bind4")
        .expect("cgroup_sock post_bind4 spec should parse");
    let projections = spec_context_projections(&spec);

    let src_ip4 = projection(&projections, "sk.src_ip4");
    assert!(src_ip4.supported);
    assert!(src_ip4.unsupported_reason.is_none());

    let src_ip6 = projection(&projections, "sk.src_ip6");
    assert!(!src_ip6.supported);
    assert!(
        src_ip6
            .unsupported_reason
            .as_deref()
            .is_some_and(|reason| { reason.contains("cgroup_sock post_bind6") })
    );
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

fn tracepoint_field<'a>(
    fields: &'a [SpecTracepointField],
    field_name: &str,
) -> Option<&'a SpecTracepointField> {
    fields.iter().find(|field| field.name == field_name)
}

#[test]
fn test_spec_tracepoint_fields_include_payload_fields_when_available() {
    let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
        .expect("tracepoint spec should parse");
    let (fields, err) = spec_tracepoint_fields(&spec, true);

    if fields.is_empty() {
        assert!(err.is_some(), "expected tracepoint fields or an error");
        return;
    }

    assert!(
        tracepoint_field(&fields, "filename").is_some()
            || tracepoint_field(&fields, "args").is_some(),
        "expected tracefs syscall fields or the well-known syscall fallback"
    );
    assert!(fields.iter().all(|field| !field.ty.is_empty()));
}

#[test]
fn test_spec_tracepoint_fields_are_absent_for_non_tracepoints() {
    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let (fields, err) = spec_tracepoint_fields(&spec, true);

    assert!(fields.is_empty());
    assert!(err.is_none());
}

fn arg<'a>(args: &'a [SpecContextArg], arg_name: &str) -> &'a SpecContextArg {
    args.iter()
        .find(|arg| arg.name == arg_name)
        .unwrap_or_else(|| panic!("expected {arg_name} in spec context args"))
}

#[test]
fn test_spec_context_args_include_pt_regs_slots() {
    let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let (args, err) = spec_context_args(&spec, true);

    assert!(err.is_none());
    assert_eq!(args.len(), 6);
    let arg0 = arg(&args, "arg0");
    assert_eq!(arg0.index, Some(0));
    assert_eq!(arg0.source, "pt_regs");
    assert_eq!(arg0.kind, "scalar");
    assert_eq!(arg0.ty.as_deref(), Some("u64"));
    assert!(arg0.supported);
}

#[test]
fn test_spec_context_args_describe_raw_tracepoint_symbolic_args() {
    let spec =
        ProgramSpec::parse("raw_tracepoint:sys_enter").expect("raw tracepoint spec should parse");
    let (args, err) = spec_context_args(&spec, true);

    assert!(err.is_none());
    let argn = arg(&args, "argN");
    assert_eq!(argn.index, None);
    assert_eq!(argn.source, "raw_tracepoint");
    assert_eq!(argn.ty.as_deref(), Some("u64"));
    assert!(argn.note.is_some());
    assert!(argn.unsupported_reason.is_none());
}

#[test]
fn test_spec_context_args_include_btf_trampoline_metadata_when_available() {
    let spec = ProgramSpec::parse("fentry:security_file_open").expect("fentry spec should parse");
    let (args, err) = spec_context_args(&spec, true);

    let Some(file_arg) = args
        .iter()
        .find(|arg| arg.named_alias.as_deref() == Some("file"))
    else {
        assert!(
            err.is_some() || args.is_empty(),
            "expected named file arg metadata or an unavailable-BTF skip"
        );
        return;
    };

    assert_eq!(file_arg.name, "arg0");
    assert_eq!(file_arg.index, Some(0));
    assert_eq!(file_arg.source, "btf_trampoline");
    assert!(file_arg.supported);
    assert!(file_arg.ty.as_deref().is_some_and(|ty| ty.contains("file")));
}

#[test]
fn test_spec_context_retval_includes_pt_regs_surface() {
    let spec = ProgramSpec::parse("kretprobe:sys_read").expect("kretprobe spec should parse");
    let (retval, err) = spec_context_retval(&spec, true);
    let retval = retval.expect("kretprobe should expose ctx.retval");

    assert!(err.is_none());
    assert_eq!(retval.name, "retval");
    assert_eq!(retval.source, "pt_regs");
    assert_eq!(retval.kind, "scalar");
    assert_eq!(retval.ty.as_deref(), Some("u64"));
    assert!(retval.supported);
}

#[test]
fn test_spec_context_retval_is_absent_on_entry_probe() {
    let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let (retval, err) = spec_context_retval(&spec, true);

    assert!(retval.is_none());
    assert!(err.is_none());
}

#[test]
fn test_spec_context_retval_includes_btf_trampoline_metadata_when_available() {
    let spec = ProgramSpec::parse("fexit:security_file_open").expect("fexit spec should parse");
    let (retval, err) = spec_context_retval(&spec, true);

    let Some(retval) = retval else {
        assert!(
            err.is_some(),
            "expected BTF retval metadata or an unavailable-BTF skip"
        );
        return;
    };

    assert_eq!(retval.name, "retval");
    assert_eq!(retval.source, "btf_trampoline");
    assert!(retval.supported);
    assert!(retval.ty.is_some());
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
