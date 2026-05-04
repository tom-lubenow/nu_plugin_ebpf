use super::*;
use crate::compiler::EbpfProgramType;
use crate::program_spec::ProgramSpec;

fn field<'a>(fields: &'a [SpecContextField], field_name: &str) -> &'a SpecContextField {
    fields
        .iter()
        .find(|field| field.field == field_name)
        .unwrap_or_else(|| panic!("expected ctx.{field_name} in spec context fields"))
}

fn context_write<'a>(writes: &'a [SpecContextWrite], field_name: &str) -> &'a SpecContextWrite {
    writes
        .iter()
        .find(|surface| surface.field == field_name)
        .unwrap_or_else(|| panic!("expected writable ctx.{field_name} in spec context writes"))
}

fn intrinsic_commands(spec_text: &str) -> Vec<String> {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let record = spec_record(spec_text.to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    record
        .get("intrinsics")
        .expect("intrinsics should be present")
        .as_list()
        .expect("intrinsics should be a list")
        .iter()
        .map(|intrinsic| {
            intrinsic
                .as_record()
                .expect("intrinsic should be a record")
                .get("command")
                .expect("intrinsic command should be present")
                .as_str()
                .expect("intrinsic command should be a string")
                .to_string()
        })
        .collect()
}

fn intrinsic_record(spec_text: &str, command: &str) -> Value {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let record = spec_record(spec_text.to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    record
        .get("intrinsics")
        .expect("intrinsics should be present")
        .as_list()
        .expect("intrinsics should be a list")
        .iter()
        .find(|intrinsic| {
            intrinsic
                .as_record()
                .ok()
                .and_then(|record| record.get("command"))
                .and_then(|command| command.as_str().ok())
                .is_some_and(|candidate| candidate == command)
        })
        .unwrap_or_else(|| panic!("expected {command} intrinsic in {spec_text} spec"))
        .clone()
}

fn intrinsic_backing_helper_names(spec_text: &str, command: &str) -> Vec<String> {
    intrinsic_record(spec_text, command)
        .as_record()
        .expect("intrinsic should be a record")
        .get("backing_helpers")
        .expect("backing helpers should be present")
        .as_list()
        .expect("backing helpers should be a list")
        .iter()
        .map(|helper| {
            helper
                .as_record()
                .expect("backing helper should be a record")
                .get("helper")
                .expect("helper name should be present")
                .as_str()
                .expect("helper name should be a string")
                .to_string()
        })
        .collect()
}

fn intrinsic_variant_entries(spec_text: &str, command: &str) -> Vec<(String, String, String)> {
    intrinsic_record(spec_text, command)
        .as_record()
        .expect("intrinsic should be a record")
        .get("variants")
        .expect("intrinsic variants should be present")
        .as_list()
        .expect("intrinsic variants should be a list")
        .iter()
        .map(|variant| {
            let variant = variant
                .as_record()
                .expect("intrinsic variant should be a record");
            let selector = variant
                .get("selector")
                .expect("variant selector should be present")
                .as_str()
                .expect("variant selector should be a string")
                .to_string();
            let value = variant
                .get("value")
                .expect("variant value should be present")
                .as_str()
                .expect("variant value should be a string")
                .to_string();
            let helper = variant
                .get("backing_helper")
                .expect("variant backing helper should be present")
                .as_str()
                .expect("variant backing helper should be a string")
                .to_string();
            (selector, value, helper)
        })
        .collect()
}

fn intrinsic_backing_helper_kernel_floor(
    spec_text: &str,
    command: &str,
    helper_name: &str,
) -> (String, String) {
    let intrinsic = intrinsic_record(spec_text, command);
    let intrinsic = intrinsic.as_record().expect("intrinsic should be a record");
    let helper = intrinsic
        .get("backing_helpers")
        .expect("backing helpers should be present")
        .as_list()
        .expect("backing helpers should be a list")
        .iter()
        .find(|helper| {
            helper
                .as_record()
                .ok()
                .and_then(|record| record.get("helper"))
                .and_then(|helper| helper.as_str().ok())
                .is_some_and(|candidate| candidate == helper_name)
        })
        .unwrap_or_else(|| panic!("expected {helper_name} backing helper for {command}"));
    let helper = helper
        .as_record()
        .expect("backing helper should be a record");
    let minimum_kernel = helper
        .get("minimum_kernel")
        .expect("minimum kernel should be present")
        .as_str()
        .expect("minimum kernel should be a string")
        .to_string();
    let minimum_kernel_source = helper
        .get("minimum_kernel_source")
        .expect("minimum kernel source should be present")
        .as_str()
        .expect("minimum kernel source should be a string")
        .to_string();
    (minimum_kernel, minimum_kernel_source)
}

fn assert_field_backing_helper(
    spec_text: &str,
    field_name: &str,
    helper: &str,
    minimum_kernel: &str,
) {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let fields = spec_context_fields(&spec, false);
    let field = field(&fields, field_name);
    assert_eq!(field.backing_helper, Some(helper));
    assert_eq!(field.backing_helper_minimum_kernel, Some(minimum_kernel));
    assert!(
        field
            .backing_helper_minimum_kernel_source
            .is_some_and(|source| source.contains(&format!("/v{minimum_kernel}/"))),
        "ctx.{field_name} helper metadata should include a source link for {minimum_kernel}"
    );
}

#[test]
fn test_spec_context_fields_include_program_specific_aliases() {
    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let fields = spec_context_fields(&spec, false);

    let ifindex = field(&fields, "ingress_ifindex");
    assert!(ifindex.names.contains(&"ifindex"));
    assert_eq!(ifindex.minimum_kernel, Some("4.16"));
    assert!(
        ifindex
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.16/include/uapi/linux/bpf.h"))
    );
    let rx_queue_index = field(&fields, "rx_queue_index");
    assert_eq!(rx_queue_index.minimum_kernel, Some("4.16"));
    let packet_len = field(&fields, "packet_len");
    assert!(packet_len.names.contains(&"packet_len"));
    assert_eq!(packet_len.semantic_type.as_deref(), Some("u32"));
    assert_eq!(packet_len.runtime_type.as_deref(), Some("u32"));
    assert_eq!(packet_len.minimum_kernel, Some("4.8"));
    assert!(
        packet_len
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.8/include/uapi/linux/bpf.h"))
    );
    let data = field(&fields, "data");
    assert_eq!(data.minimum_kernel, Some("4.8"));
    let data_end = field(&fields, "data_end");
    assert_eq!(data_end.minimum_kernel, Some("4.8"));
}

#[test]
fn test_spec_context_fields_include_kernel_btf_runtime_type_labels() {
    let spec = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let fields = spec_context_fields(&spec, false);

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
    assert_eq!(task.minimum_kernel, Some("5.11"));
    assert_eq!(task.backing_helper, Some("bpf_get_current_task_btf"));
    assert_eq!(task.backing_helper_minimum_kernel, Some("5.11"));
    assert!(
        task.backing_helper_minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.11/"))
    );

    let cgroup = field(&fields, "cgroup");
    assert!(cgroup.names.contains(&"current_cgroup"));
    assert_eq!(
        cgroup.semantic_type.as_deref(),
        Some("ptr<kernel, struct<cgroup>>")
    );
    assert_eq!(cgroup.kernel_btf_runtime_type, Some("cgroup"));
    assert!(cgroup.trusted_btf_kernel_pointer);
    assert_eq!(cgroup.backing_helper, Some("bpf_get_current_task_btf"));
    assert_eq!(cgroup.backing_helper_minimum_kernel, Some("5.11"));
    assert_eq!(cgroup.minimum_kernel, Some("5.11"));
}

#[test]
fn test_spec_context_fields_include_pointer_verifier_facts() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let fields = spec_context_fields(&spec, false);

    let socket = field(&fields, "sk");
    assert!(socket.raw_context_pointer);
    assert!(socket.pointer_non_null);
    assert!(!socket.trusted_btf_kernel_pointer);

    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let fields = spec_context_fields(&spec, false);
    for field_name in ["data", "data_meta", "data_end"] {
        let packet_ptr = field(&fields, field_name);
        assert_eq!(packet_ptr.semantic_type.as_deref(), Some("ptr<packet, u8>"));
        assert!(packet_ptr.pointer_non_null);
    }
}

#[test]
fn test_spec_context_fields_label_flow_keys_as_context_pointer() {
    let spec = ProgramSpec::parse("flow_dissector:/proc/self/ns/net")
        .expect("flow_dissector spec should parse");
    let fields = spec_context_fields(&spec, false);

    let flow_keys = field(&fields, "flow_keys");
    assert_eq!(
        flow_keys.semantic_type.as_deref(),
        Some("ptr<context, struct<bpf_flow_keys>>")
    );
    assert_eq!(
        flow_keys.runtime_type.as_deref(),
        Some("ptr<context, struct<bpf_flow_keys>>")
    );
    assert!(flow_keys.pointer_non_null);
}

#[test]
fn test_spec_context_fields_label_helper_backed_scalar_fields() {
    let spec = ProgramSpec::parse("kretprobe:sys_read").expect("kretprobe spec should parse");
    let fields = spec_context_fields(&spec, false);

    let pid = field(&fields, "pid");
    assert_eq!(pid.backing_helper, Some("bpf_get_current_pid_tgid"));
    assert_eq!(pid.backing_helper_minimum_kernel, Some("4.2"));
    assert_eq!(pid.minimum_kernel, Some("4.2"));
    assert!(
        pid.minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.2/"))
    );

    let retval = field(&fields, "retval");
    assert_eq!(retval.semantic_type.as_deref(), Some("u64"));
    assert_eq!(retval.runtime_type.as_deref(), Some("u64"));
    assert_eq!(retval.backing_helper, None);
    assert_eq!(retval.minimum_kernel, None);

    let kstack = field(&fields, "kstack");
    assert_eq!(kstack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(kstack.runtime_type.as_deref(), Some("i64"));
    assert_eq!(kstack.backing_helper, Some("bpf_get_stackid"));
    assert_eq!(kstack.backing_helper_minimum_kernel, Some("4.6"));
    assert_eq!(kstack.minimum_kernel, Some("4.6"));

    let ustack = field(&fields, "ustack");
    assert_eq!(ustack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(ustack.runtime_type.as_deref(), Some("i64"));
}

#[test]
fn test_spec_context_fields_label_specialized_helper_backed_fields() {
    for (spec, field, helper, minimum_kernel) in [
        ("kprobe.multi:vfs_*", "func_ip", "bpf_get_func_ip", "5.15"),
        (
            "kprobe.multi:vfs_*",
            "attach_cookie",
            "bpf_get_attach_cookie",
            "5.15",
        ),
        (
            "perf_event:software:cpu-clock",
            "perf_counter",
            "bpf_perf_prog_read_value",
            "4.15",
        ),
        ("xdp:lo", "xdp_buff_len", "bpf_xdp_get_buff_len", "5.18"),
        ("lwt_xmit:demo-route", "csum_level", "bpf_csum_level", "5.8"),
        (
            "lwt_xmit:demo-route",
            "hash_recalc",
            "bpf_get_hash_recalc",
            "4.8",
        ),
        (
            "cgroup_sysctl:/sys/fs/cgroup",
            "sysctl_name",
            "bpf_sysctl_get_name",
            "5.2",
        ),
        (
            "cgroup_sysctl:/sys/fs/cgroup",
            "sysctl_current_value",
            "bpf_sysctl_get_current_value",
            "5.2",
        ),
        (
            "cgroup_sysctl:/sys/fs/cgroup",
            "sysctl_new_value",
            "bpf_sysctl_get_new_value",
            "5.2",
        ),
        (
            "fentry:security_file_open",
            "arg_count",
            "bpf_get_func_arg_cnt",
            "5.17",
        ),
    ] {
        assert_field_backing_helper(spec, field, helper, minimum_kernel);
    }
}

#[test]
fn test_spec_context_fields_include_load_guards() {
    let spec = ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let fields = spec_context_fields(&spec, false);

    let data = field(&fields, "data");
    assert_eq!(data.load_guard, Some("sock-ops-packet-data"));
    assert_eq!(data.minimum_kernel, Some("5.10"));
    assert_eq!(data.load_guard_witness.as_deref(), Some("op"));
    assert!(
        data.load_guard_description
            .as_deref()
            .is_some_and(|description| description.contains("packet-aware ctx.op"))
    );

    let skb_len = field(&fields, "skb_len");
    assert_eq!(skb_len.load_guard, Some("sock-ops-packet-metadata"));
    assert_eq!(skb_len.minimum_kernel, Some("5.10"));

    let packet_len = field(&fields, "packet_len");
    assert_eq!(packet_len.minimum_kernel, Some("5.10"));
    assert!(
        packet_len
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.10/"))
    );
}

#[test]
fn test_spec_context_fields_include_sock_ops_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let fields = spec_context_fields(&spec, false);

    let op = field(&fields, "op");
    assert_eq!(op.minimum_kernel, Some("4.14"));
    assert!(
        op.minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.14/include/uapi/linux/bpf.h"))
    );
    for field_name in ["reply", "replylong"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.14"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.14/include/uapi/linux/bpf.h"))
        );
    }

    for field_name in ["args", "snd_cwnd", "state", "bytes_acked", "sk_txhash"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.16"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.16/include/uapi/linux/bpf.h"))
        );
    }

    let socket = field(&fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("5.3"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.3/include/uapi/linux/bpf.h"))
    );
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

#[test]
fn test_spec_record_reports_target_specific_live_attach_policy() {
    let spec = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("cgroup_sock_addr unix spec should parse");
    let record = spec_record(
        "cgroup_sock_addr:/sys/fs/cgroup:connect_unix".to_string(),
        spec,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");

    assert!(
        !record
            .get("live_attach_supported")
            .expect("live_attach_supported should be present")
            .as_bool()
            .expect("live_attach_supported should be a bool")
    );
    assert!(
        !record
            .get("live_attach_default_allowed")
            .expect("live_attach_default_allowed should be present")
            .as_bool()
            .expect("live_attach_default_allowed should be a bool")
    );
    assert!(
        !record
            .get("live_attach_requires_opt_in")
            .expect("live_attach_requires_opt_in should be present")
            .as_bool()
            .expect("live_attach_requires_opt_in should be a bool")
    );
    assert!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string")
            .contains("BPF_CGROUP_UNIX")
    );

    let generic_struct_ops =
        ProgramSpec::parse("struct_ops:demo_ops").expect("generic struct_ops spec should parse");
    let record = spec_record(
        "struct_ops:demo_ops".to_string(),
        generic_struct_ops,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    assert!(
        record
            .get("live_attach_supported")
            .expect("live_attach_supported should be present")
            .as_bool()
            .expect("live_attach_supported should be a bool")
    );
    assert!(
        !record
            .get("live_attach_default_allowed")
            .expect("live_attach_default_allowed should be present")
            .as_bool()
            .expect("live_attach_default_allowed should be a bool")
    );
    assert!(
        record
            .get("live_attach_requires_opt_in")
            .expect("live_attach_requires_opt_in should be present")
            .as_bool()
            .expect("live_attach_requires_opt_in should be a bool")
    );
    assert!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string")
            .contains("unclassified struct_ops")
    );
}

#[test]
fn test_spec_record_context_fields_include_minimum_kernel_metadata() {
    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let context_fields = record
        .get("context_fields")
        .expect("context fields should be present")
        .as_list()
        .expect("context fields should be a list");
    let packet_len = context_fields
        .iter()
        .find_map(|value| {
            let field = value.as_record().ok()?;
            (field
                .get("field")?
                .as_str()
                .ok()
                .is_some_and(|field_name| field_name == "packet_len"))
            .then_some(field)
        })
        .expect("packet_len context field should be present");

    assert_eq!(
        packet_len
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "4.8"
    );
    assert!(
        packet_len
            .get("minimum_kernel_source")
            .expect("minimum kernel source should be present")
            .as_str()
            .expect("minimum kernel source should be a string")
            .contains("/v4.8/")
    );
}

#[test]
fn test_spec_record_context_projections_include_helper_kernel_metadata() {
    let tc = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
    let record = spec_record("tc:lo:ingress".to_string(), tc, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let context_projections = record
        .get("context_projections")
        .expect("context projections should be present")
        .as_list()
        .expect("context projections should be a list");
    let tcp_snd_cwnd = context_projections
        .iter()
        .find_map(|value| {
            let projection = value.as_record().ok()?;
            (projection
                .get("path")?
                .as_str()
                .ok()
                .is_some_and(|path| path == "sk.tcp.snd_cwnd"))
            .then_some(projection)
        })
        .expect("sk.tcp.snd_cwnd projection should be present");

    assert_eq!(
        tcp_snd_cwnd
            .get("helper_minimum_kernel")
            .expect("helper minimum kernel should be present")
            .as_str()
            .expect("helper minimum kernel should be a string"),
        "5.1"
    );
    assert!(
        tcp_snd_cwnd
            .get("helper_minimum_kernel_source")
            .expect("helper minimum kernel source should be present")
            .as_str()
            .expect("helper minimum kernel source should be a string")
            .contains("/v5.1/")
    );

    let sk_family = context_projections
        .iter()
        .find_map(|value| {
            let projection = value.as_record().ok()?;
            (projection
                .get("path")?
                .as_str()
                .ok()
                .is_some_and(|path| path == "sk.family"))
            .then_some(projection)
        })
        .expect("sk.family projection should be present");
    assert_eq!(
        sk_family
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "5.1"
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

fn projection_absent(projections: &[SpecContextProjection], path: &str) {
    assert!(
        !projections.iter().any(|projection| projection.path == path),
        "did not expect {path} in spec context projections"
    );
}

#[test]
fn test_spec_record_includes_registry_shape_metadata() {
    let fentry = ProgramSpec::parse("fentry:security_file_open").expect("fentry spec should parse");
    let record = spec_record(
        "fentry:security_file_open".to_string(),
        fentry,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");

    let aliases = record
        .get("spec_aliases")
        .expect("spec aliases should be present")
        .as_list()
        .expect("spec aliases should be a list")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("spec aliases should contain strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(aliases, vec!["fentry", "fentry.s"]);
    assert_eq!(
        record
            .get("section_prefix")
            .expect("section prefix should be present")
            .as_str()
            .expect("section prefix should be a string"),
        "fentry"
    );
    assert!(
        record
            .get("section_uses_target")
            .expect("section target policy should be present")
            .as_bool()
            .expect("section target policy should be a bool")
    );
    assert_eq!(
        record
            .get("kernel_target_validation")
            .expect("kernel target validation should be present")
            .as_str()
            .expect("kernel target validation should be a string"),
        "fentry-trampoline"
    );
    assert_eq!(
        record
            .get("btf_callable_surface")
            .expect("BTF callable surface should be present")
            .as_str()
            .expect("BTF callable surface should be a string"),
        "function-trampoline"
    );
    assert!(
        !record
            .get("sleepable")
            .expect("sleepable flag should be present")
            .as_bool()
            .expect("sleepable flag should be a bool")
    );

    let sleepable_fentry =
        ProgramSpec::parse("fentry.s:security_file_open").expect("sleepable fentry spec");
    let record = spec_record(
        "fentry.s:security_file_open".to_string(),
        sleepable_fentry,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    assert!(
        record
            .get("sleepable")
            .expect("sleepable flag should be present")
            .as_bool()
            .expect("sleepable flag should be a bool")
    );
    assert_eq!(
        record
            .get("section")
            .expect("section should be present")
            .as_str()
            .expect("section should be a string"),
        "fentry.s/security_file_open"
    );

    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    assert!(
        !record
            .get("section_uses_target")
            .expect("section target policy should be present")
            .as_bool()
            .expect("section target policy should be a bool")
    );
    assert!(
        record
            .get("kernel_target_validation")
            .expect("kernel target validation should be present")
            .is_nothing()
    );
    assert!(
        record
            .get("btf_callable_surface")
            .expect("BTF callable surface should be present")
            .is_nothing()
    );
}

#[test]
fn test_spec_record_includes_intrinsic_command_metadata() {
    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let intrinsics = record
        .get("intrinsics")
        .expect("intrinsics should be present")
        .as_list()
        .expect("intrinsics should be a list");

    let commands = intrinsics
        .iter()
        .map(|intrinsic| {
            intrinsic
                .as_record()
                .expect("intrinsic should be a record")
                .get("command")
                .expect("intrinsic command should be present")
                .as_str()
                .expect("intrinsic command should be a string")
                .to_string()
        })
        .collect::<Vec<_>>();

    assert!(commands.contains(&"helper-call".to_string()));
    assert!(commands.contains(&"kfunc-call".to_string()));
    assert!(commands.contains(&"map-get".to_string()));
    assert!(commands.contains(&"global-get".to_string()));
    assert!(!commands.contains(&"read-str".to_string()));
    assert!(commands.contains(&"adjust-packet".to_string()));
    assert!(commands.contains(&"redirect".to_string()));
    assert!(commands.contains(&"redirect-map".to_string()));
    assert!(!commands.contains(&"adjust-message".to_string()));
    assert!(!commands.contains(&"redirect-socket".to_string()));
    assert!(!commands.contains(&"assign-socket".to_string()));

    let kfunc = intrinsics
        .iter()
        .find_map(|intrinsic| {
            let intrinsic = intrinsic.as_record().ok()?;
            (intrinsic
                .get("command")?
                .as_str()
                .ok()
                .is_some_and(|command| command == "kfunc-call"))
            .then_some(intrinsic)
        })
        .expect("kfunc-call intrinsic should be present");
    assert_eq!(
        kfunc
            .get("capability")
            .expect("intrinsic capability should be present")
            .as_str()
            .expect("intrinsic capability should be a string"),
        "kfunc-calls"
    );
    assert_eq!(
        kfunc
            .get("capability_description")
            .expect("intrinsic capability description should be present")
            .as_str()
            .expect("intrinsic capability description should be a string"),
        "kfunc calls"
    );
}

#[test]
fn test_spec_record_intrinsics_follow_program_specific_helper_surfaces() {
    let sk_msg = intrinsic_commands("sk_msg:/sys/fs/bpf/demo_sockmap");
    assert!(sk_msg.contains(&"adjust-message".to_string()));
    assert!(sk_msg.contains(&"redirect-socket".to_string()));
    assert!(!sk_msg.contains(&"adjust-packet".to_string()));
    assert!(!sk_msg.contains(&"redirect-map".to_string()));

    let tc_ingress = intrinsic_commands("tc:lo:ingress");
    assert!(tc_ingress.contains(&"adjust-packet".to_string()));
    assert!(tc_ingress.contains(&"redirect".to_string()));
    assert!(tc_ingress.contains(&"assign-socket".to_string()));

    let tc_egress = intrinsic_commands("tc:lo:egress");
    assert!(tc_egress.contains(&"adjust-packet".to_string()));
    assert!(tc_egress.contains(&"redirect".to_string()));
    assert!(!tc_egress.contains(&"assign-socket".to_string()));

    let tcx_ingress = intrinsic_commands("tcx:lo:ingress");
    assert!(tcx_ingress.contains(&"assign-socket".to_string()));

    let tcx_egress = intrinsic_commands("tcx:lo:egress");
    assert!(!tcx_egress.contains(&"assign-socket".to_string()));

    let tc_action = intrinsic_commands("tc_action:diff-action");
    assert!(tc_action.contains(&"assign-socket".to_string()));

    let netkit = intrinsic_commands("netkit:lo:primary");
    assert!(!netkit.contains(&"assign-socket".to_string()));

    let sk_lookup = intrinsic_commands("sk_lookup:/proc/self/ns/net");
    assert!(sk_lookup.contains(&"assign-socket".to_string()));

    let raw_tracepoint = intrinsic_commands("raw_tracepoint:sys_enter");
    assert!(raw_tracepoint.contains(&"helper-call".to_string()));
    assert!(!raw_tracepoint.contains(&"adjust-message".to_string()));
    assert!(!raw_tracepoint.contains(&"redirect".to_string()));
    assert!(!raw_tracepoint.contains(&"redirect-map".to_string()));
}

#[test]
fn test_spec_record_intrinsics_include_backing_helper_metadata() {
    assert_eq!(
        intrinsic_backing_helper_names("xdp:lo", "adjust-packet"),
        vec![
            "bpf_xdp_adjust_head".to_string(),
            "bpf_xdp_adjust_meta".to_string(),
            "bpf_xdp_adjust_tail".to_string(),
        ]
    );
    assert_eq!(
        intrinsic_backing_helper_names("xdp:lo", "redirect-map"),
        vec!["bpf_redirect_map".to_string()]
    );

    assert_eq!(
        intrinsic_backing_helper_names("xdp:lo", "redirect"),
        vec!["bpf_redirect".to_string()]
    );
    let tc_ingress_redirect = intrinsic_backing_helper_names("tc:lo:ingress", "redirect");
    assert!(tc_ingress_redirect.contains(&"bpf_redirect".to_string()));
    assert!(tc_ingress_redirect.contains(&"bpf_redirect_peer".to_string()));
    assert!(tc_ingress_redirect.contains(&"bpf_redirect_neigh".to_string()));

    let tc_egress_redirect = intrinsic_backing_helper_names("tc:lo:egress", "redirect");
    assert!(tc_egress_redirect.contains(&"bpf_redirect".to_string()));
    assert!(!tc_egress_redirect.contains(&"bpf_redirect_peer".to_string()));
    assert!(tc_egress_redirect.contains(&"bpf_redirect_neigh".to_string()));

    let tc_action_redirect = intrinsic_backing_helper_names("tc_action:diff-action", "redirect");
    assert!(tc_action_redirect.contains(&"bpf_redirect".to_string()));
    assert!(tc_action_redirect.contains(&"bpf_redirect_peer".to_string()));
    assert!(tc_action_redirect.contains(&"bpf_redirect_neigh".to_string()));

    assert_eq!(
        intrinsic_backing_helper_names("tc:lo:ingress", "assign-socket"),
        vec!["bpf_sk_assign".to_string()]
    );
    assert_eq!(
        intrinsic_backing_helper_names("tc_action:diff-action", "assign-socket"),
        vec!["bpf_sk_assign".to_string()]
    );
    assert_eq!(
        intrinsic_backing_helper_names("sk_lookup:/proc/self/ns/net", "assign-socket"),
        vec!["bpf_sk_assign".to_string()]
    );
    let tc_map_contains = intrinsic_backing_helper_names("tc:lo:ingress", "map-contains");
    assert!(tc_map_contains.contains(&"bpf_map_lookup_elem".to_string()));
    assert!(tc_map_contains.contains(&"bpf_map_peek_elem".to_string()));
    assert!(tc_map_contains.contains(&"bpf_skb_under_cgroup".to_string()));
    assert!(!tc_map_contains.contains(&"bpf_current_task_under_cgroup".to_string()));

    let xdp_map_contains = intrinsic_backing_helper_names("xdp:lo", "map-contains");
    assert!(xdp_map_contains.contains(&"bpf_current_task_under_cgroup".to_string()));
    assert!(!xdp_map_contains.contains(&"bpf_skb_under_cgroup".to_string()));

    let sock_ops_map_put = intrinsic_backing_helper_names("sock_ops:/sys/fs/cgroup", "map-put");
    assert!(sock_ops_map_put.contains(&"bpf_map_update_elem".to_string()));
    assert!(sock_ops_map_put.contains(&"bpf_sock_map_update".to_string()));
    assert!(sock_ops_map_put.contains(&"bpf_sock_hash_update".to_string()));

    assert_eq!(
        intrinsic_backing_helper_names("sk_msg:/sys/fs/bpf/demo_sockmap", "redirect-socket"),
        vec![
            "bpf_msg_redirect_map".to_string(),
            "bpf_msg_redirect_hash".to_string(),
        ]
    );
    assert_eq!(
        intrinsic_backing_helper_names("raw_tracepoint:sys_enter", "helper-call"),
        Vec::<String>::new()
    );

    let (redirect_map_minimum, redirect_map_source) =
        intrinsic_backing_helper_kernel_floor("xdp:lo", "redirect-map", "bpf_redirect_map");
    assert_eq!(redirect_map_minimum, "4.14");
    assert!(
        redirect_map_source.contains("include/uapi/linux/bpf.h"),
        "{redirect_map_source}"
    );

    let (assign_socket_minimum, assign_socket_source) =
        intrinsic_backing_helper_kernel_floor("tc:lo:ingress", "assign-socket", "bpf_sk_assign");
    assert_eq!(assign_socket_minimum, "5.7");
    assert!(
        assign_socket_source.contains("include/uapi/linux/bpf.h"),
        "{assign_socket_source}"
    );
}

#[test]
fn test_spec_record_intrinsics_include_mode_and_kind_variants() {
    assert_eq!(
        intrinsic_variant_entries("xdp:lo", "adjust-packet"),
        vec![
            (
                "flag".to_string(),
                "head".to_string(),
                "bpf_xdp_adjust_head".to_string(),
            ),
            (
                "flag".to_string(),
                "meta".to_string(),
                "bpf_xdp_adjust_meta".to_string(),
            ),
            (
                "flag".to_string(),
                "tail".to_string(),
                "bpf_xdp_adjust_tail".to_string(),
            ),
        ]
    );

    let tc_adjust = intrinsic_variant_entries("tc:lo:ingress", "adjust-packet");
    assert!(tc_adjust.contains(&(
        "flag".to_string(),
        "head".to_string(),
        "bpf_skb_change_head".to_string()
    )));
    assert!(tc_adjust.contains(&(
        "flag".to_string(),
        "tail".to_string(),
        "bpf_skb_change_tail".to_string()
    )));
    assert!(tc_adjust.contains(&(
        "flag".to_string(),
        "pull".to_string(),
        "bpf_skb_pull_data".to_string()
    )));
    assert!(tc_adjust.contains(&(
        "flag".to_string(),
        "room".to_string(),
        "bpf_skb_adjust_room".to_string()
    )));
    assert!(!tc_adjust.iter().any(|(_, value, _)| value == "meta"));

    assert_eq!(
        intrinsic_variant_entries("lwt_in:demo-route", "adjust-packet"),
        vec![(
            "flag".to_string(),
            "pull".to_string(),
            "bpf_skb_pull_data".to_string(),
        )]
    );

    assert_eq!(
        intrinsic_variant_entries("sk_msg:/sys/fs/bpf/demo_sockmap", "adjust-message"),
        vec![
            (
                "flag".to_string(),
                "apply".to_string(),
                "bpf_msg_apply_bytes".to_string(),
            ),
            (
                "flag".to_string(),
                "cork".to_string(),
                "bpf_msg_cork_bytes".to_string(),
            ),
            (
                "flag".to_string(),
                "pull".to_string(),
                "bpf_msg_pull_data".to_string(),
            ),
            (
                "flag".to_string(),
                "push".to_string(),
                "bpf_msg_push_data".to_string(),
            ),
            (
                "flag".to_string(),
                "pop".to_string(),
                "bpf_msg_pop_data".to_string(),
            ),
        ]
    );

    let tc_egress_redirect = intrinsic_variant_entries("tc:lo:egress", "redirect");
    assert!(tc_egress_redirect.contains(&(
        "default".to_string(),
        "default".to_string(),
        "bpf_redirect".to_string()
    )));
    assert!(tc_egress_redirect.contains(&(
        "flag".to_string(),
        "neigh".to_string(),
        "bpf_redirect_neigh".to_string()
    )));
    assert!(
        !tc_egress_redirect
            .iter()
            .any(|(_, value, _)| value == "peer")
    );

    assert_eq!(
        intrinsic_variant_entries("sk_skb:/sys/fs/bpf/demo_sockmap", "redirect-socket"),
        vec![
            (
                "kind".to_string(),
                "sockmap".to_string(),
                "bpf_sk_redirect_map".to_string(),
            ),
            (
                "kind".to_string(),
                "sockhash".to_string(),
                "bpf_sk_redirect_hash".to_string(),
            ),
        ]
    );
    assert_eq!(
        intrinsic_variant_entries("sk_reuseport:select", "redirect-socket"),
        vec![(
            "kind".to_string(),
            "reuseport-sockarray".to_string(),
            "bpf_sk_select_reuseport".to_string(),
        )]
    );
}

#[test]
fn test_spec_record_includes_compatibility_requirement_metadata() {
    let spec = ProgramSpec::parse("netfilter:ipv4:pre_routing:priority=-100:defrag")
        .expect("netfilter spec should parse");
    let record = spec_record(
        "netfilter:ipv4:pre_routing:priority=-100:defrag".to_string(),
        spec,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");
    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "6.6"
    );
    assert_eq!(
        record
            .get("compatibility_default_test_lane")
            .expect("compatibility default test lane should be present")
            .as_str()
            .expect("compatibility default test lane should be a string"),
        "vm-only"
    );
    assert!(
        record
            .get("compatibility_default_test_lane_description")
            .expect("compatibility default test lane description should be present")
            .as_str()
            .expect("compatibility default test lane description should be a string")
            .contains("isolated VM")
    );
    let link_requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "netfilter-link"))
            .then_some(requirement)
        })
        .expect("netfilter-link requirement should be present");

    assert_eq!(
        link_requirement
            .get("category")
            .expect("requirement category should be present")
            .as_str()
            .expect("requirement category should be a string"),
        "program-feature"
    );
    assert_eq!(
        link_requirement
            .get("default_test_lane")
            .expect("requirement test lane should be present")
            .as_str()
            .expect("requirement test lane should be a string"),
        "vm-only"
    );
    assert!(
        link_requirement
            .get("default_test_lane_description")
            .expect("requirement test lane description should be present")
            .as_str()
            .expect("requirement test lane description should be a string")
            .contains("isolated VM")
    );
    assert!(
        link_requirement
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string")
            == "6.4"
    );
    assert_eq!(
        link_requirement
            .get("minimum_kernel_source")
            .expect("minimum kernel source should be present")
            .as_str()
            .expect("minimum kernel source should be a string"),
        "https://github.com/torvalds/linux/blob/v6.4/include/uapi/linux/bpf.h"
    );

    let defrag_requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "netfilter-defrag"))
            .then_some(requirement)
        })
        .expect("netfilter-defrag requirement should be present");

    assert_eq!(
        defrag_requirement
            .get("category")
            .expect("defrag requirement category should be present")
            .as_str()
            .expect("defrag requirement category should be a string"),
        "attach-mode"
    );
    assert_eq!(
        defrag_requirement
            .get("default_test_lane")
            .expect("defrag requirement test lane should be present")
            .as_str()
            .expect("defrag requirement test lane should be a string"),
        "host-gated"
    );
    assert_eq!(
        defrag_requirement
            .get("minimum_kernel")
            .expect("defrag minimum kernel should be present")
            .as_str()
            .expect("defrag minimum kernel should be a string"),
        "6.6"
    );
    assert_eq!(
        defrag_requirement
            .get("minimum_kernel_source")
            .expect("defrag minimum kernel source should be present")
            .as_str()
            .expect("defrag minimum kernel source should be a string"),
        "https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/bpf.h"
    );
}

#[test]
fn test_spec_record_includes_iterator_target_compatibility_metadata() {
    let spec = ProgramSpec::parse("iter:bpf_link").expect("iter bpf_link spec should parse");
    let record = spec_record("iter:bpf_link".to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");

    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "5.19"
    );

    let requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "bpf-iterator-target-bpf-link"))
            .then_some(requirement)
        })
        .expect("bpf_link iterator target requirement should be present");

    assert_eq!(
        requirement
            .get("category")
            .expect("requirement category should be present")
            .as_str()
            .expect("requirement category should be a string"),
        "iterator-target"
    );
    assert_eq!(
        requirement
            .get("minimum_kernel_source")
            .expect("minimum kernel source should be present")
            .as_str()
            .expect("minimum kernel source should be a string"),
        "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c"
    );
}

#[test]
fn test_spec_context_fields_include_netfilter_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("netfilter:ipv4:pre_routing:priority=-100:defrag")
        .expect("netfilter spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in ["state", "skb", "hook", "pf"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("6.4"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v6.4/net/netfilter/nf_bpf_link.c"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_lirc_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("lirc_mode2:/dev/lirc0").expect("lirc spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in ["sample", "value", "mode"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.18"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.18/drivers/media/rc/bpf-lirc.c"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_perf_event_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("perf_event:software:cpu-clock:period=100000")
        .expect("perf_event spec should parse");
    let fields = spec_context_fields(&spec, false);

    let sample_period = field(&fields, "sample_period");
    assert_eq!(sample_period.minimum_kernel, Some("4.9"));
    assert!(
        sample_period
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.9/include/uapi/linux/bpf_perf_event.h"))
    );

    let addr = field(&fields, "addr");
    assert_eq!(addr.minimum_kernel, Some("5.0"));
    assert!(
        addr.minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.0/include/uapi/linux/bpf_perf_event.h"))
    );
}

#[test]
fn test_spec_context_fields_include_cgroup_device_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("cgroup_device:/sys/fs/cgroup")
        .expect("cgroup_device spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in [
        "access_type",
        "device_access",
        "device_type",
        "major",
        "minor",
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.15"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.15/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_cgroup_sysctl_direct_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("cgroup_sysctl:/sys/fs/cgroup")
        .expect("cgroup_sysctl spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in ["write", "file_pos"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("5.2"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.2/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_cgroup_sockopt_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("cgroup_sockopt:/sys/fs/cgroup:get")
        .expect("cgroup_sockopt spec should parse");
    let fields = spec_context_fields(&spec, false);

    let socket = field(&fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("5.3"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.3/include/uapi/linux/bpf.h"))
    );

    for field_name in [
        "level",
        "optname",
        "optlen",
        "optval",
        "optval_end",
        "sockopt_retval",
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("5.3"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.3/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_cgroup_sock_addr_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg6")
        .expect("cgroup_sock_addr spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in [
        "user_family",
        "user_ip6",
        "user_port",
        "family",
        "sock_type",
        "protocol",
        "remote_ip6",
        "remote_port",
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.17"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.17/include/uapi/linux/bpf.h"))
        );
    }

    let msg_src_ip6 = field(&fields, "msg_src_ip6");
    assert_eq!(msg_src_ip6.minimum_kernel, Some("4.18"));
    assert!(
        msg_src_ip6
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.18/include/uapi/linux/bpf.h"))
    );

    let socket = field(&fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("5.3"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.3/include/uapi/linux/bpf.h"))
    );
}

#[test]
fn test_spec_context_fields_include_cgroup_sock_minimum_kernel_metadata() {
    let create = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let create_fields = spec_context_fields(&create, false);

    for field_name in ["bound_dev_if", "family", "sock_type", "protocol"] {
        let field = field(&create_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.10"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.10/include/uapi/linux/bpf.h"))
        );
    }

    let socket = field(&create_fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("4.10"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.10/include/uapi/linux/bpf.h"))
    );

    for field_name in ["mark", "priority"] {
        let field = field(&create_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.14"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.14/include/uapi/linux/bpf.h"))
        );
    }

    let post_bind = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:post_bind6")
        .expect("cgroup_sock post_bind spec should parse");
    let post_bind_fields = spec_context_fields(&post_bind, false);

    for field_name in ["local_ip6", "local_port"] {
        let field = field(&post_bind_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.17"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.17/include/uapi/linux/bpf.h"))
        );
    }

    for field_name in ["remote_ip6", "remote_port", "state"] {
        let field = field(&post_bind_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("5.1"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.1/include/uapi/linux/bpf.h"))
        );
    }

    let rx_queue_mapping = field(&post_bind_fields, "rx_queue_mapping");
    assert_eq!(rx_queue_mapping.minimum_kernel, Some("5.8"));
    assert!(
        rx_queue_mapping
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.8/include/uapi/linux/bpf.h"))
    );
}

#[test]
fn test_spec_context_fields_include_sk_lookup_minimum_kernel_metadata() {
    let spec =
        ProgramSpec::parse("sk_lookup:/proc/self/ns/net").expect("sk_lookup spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in [
        "family",
        "protocol",
        "remote_ip4",
        "remote_ip6",
        "remote_port",
        "local_ip4",
        "local_ip6",
        "local_port",
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("5.9"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.9/include/uapi/linux/bpf.h"))
        );
    }

    let cookie = field(&fields, "cookie");
    assert_eq!(cookie.minimum_kernel, Some("5.13"));
    assert!(
        cookie
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.13/include/uapi/linux/bpf.h"))
    );

    let ingress_ifindex = field(&fields, "ingress_ifindex");
    assert_eq!(ingress_ifindex.minimum_kernel, Some("5.17"));
    assert!(
        ingress_ifindex
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.17/include/uapi/linux/bpf.h"))
    );

    let socket = field(&fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("5.9"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.9/include/uapi/linux/bpf.h"))
    );
}

#[test]
fn test_spec_context_fields_include_sk_msg_minimum_kernel_metadata() {
    let spec =
        ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap").expect("sk_msg spec should parse");
    let fields = spec_context_fields(&spec, false);

    for field_name in ["data", "data_end"] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.17"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.17/include/uapi/linux/bpf.h"))
        );
    }

    for field_name in [
        "family",
        "remote_ip4",
        "remote_ip6",
        "remote_port",
        "local_ip4",
        "local_ip6",
        "local_port",
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.18"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.18/include/uapi/linux/bpf.h"))
        );
    }

    let packet_len = field(&fields, "packet_len");
    assert!(packet_len.names.contains(&"size"));
    assert_eq!(packet_len.minimum_kernel, Some("5.0"));
    assert!(
        packet_len
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.0/include/uapi/linux/bpf.h"))
    );

    let socket = field(&fields, "sk");
    assert_eq!(socket.minimum_kernel, Some("5.8"));
    assert!(
        socket
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.8/include/uapi/linux/bpf.h"))
    );
}

#[test]
fn test_spec_context_fields_include_sk_skb_socket_minimum_kernel_metadata() {
    for spec_text in [
        "sk_skb:/sys/fs/bpf/demo_sockmap",
        "sk_skb_parser:/sys/fs/bpf/demo_sockmap",
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("sk_skb spec should parse");
        let fields = spec_context_fields(&spec, false);
        let socket = field(&fields, "sk");

        assert_eq!(socket.minimum_kernel, Some("5.1"));
        assert!(
            socket
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.1/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_skb_backed_socket_minimum_kernel_metadata() {
    for spec_text in [
        "socket_filter:udp4:127.0.0.1:31337",
        "tc_action:demo-action",
        "tc:lo:ingress",
        "tcx:lo:ingress",
        "netkit:lo:primary",
        "cgroup_skb:/sys/fs/cgroup:egress",
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("skb-backed spec should parse");
        let fields = spec_context_fields(&spec, false);
        let socket = field(&fields, "sk");

        assert_eq!(socket.minimum_kernel, Some("5.1"));
        assert!(
            socket
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.1/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_context_fields_include_iterator_minimum_kernel_metadata() {
    for (spec_text, field_name, minimum_kernel, source_fragment) in [
        ("iter:task", "iter_meta", "5.8", "/v5.8/include/linux/bpf.h"),
        (
            "iter:task",
            "iter_task",
            "5.8",
            "/v5.8/kernel/bpf/task_iter.c",
        ),
        (
            "iter:task_vma",
            "iter_task",
            "5.12",
            "/v5.12/kernel/bpf/task_iter.c",
        ),
        (
            "iter:task_vma",
            "iter_vma",
            "5.12",
            "/v5.12/kernel/bpf/task_iter.c",
        ),
        (
            "iter:cgroup",
            "iter_cgroup",
            "6.1",
            "/v6.1/kernel/bpf/cgroup_iter.c",
        ),
        (
            "iter:bpf_link",
            "iter_link",
            "5.19",
            "/v5.19/kernel/bpf/link_iter.c",
        ),
        (
            "iter:sockmap",
            "iter_key",
            "5.10",
            "/v5.10/net/core/sock_map.c",
        ),
        (
            "iter:unix",
            "iter_unix_sk",
            "5.15",
            "/v5.15/net/unix/af_unix.c",
        ),
        ("iter:ksym", "iter_ksym", "6.0", "/v6.0/kernel/kallsyms.c"),
        (
            "iter:kmem_cache",
            "iter_kmem_cache",
            "6.13",
            "/v6.13/kernel/bpf/kmem_cache_iter.c",
        ),
        (
            "iter:dmabuf",
            "iter_dmabuf",
            "6.16",
            "/v6.16/kernel/bpf/dmabuf_iter.c",
        ),
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("iter spec should parse");
        let fields = spec_context_fields(&spec, false);
        let field = field(&fields, field_name);

        assert_eq!(field.minimum_kernel, Some(minimum_kernel));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains(source_fragment)),
            "ctx.{field_name} on {spec_text} should point at {source_fragment}"
        );
    }
}

#[test]
fn test_spec_context_fields_include_sk_reuseport_minimum_kernel_metadata() {
    let select =
        ProgramSpec::parse("sk_reuseport:select").expect("sk_reuseport select spec should parse");
    let select_fields = spec_context_fields(&select, false);

    for field_name in [
        "data",
        "data_end",
        "packet_len",
        "eth_protocol",
        "protocol",
        "bind_inany",
        "hash",
    ] {
        let field = field(&select_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("4.19"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v4.19/include/uapi/linux/bpf.h"))
        );
    }

    let migrate =
        ProgramSpec::parse("sk_reuseport:migrate").expect("sk_reuseport migrate spec should parse");
    let migrate_fields = spec_context_fields(&migrate, false);

    for field_name in ["sk", "migrating_sk"] {
        let field = field(&migrate_fields, field_name);
        assert_eq!(field.minimum_kernel, Some("5.14"));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains("/v5.14/include/uapi/linux/bpf.h"))
        );
    }
}

#[test]
fn test_spec_record_reports_target_specific_cgroup_unix_minimum() {
    let spec = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("cgroup unix socket-address spec should parse");
    let record = spec_record(
        "cgroup_sock_addr:/sys/fs/cgroup:connect_unix".to_string(),
        spec,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");

    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "6.7"
    );

    let requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "cgroup-unix-sock-addr"))
            .then_some(requirement)
        })
        .expect("cgroup unix requirement should be present");

    assert_eq!(
        requirement
            .get("category")
            .expect("requirement category should be present")
            .as_str()
            .expect("requirement category should be a string"),
        "attach-mode"
    );
    assert_eq!(
        requirement
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "6.7"
    );
    assert_eq!(
        requirement
            .get("minimum_kernel_source")
            .expect("minimum kernel source should be present")
            .as_str()
            .expect("minimum kernel source should be a string"),
        "https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/bpf.h"
    );
}

#[test]
fn test_spec_record_reports_base_program_minimum() {
    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let record = spec_record("xdp:lo".to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");

    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "4.12"
    );

    let requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "xdp-program"))
            .then_some(requirement)
        })
        .expect("xdp base program requirement should be present");

    assert_eq!(
        requirement
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "4.8"
    );

    let attach_requirement = requirements
        .iter()
        .find_map(|requirement| {
            let requirement = requirement.as_record().ok()?;
            (requirement
                .get("key")?
                .as_str()
                .ok()
                .is_some_and(|key| key == "xdp-attach-skb"))
            .then_some(requirement)
        })
        .expect("xdp skb attach-mode requirement should be present");

    assert_eq!(
        attach_requirement
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "4.12"
    );

    let spec = ProgramSpec::parse("xdp:cpumap").expect("xdp cpumap spec should parse");
    let record = spec_record("xdp:cpumap".to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");

    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "5.9"
    );
    assert!(
        requirements.iter().any(|requirement| {
            requirement
                .as_record()
                .ok()
                .and_then(|requirement| requirement.get("key"))
                .and_then(|key| key.as_str().ok())
                .is_some_and(|key| key == "xdp-attach-cpumap")
        }),
        "xdp cpumap attach-mode requirement should be present"
    );
}

#[test]
fn test_spec_record_includes_attach_shape_metadata() {
    let xdp = ProgramSpec::parse("xdp:lo:drv:frags").expect("xdp frags spec should parse");
    let record = spec_record(
        "xdp:lo:drv:frags".to_string(),
        xdp,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "xdp"
    );
    assert_eq!(
        attach_shape
            .get("target_kind")
            .expect("xdp target kind should be present")
            .as_str()
            .expect("xdp target kind should be a string"),
        "interface"
    );
    assert_eq!(
        attach_shape
            .get("mode")
            .expect("xdp mode should be present")
            .as_str()
            .expect("xdp mode should be a string"),
        "drv"
    );
    assert!(
        attach_shape
            .get("frags")
            .expect("xdp frags should be present")
            .as_bool()
            .expect("xdp frags should be a bool")
    );

    let xdp_devmap = ProgramSpec::parse("xdp:devmap").expect("xdp devmap spec should parse");
    let record = spec_record(
        "xdp:devmap".to_string(),
        xdp_devmap,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    assert_eq!(
        record
            .get("target_kind")
            .expect("target kind should be present")
            .as_str()
            .expect("target kind should be a string"),
        "xdp-secondary-program"
    );
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("target_kind")
            .expect("xdp target kind should be present")
            .as_str()
            .expect("xdp target kind should be a string"),
        "devmap"
    );

    let perf_event = ProgramSpec::parse("perf_event:hardware:instructions:cpu=2:pid=42:freq=99")
        .expect("perf_event spec should parse");
    let record = spec_record(
        "perf_event:hardware:instructions:cpu=2:pid=42:freq=99".to_string(),
        perf_event,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "perf-event"
    );
    assert_eq!(
        attach_shape
            .get("source")
            .expect("perf_event source should be present")
            .as_str()
            .expect("perf_event source should be a string"),
        "hardware"
    );
    assert_eq!(
        attach_shape
            .get("event")
            .expect("perf_event selector should be present")
            .as_str()
            .expect("perf_event selector should be a string"),
        "instructions"
    );
    assert_eq!(
        attach_shape
            .get("cpu")
            .expect("perf_event cpu should be present")
            .as_int()
            .expect("perf_event cpu should be an int"),
        2
    );
    assert_eq!(
        attach_shape
            .get("pid")
            .expect("perf_event pid should be present")
            .as_int()
            .expect("perf_event pid should be an int"),
        42
    );
    assert_eq!(
        attach_shape
            .get("sample_policy")
            .expect("perf_event sample policy should be present")
            .as_str()
            .expect("perf_event sample policy should be a string"),
        "freq"
    );
    assert_eq!(
        attach_shape
            .get("sample_value")
            .expect("perf_event sample value should be present")
            .as_int()
            .expect("perf_event sample value should be an int"),
        99
    );
    assert!(
        !attach_shape
            .get("default_sample")
            .expect("perf_event default sample should be present")
            .as_bool()
            .expect("perf_event default sample should be a bool")
    );

    let socket_filter = ProgramSpec::parse("socket_filter:tcp6:[::1]:8080")
        .expect("socket_filter spec should parse");
    let record = spec_record(
        "socket_filter:tcp6:[::1]:8080".to_string(),
        socket_filter,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "socket-filter"
    );
    assert_eq!(
        attach_shape
            .get("socket_kind")
            .expect("socket_filter socket kind should be present")
            .as_str()
            .expect("socket_filter socket kind should be a string"),
        "tcp6"
    );
    assert_eq!(
        attach_shape
            .get("transport")
            .expect("socket_filter transport should be present")
            .as_str()
            .expect("socket_filter transport should be a string"),
        "tcp"
    );
    assert_eq!(
        attach_shape
            .get("family")
            .expect("socket_filter family should be present")
            .as_str()
            .expect("socket_filter family should be a string"),
        "ipv6"
    );

    let tc = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
    let record = spec_record("tc:lo:egress".to_string(), tc, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "tc"
    );
    assert_eq!(
        attach_shape
            .get("direction")
            .expect("tc direction should be present")
            .as_str()
            .expect("tc direction should be a string"),
        "egress"
    );
    assert!(
        !attach_shape
            .get("ingress")
            .expect("tc ingress should be present")
            .as_bool()
            .expect("tc ingress should be a bool")
    );

    let netkit = ProgramSpec::parse("netkit:nk0:peer").expect("netkit spec should parse");
    let record = spec_record(
        "netkit:nk0:peer".to_string(),
        netkit,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "netkit"
    );
    assert_eq!(
        attach_shape
            .get("endpoint")
            .expect("netkit endpoint should be present")
            .as_str()
            .expect("netkit endpoint should be a string"),
        "peer"
    );
    assert!(
        !attach_shape
            .get("primary")
            .expect("netkit primary should be present")
            .as_bool()
            .expect("netkit primary should be a bool")
    );

    let sk_reuseport =
        ProgramSpec::parse("sk_reuseport:migrate").expect("sk_reuseport spec should parse");
    let record = spec_record(
        "sk_reuseport:migrate".to_string(),
        sk_reuseport,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "sk-reuseport"
    );
    assert_eq!(
        attach_shape
            .get("mode")
            .expect("sk_reuseport mode should be present")
            .as_str()
            .expect("sk_reuseport mode should be a string"),
        "migrate"
    );

    let lwt = ProgramSpec::parse("lwt_seg6local:demo-route").expect("lwt spec should parse");
    let record = spec_record(
        "lwt_seg6local:demo-route".to_string(),
        lwt,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "lwt"
    );
    assert_eq!(
        attach_shape
            .get("hook")
            .expect("lwt hook should be present")
            .as_str()
            .expect("lwt hook should be a string"),
        "seg6local"
    );

    let netfilter = ProgramSpec::parse("netfilter:ipv6:local_out:priority=-100:defrag")
        .expect("netfilter spec should parse");
    let record = spec_record(
        "netfilter:ipv6:local_out:priority=-100:defrag".to_string(),
        netfilter,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "netfilter"
    );
    assert_eq!(
        attach_shape
            .get("family")
            .expect("netfilter family should be present")
            .as_str()
            .expect("netfilter family should be a string"),
        "ipv6"
    );
    assert_eq!(
        attach_shape
            .get("hook")
            .expect("netfilter hook should be present")
            .as_str()
            .expect("netfilter hook should be a string"),
        "local_out"
    );
    assert_eq!(
        attach_shape
            .get("priority")
            .expect("netfilter priority should be present")
            .as_int()
            .expect("netfilter priority should be an int"),
        -100
    );
    assert!(
        attach_shape
            .get("defrag")
            .expect("netfilter defrag should be present")
            .as_bool()
            .expect("netfilter defrag should be a bool")
    );

    let sock_addr = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg6")
        .expect("cgroup sock addr spec should parse");
    let record = spec_record(
        "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6".to_string(),
        sock_addr,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "cgroup-sock-addr"
    );
    assert_eq!(
        attach_shape
            .get("family")
            .expect("sock addr family should be present")
            .as_str()
            .expect("sock addr family should be a string"),
        "ipv6"
    );
    assert_eq!(
        attach_shape
            .get("hook")
            .expect("sock addr hook should be present")
            .as_str()
            .expect("sock addr hook should be a string"),
        "sendmsg"
    );

    let struct_ops = ProgramSpec::parse("struct_ops:tcp_congestion_ops")
        .expect("struct_ops object spec should parse");
    let record = spec_record(
        "struct_ops:tcp_congestion_ops".to_string(),
        struct_ops,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        record
            .get("struct_ops_value_type")
            .expect("struct_ops value type should be present")
            .as_str()
            .expect("struct_ops value type should be a string"),
        "tcp_congestion_ops"
    );
    assert!(
        record
            .get("struct_ops_callback")
            .expect("struct_ops callback should be present")
            .is_nothing()
    );
    assert_eq!(
        attach_shape
            .get("value_type")
            .expect("struct_ops value type should be present")
            .as_str()
            .expect("struct_ops value type should be a string"),
        "tcp_congestion_ops"
    );

    let callback = ProgramSpec::parse("struct_ops:sched_ext_ops.init")
        .expect("struct_ops callback spec should parse");
    let record = spec_record(
        "struct_ops:sched_ext_ops.init".to_string(),
        callback,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        record
            .get("struct_ops_value_type")
            .expect("struct_ops value type should be present")
            .as_str()
            .expect("struct_ops value type should be a string"),
        "sched_ext_ops"
    );
    assert_eq!(
        record
            .get("struct_ops_callback")
            .expect("struct_ops callback should be present")
            .as_str()
            .expect("struct_ops callback should be a string"),
        "init"
    );
    assert_eq!(
        record
            .get("target_kind")
            .expect("target kind should be present")
            .as_str()
            .expect("target kind should be a string"),
        "struct-ops-callback"
    );
    assert_eq!(
        record
            .get("btf_callable_surface")
            .expect("BTF callable surface should be present")
            .as_str()
            .expect("BTF callable surface should be a string"),
        "struct-ops-callback"
    );
    assert_eq!(
        record
            .get("arg_access")
            .expect("arg access should be present")
            .as_str()
            .expect("arg access should be a string"),
        "trampoline"
    );
    assert_eq!(
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string"),
        "struct-ops-callback"
    );
    assert_eq!(
        attach_shape
            .get("family")
            .expect("struct_ops family should be present")
            .as_str()
            .expect("struct_ops family should be a string"),
        "sched-ext"
    );
    assert_eq!(
        attach_shape
            .get("value_type")
            .expect("struct_ops value type should be present")
            .as_str()
            .expect("struct_ops value type should be a string"),
        "sched_ext_ops"
    );
    assert_eq!(
        attach_shape
            .get("callback")
            .expect("struct_ops callback should be present")
            .as_str()
            .expect("struct_ops callback should be a string"),
        "init"
    );
    assert!(
        attach_shape
            .get("sleepable")
            .expect("struct_ops sleepable should be present")
            .as_bool()
            .expect("struct_ops sleepable should be a bool")
    );
    assert!(
        !record
            .get("live_attach_supported")
            .expect("live_attach_supported should be present")
            .as_bool()
            .expect("live_attach_supported should be a bool")
    );
    assert!(
        !record
            .get("live_attach_default_allowed")
            .expect("live_attach_default_allowed should be present")
            .as_bool()
            .expect("live_attach_default_allowed should be a bool")
    );
    assert!(
        !record
            .get("live_attach_requires_opt_in")
            .expect("live_attach_requires_opt_in should be present")
            .as_bool()
            .expect("live_attach_requires_opt_in should be a bool")
    );
    assert!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string")
            .contains("not directly attachable")
    );
}

#[test]
fn test_spec_record_includes_resource_attach_shapes() {
    let shape_kind = |target: &str| {
        let spec = ProgramSpec::parse(target).expect("spec should parse");
        let record = spec_record(target.to_string(), spec, Span::test_data(), false)
            .into_record()
            .expect("spec output should be a record");
        let attach_shape = record
            .get("attach_shape")
            .expect("attach shape should be present")
            .as_record()
            .expect("attach shape should be a record");
        attach_shape
            .get("kind")
            .expect("attach shape kind should be present")
            .as_str()
            .expect("attach shape kind should be a string")
            .to_string()
    };

    assert_eq!(shape_kind("syscall:demo"), "syscall");
    assert_eq!(shape_kind("iter:task"), "iterator");
    assert_eq!(shape_kind("sk_lookup:/proc/self/ns/net"), "sk-lookup");
    assert_eq!(
        shape_kind("flow_dissector:/proc/self/ns/net"),
        "flow-dissector"
    );
    assert_eq!(shape_kind("sk_msg:/sys/fs/bpf/demo_sockmap"), "sk-msg");
    assert_eq!(shape_kind("sk_skb:/sys/fs/bpf/demo_sockmap"), "sk-skb");
    assert_eq!(
        shape_kind("sk_skb_parser:/sys/fs/bpf/demo_sockmap"),
        "sk-skb"
    );
    assert_eq!(shape_kind("tc_action:demo-action"), "tc-action");
    assert_eq!(shape_kind("cgroup_device:/sys/fs/cgroup"), "cgroup-device");
    assert_eq!(shape_kind("cgroup_sysctl:/sys/fs/cgroup"), "cgroup-sysctl");
    assert_eq!(shape_kind("sock_ops:/sys/fs/cgroup"), "sock-ops");
    assert_eq!(shape_kind("lirc_mode2:/dev/lirc0"), "lirc-mode2");
    assert_eq!(shape_kind("struct_ops:sched_ext_ops"), "struct-ops");

    let parser =
        ProgramSpec::parse("sk_skb_parser:/sys/fs/bpf/demo_sockmap").expect("spec should parse");
    let record = spec_record(
        "sk_skb_parser:/sys/fs/bpf/demo_sockmap".to_string(),
        parser,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        attach_shape
            .get("hook")
            .expect("sk_skb hook should be present")
            .as_str()
            .expect("sk_skb hook should be a string"),
        "parser"
    );
    assert!(
        attach_shape
            .get("parser")
            .expect("sk_skb parser flag should be present")
            .as_bool()
            .expect("sk_skb parser flag should be a bool")
    );

    let struct_ops =
        ProgramSpec::parse("struct_ops:tcp_congestion_ops").expect("struct_ops spec should parse");
    let record = spec_record(
        "struct_ops:tcp_congestion_ops".to_string(),
        struct_ops,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let attach_shape = record
        .get("attach_shape")
        .expect("attach shape should be present")
        .as_record()
        .expect("attach shape should be a record");
    assert_eq!(
        record
            .get("target_kind")
            .expect("target kind should be present")
            .as_str()
            .expect("target kind should be a string"),
        "struct-ops-value-type"
    );
    assert!(
        record
            .get("btf_callable_surface")
            .expect("BTF callable surface should be present")
            .is_nothing()
    );
    assert_eq!(
        record
            .get("arg_access")
            .expect("arg access should be present")
            .as_str()
            .expect("arg access should be a string"),
        "none"
    );
    assert_eq!(
        attach_shape
            .get("family")
            .expect("struct_ops family should be present")
            .as_str()
            .expect("struct_ops family should be a string"),
        "tcp-congestion"
    );
    assert_eq!(
        record
            .get("compatibility_minimum_kernel")
            .expect("tcp_congestion_ops compatibility minimum should be present")
            .as_str()
            .expect("compatibility minimum should be a string"),
        "5.6"
    );
    let requirements = record
        .get("compatibility_requirements")
        .expect("compatibility requirements should be present")
        .as_list()
        .expect("compatibility requirements should be a list");
    assert!(
        requirements.iter().any(|requirement| {
            requirement
                .as_record()
                .ok()
                .and_then(|requirement| requirement.get("key"))
                .and_then(|key| key.as_str().ok())
                .is_some_and(|key| key == "tcp-congestion-ops")
        }),
        "tcp_congestion_ops should carry family compatibility metadata"
    );

    for (spec_text, family, requirement_key, minimum_kernel) in [
        ("struct_ops:hid_bpf_ops", "hid-bpf", "hid-bpf-ops", "6.11"),
        ("struct_ops:Qdisc_ops", "qdisc", "qdisc-ops", "6.16"),
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("struct_ops family spec should parse");
        let record = spec_record(spec_text.to_string(), spec, Span::test_data(), false)
            .into_record()
            .expect("spec output should be a record");
        let attach_shape = record
            .get("attach_shape")
            .expect("attach shape should be present")
            .as_record()
            .expect("attach shape should be a record");
        assert_eq!(
            attach_shape
                .get("family")
                .expect("struct_ops family should be present")
                .as_str()
                .expect("struct_ops family should be a string"),
            family
        );
        assert_eq!(
            record
                .get("compatibility_minimum_kernel")
                .expect("compatibility minimum should be present")
                .as_str()
                .expect("compatibility minimum should be a string"),
            minimum_kernel
        );
        let requirements = record
            .get("compatibility_requirements")
            .expect("compatibility requirements should be present")
            .as_list()
            .expect("compatibility requirements should be a list");
        assert!(
            requirements.iter().any(|requirement| {
                requirement
                    .as_record()
                    .ok()
                    .and_then(|requirement| requirement.get("key"))
                    .and_then(|key| key.as_str().ok())
                    .is_some_and(|key| key == requirement_key)
            }),
            "{spec_text} should carry family compatibility metadata"
        );
    }
}

#[test]
fn test_spec_context_projections_include_socket_members() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let projections = spec_context_projections(&spec);

    let family = projection(&projections, "sk.family");
    assert_eq!(family.root, "sk");
    assert_eq!(family.name, "family");
    assert_eq!(family.source, "context_field");
    assert_eq!(family.minimum_kernel, Some("4.10"));
    assert!(
        family
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.10/include/uapi/linux/bpf.h"))
    );
    assert_eq!(family.helper, None);
    assert_eq!(family.ty, "u32");
    assert_eq!(family.offset, Some(4));
    assert!(family.supported);
    assert!(family.unsupported_reason.is_none());

    projection_absent(&projections, "sk.src_ip4");
}

#[test]
fn test_spec_context_projections_include_helper_backed_socket_members() {
    let spec = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
    let projections = spec_context_projections(&spec);

    let tcp_snd_cwnd = projection(&projections, "sk.tcp.snd_cwnd");
    assert_eq!(tcp_snd_cwnd.root, "sk.tcp");
    assert_eq!(tcp_snd_cwnd.name, "snd_cwnd");
    assert_eq!(tcp_snd_cwnd.source, "helper_return");
    assert_eq!(tcp_snd_cwnd.helper, Some("bpf_tcp_sock"));
    assert_eq!(tcp_snd_cwnd.helper_minimum_kernel, Some("5.1"));
    assert!(
        tcp_snd_cwnd
            .helper_minimum_kernel_source
            .is_some_and(|source| source.contains("/v5.1/include/uapi/linux/bpf.h"))
    );
    assert_eq!(tcp_snd_cwnd.ty, "u32");
    assert!(tcp_snd_cwnd.supported);
    assert!(tcp_snd_cwnd.unsupported_reason.is_none());

    let full_family = projection(&projections, "sk.full.family");
    assert_eq!(full_family.helper, Some("bpf_sk_fullsock"));
    assert_eq!(full_family.helper_minimum_kernel, Some("5.1"));
    assert_eq!(full_family.ty, "u32");
    assert!(full_family.supported);
    assert!(full_family.unsupported_reason.is_none());

    let sk_family = projection(&projections, "sk.family");
    assert_eq!(sk_family.minimum_kernel, Some("5.1"));
}

#[test]
fn test_spec_context_projections_respect_attach_sensitive_socket_members() {
    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:post_bind4")
        .expect("cgroup_sock post_bind4 spec should parse");
    let projections = spec_context_projections(&spec);

    let src_ip4 = projection(&projections, "sk.src_ip4");
    assert!(src_ip4.supported);
    assert_eq!(src_ip4.minimum_kernel, Some("4.17"));
    assert!(src_ip4.unsupported_reason.is_none());

    projection_absent(&projections, "sk.src_ip6");
}

#[test]
fn test_spec_context_projections_include_parameterized_helper_members() {
    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let xdp_projections = spec_context_projections(&xdp);
    let current_ancestor = projection(&xdp_projections, "ancestor_cgroup_id.N");
    assert_eq!(current_ancestor.root, "ancestor_cgroup_id");
    assert_eq!(current_ancestor.name, "N");
    assert_eq!(current_ancestor.source, "helper_call");
    assert_eq!(
        current_ancestor.helper,
        Some("bpf_get_current_ancestor_cgroup_id")
    );
    assert_eq!(current_ancestor.helper_minimum_kernel, Some("5.7"));
    assert_eq!(current_ancestor.ty, "u64");
    assert_eq!(current_ancestor.offset, None);
    assert!(current_ancestor.supported);

    let tc_egress = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
    let tc_egress_projections = spec_context_projections(&tc_egress);
    let skb_ancestor = projection(&tc_egress_projections, "skb_ancestor_cgroup_id.N");
    assert_eq!(skb_ancestor.root, "skb_ancestor_cgroup_id");
    assert_eq!(skb_ancestor.helper, Some("bpf_skb_ancestor_cgroup_id"));
    assert_eq!(skb_ancestor.helper_minimum_kernel, Some("4.19"));
    assert_eq!(skb_ancestor.ty, "u64");
    assert_eq!(skb_ancestor.offset, None);

    let cgroup_skb = ProgramSpec::parse("cgroup_skb:/sys/fs/cgroup:egress")
        .expect("cgroup_skb spec should parse");
    let cgroup_skb_projections = spec_context_projections(&cgroup_skb);
    let sk_cgroup = projection(&cgroup_skb_projections, "sk.cgroup_id");
    assert_eq!(sk_cgroup.root, "sk");
    assert_eq!(sk_cgroup.name, "cgroup_id");
    assert_eq!(sk_cgroup.helper, Some("bpf_sk_cgroup_id"));
    assert_eq!(sk_cgroup.helper_minimum_kernel, Some("5.8"));
    assert_eq!(sk_cgroup.ty, "u64");
    assert_eq!(sk_cgroup.offset, None);

    let sk_ancestor = projection(&cgroup_skb_projections, "sk.ancestor_cgroup_id.N");
    assert_eq!(sk_ancestor.root, "sk");
    assert_eq!(sk_ancestor.name, "ancestor_cgroup_id.N");
    assert_eq!(sk_ancestor.helper, Some("bpf_sk_ancestor_cgroup_id"));
    assert_eq!(sk_ancestor.helper_minimum_kernel, Some("5.8"));
    assert_eq!(sk_ancestor.ty, "u64");
    assert_eq!(sk_ancestor.offset, None);

    let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
    let tc_ingress_projections = spec_context_projections(&tc_ingress);
    projection_absent(&tc_ingress_projections, "skb_ancestor_cgroup_id.N");

    let sk_msg =
        ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap").expect("sk_msg spec should parse");
    let sk_msg_projections = spec_context_projections(&sk_msg);
    projection_absent(&sk_msg_projections, "sk.cgroup_id");
    projection_absent(&sk_msg_projections, "sk.ancestor_cgroup_id.N");
}

#[test]
fn test_spec_context_projections_include_task_pt_regs_helper_members() {
    let kprobe = ProgramSpec::parse("kprobe:sys_read").expect("kprobe spec should parse");
    let projections = spec_context_projections(&kprobe);

    let arg0 = projection(&projections, "task.pt_regs.arg0");
    assert_eq!(arg0.root, "task");
    assert_eq!(arg0.name, "pt_regs.arg0");
    assert_eq!(arg0.source, "helper_call");
    assert_eq!(arg0.helper, Some("bpf_task_pt_regs"));
    assert_eq!(arg0.helper_minimum_kernel, Some("5.15"));
    assert_eq!(arg0.ty, "u64");
    assert_eq!(arg0.offset, None);
    assert!(arg0.supported);

    let retval = projection(&projections, "task.pt_regs.retval");
    assert_eq!(retval.root, "task");
    assert_eq!(retval.name, "pt_regs.retval");
    assert_eq!(retval.helper, Some("bpf_task_pt_regs"));
    assert_eq!(retval.helper_minimum_kernel, Some("5.15"));
    assert_eq!(retval.ty, "u64");
    assert_eq!(retval.offset, None);

    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let xdp_projections = spec_context_projections(&xdp);
    projection_absent(&xdp_projections, "task.pt_regs.arg0");
}

#[test]
fn test_spec_context_projections_only_include_supported_entries() {
    for program_type in EbpfProgramType::supported_program_types() {
        let target = ProgramSpec::representative_target_for_program_type(*program_type);
        let spec = ProgramSpec::from_program_type_target(*program_type, target)
            .unwrap_or_else(|err| panic!("{program_type:?} representative target failed: {err}"));

        for projection in spec_context_projections(&spec) {
            assert!(projection.supported);
            assert!(
                projection.unsupported_reason.is_none(),
                "{program_type:?} exposed unsupported projection {}",
                projection.path
            );
        }
    }
}

#[test]
fn test_spec_context_fields_preserve_tracepoint_payload_names() {
    let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
        .expect("tracepoint spec should parse");
    let fields = spec_context_fields(&spec, false);

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
    assert!(fields.iter().all(|field| !field.source.is_empty()));
    assert!(fields.iter().all(|field| !field.context_struct.is_empty()));
    assert!(fields.iter().all(|field| field.context_size > 0));
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
fn test_spec_context_args_skip_struct_ops_object_without_callback() {
    let spec =
        ProgramSpec::parse("struct_ops:sched_ext_ops").expect("struct_ops spec should parse");
    let (args, err) = spec_context_args(&spec, true);

    assert!(args.is_empty());
    assert!(err.is_none());
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
fn test_spec_context_fields_resolve_btf_retval_when_available() {
    let spec = ProgramSpec::parse("fexit:security_file_open").expect("fexit spec should parse");
    let fields = spec_context_fields(&spec, true);
    let retval = field(&fields, "retval");

    if retval.semantic_type.is_none() {
        let (metadata, err) = spec_context_retval(&spec, true);
        assert!(
            metadata.is_none() && err.is_some(),
            "missing ctx.retval field type should only happen when BTF retval metadata is unavailable"
        );
        return;
    }

    assert!(retval.runtime_type.is_some());
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

    let tcx_ingress = ProgramSpec::parse("tcx:lo:ingress").expect("tcx ingress spec should parse");
    let tcx_ingress_writes = spec_context_writes(&tcx_ingress);
    assert!(tcx_ingress_writes.iter().any(|surface| {
        surface.field == "sk" && surface.kind == "assign-socket" && !surface.indexed
    }));

    let tcx_egress = ProgramSpec::parse("tcx:lo:egress").expect("tcx egress spec should parse");
    let tcx_egress_writes = spec_context_writes(&tcx_egress);
    assert!(
        !tcx_egress_writes
            .iter()
            .any(|surface| surface.field == "sk"),
        "ctx.sk assignment should not be advertised on tcx egress"
    );

    let tc_action =
        ProgramSpec::parse("tc_action:diff-action").expect("tc_action spec should parse");
    let tc_action_writes = spec_context_writes(&tc_action);
    assert!(tc_action_writes.iter().any(|surface| {
        surface.field == "sk" && surface.kind == "assign-socket" && !surface.indexed
    }));

    let netkit = ProgramSpec::parse("netkit:lo:primary").expect("netkit spec should parse");
    let netkit_writes = spec_context_writes(&netkit);
    assert!(
        !netkit_writes.iter().any(|surface| surface.field == "sk"),
        "ctx.sk assignment should not be advertised on netkit"
    );
}

#[test]
fn test_context_write_records_include_backing_abi_metadata() {
    let sock_ops =
        ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let sock_ops_writes = spec_context_writes(&sock_ops);
    let reply = context_write(&sock_ops_writes, "reply");
    assert_eq!(reply.kind, "store");
    assert_eq!(reply.minimum_kernel, Some("4.14"));
    assert!(reply.helper.is_none());

    let replylong = context_write(&sock_ops_writes, "replylong");
    assert_eq!(replylong.kind, "store");
    assert!(replylong.indexed);
    assert_eq!(replylong.minimum_kernel, Some("4.14"));

    let cb_flags = context_write(&sock_ops_writes, "cb_flags");
    assert_eq!(cb_flags.kind, "store");
    assert_eq!(cb_flags.minimum_kernel, Some("4.16"));
    assert_eq!(cb_flags.helper, Some("bpf_sock_ops_cb_flags_set"));
    assert_eq!(cb_flags.helper_minimum_kernel, Some("4.16"));
    assert!(cb_flags.kfunc.is_none());

    let cgroup_sock = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let cgroup_sock_writes = spec_context_writes(&cgroup_sock);
    let bound_dev_if = context_write(&cgroup_sock_writes, "bound_dev_if");
    assert_eq!(bound_dev_if.minimum_kernel, Some("4.10"));
    let mark = context_write(&cgroup_sock_writes, "mark");
    assert_eq!(mark.minimum_kernel, Some("4.14"));

    let cgroup_sysctl = ProgramSpec::parse("cgroup_sysctl:/sys/fs/cgroup")
        .expect("cgroup_sysctl spec should parse");
    let cgroup_sysctl_writes = spec_context_writes(&cgroup_sysctl);
    let new_value = context_write(&cgroup_sysctl_writes, "new_value");
    assert_eq!(new_value.kind, "sysctl-new-value");
    assert_eq!(new_value.helper, Some("bpf_sysctl_set_new_value"));
    assert_eq!(new_value.helper_minimum_kernel, Some("5.2"));

    let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
    let tc_ingress_writes = spec_context_writes(&tc_ingress);
    let sk = context_write(&tc_ingress_writes, "sk");
    assert_eq!(sk.kind, "assign-socket");
    assert_eq!(sk.helper, Some("bpf_sk_assign"));
    assert_eq!(sk.helper_minimum_kernel, Some("5.7"));

    let cgroup_sockopt_set = ProgramSpec::parse("cgroup_sockopt:/sys/fs/cgroup:set")
        .expect("cgroup_sockopt set spec should parse");
    let cgroup_sockopt_writes = spec_context_writes(&cgroup_sockopt_set);
    let optval = context_write(&cgroup_sockopt_writes, "optval");
    assert_eq!(optval.kind, "sockopt-optval-byte");
    assert_eq!(optval.minimum_kernel, Some("5.3"));

    let unix_sock_addr = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("cgroup_sock_addr unix spec should parse");
    let unix_sock_addr_writes = spec_context_writes(&unix_sock_addr);
    let sun_path = context_write(&unix_sock_addr_writes, "sun_path");
    assert_eq!(sun_path.kind, "sun-path");
    assert_eq!(sun_path.kfunc, Some("bpf_sock_addr_set_sun_path"));
    assert_eq!(sun_path.kfunc_minimum_kernel, Some("6.7"));
    assert_eq!(sun_path.kfunc_maximum_kernel_exclusive, None);
    assert!(sun_path.helper.is_none());
}

#[test]
fn test_spec_record_context_writes_include_backing_abi_metadata() {
    let spec = ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let record = spec_record(
        "sock_ops:/sys/fs/cgroup".to_string(),
        spec,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    let context_writes = record
        .get("context_writes")
        .expect("context writes should be present")
        .as_list()
        .expect("context writes should be a list");
    let cb_flags = context_writes
        .iter()
        .find_map(|write| {
            let write = write.as_record().ok()?;
            (write.get("field")?.as_str().ok()? == "cb_flags").then_some(write)
        })
        .expect("ctx.cb_flags write should be present");

    assert_eq!(
        cb_flags
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "4.16"
    );
    assert_eq!(
        cb_flags
            .get("helper")
            .expect("helper should be present")
            .as_str()
            .expect("helper should be a string"),
        "bpf_sock_ops_cb_flags_set"
    );
    assert_eq!(
        cb_flags
            .get("helper_minimum_kernel")
            .expect("helper minimum kernel should be present")
            .as_str()
            .expect("helper minimum kernel should be a string"),
        "4.16"
    );
    assert!(
        cb_flags
            .get("kfunc")
            .expect("kfunc should be present")
            .is_nothing()
    );
    assert!(
        cb_flags
            .get("kfunc_maximum_kernel_exclusive")
            .expect("kfunc maximum kernel should be present")
            .is_nothing()
    );
}
