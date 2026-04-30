use super::*;
use crate::compiler::BpfHelper;
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
    let fields = spec_context_fields(&spec, false);

    assert!(field(&fields, "ingress_ifindex").names.contains(&"ifindex"));
    let packet_len = field(&fields, "packet_len");
    assert!(packet_len.names.contains(&"packet_len"));
    assert_eq!(packet_len.semantic_type.as_deref(), Some("u32"));
    assert_eq!(packet_len.runtime_type.as_deref(), Some("u32"));
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

    let retval = field(&fields, "retval");
    assert_eq!(retval.semantic_type.as_deref(), Some("u64"));
    assert_eq!(retval.runtime_type.as_deref(), Some("u64"));

    let kstack = field(&fields, "kstack");
    assert_eq!(kstack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(kstack.runtime_type.as_deref(), Some("i64"));

    let ustack = field(&fields, "ustack");
    assert_eq!(ustack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(ustack.runtime_type.as_deref(), Some("i64"));
}

#[test]
fn test_spec_context_fields_include_load_guards() {
    let spec = ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let fields = spec_context_fields(&spec, false);

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

    let callback = ProgramSpec::StructOpsCallback {
        value_type_name: "sched_ext_ops".to_string(),
        callback_name: "init".to_string(),
    };
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
    assert!(
        attach_shape
            .get("sleepable")
            .expect("struct_ops sleepable should be present")
            .as_bool()
            .expect("struct_ops sleepable should be a bool")
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
        attach_shape
            .get("family")
            .expect("struct_ops family should be present")
            .as_str()
            .expect("struct_ops family should be a string"),
        "tcp-congestion"
    );
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
    assert_eq!(family.helper, None);
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
fn test_spec_context_projections_include_helper_backed_socket_members() {
    let spec =
        ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap").expect("sk_msg spec should parse");
    let projections = spec_context_projections(&spec);

    let tcp_snd_cwnd = projection(&projections, "sk.tcp.snd_cwnd");
    assert_eq!(tcp_snd_cwnd.root, "sk.tcp");
    assert_eq!(tcp_snd_cwnd.name, "snd_cwnd");
    assert_eq!(tcp_snd_cwnd.source, "helper_return");
    assert_eq!(tcp_snd_cwnd.helper, Some("bpf_tcp_sock"));
    assert_eq!(tcp_snd_cwnd.ty, "u32");
    assert_eq!(
        tcp_snd_cwnd.supported,
        spec.helper_call_error(BpfHelper::TcpSock).is_none()
    );

    let full_family = projection(&projections, "sk.full.family");
    assert_eq!(full_family.helper, Some("bpf_sk_fullsock"));
    assert_eq!(full_family.ty, "u32");
    assert_eq!(
        full_family.supported,
        spec.helper_call_error(BpfHelper::SkFullsock).is_none()
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
}
