use super::*;
use crate::compiler::EbpfProgramType;
use crate::program_spec::{
    ProgramLiveAttachOptInReason, ProgramLiveAttachUnsupportedReason, ProgramSpec,
};
use std::collections::HashSet;

const CONTEXT_FIELD_SPEC_SOURCES: &[&str] = &[
    "raw_tracepoint:sys_enter",
    "tracepoint:syscalls/sys_enter_openat",
    "fentry:security_file_open",
    "fexit:ksys_read",
    "lsm:file_open",
    "socket_filter:udp4:127.0.0.1:31337",
    "tc_action:diff-action",
    "tc:lo:ingress",
    "tcx:lo:ingress",
    "netkit:lo:primary",
    "xdp:lo",
    "sk_msg:/sys/fs/bpf/demo_sockmap",
    "sk_skb:/sys/fs/bpf/demo_sockmap",
    "sk_skb_parser:/sys/fs/bpf/demo_sockmap",
    "sk_lookup:/proc/self/ns/net",
    "sk_reuseport:migrate",
    "cgroup_skb:/sys/fs/cgroup:egress",
    "cgroup_sock:/sys/fs/cgroup:sock_create",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
    "cgroup_sockopt:/sys/fs/cgroup:set",
    "cgroup_sysctl:/sys/fs/cgroup",
    "cgroup_device:/sys/fs/cgroup",
    "sock_ops:/sys/fs/cgroup",
    "lwt_xmit:demo-route",
    "flow_dissector:/proc/self/ns/net",
    "netfilter:ipv4:pre_routing:priority=-100:defrag",
    "perf_event:software:cpu-clock",
    "lirc_mode2:/dev/lirc0",
    "iter:task_file",
    "iter:bpf_map_elem",
    "iter:sockmap",
];

const CONTEXT_WRITE_SPEC_SOURCES: &[&str] = &[
    "socket_filter:udp4:127.0.0.1:31337",
    "tc_action:diff-action",
    "tc:lo:ingress",
    "tc:lo:egress",
    "tcx:lo:ingress",
    "tcx:lo:egress",
    "netkit:lo:primary",
    "sk_skb:/sys/fs/bpf/demo_sockmap",
    "sk_skb_parser:/sys/fs/bpf/demo_sockmap",
    "lwt_in:demo-route",
    "lwt_out:demo-route",
    "lwt_xmit:demo-route",
    "lwt_seg6local:demo-route",
    "cgroup_skb:/sys/fs/cgroup:ingress",
    "cgroup_skb:/sys/fs/cgroup:egress",
    "cgroup_sock:/sys/fs/cgroup:sock_create",
    "cgroup_sock:/sys/fs/cgroup:post_bind4",
    "cgroup_sysctl:/sys/fs/cgroup",
    "sock_ops:/sys/fs/cgroup",
    "cgroup_sockopt:/sys/fs/cgroup:get",
    "cgroup_sockopt:/sys/fs/cgroup:set",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:connect6",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6",
    "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
    "sk_lookup:/proc/self/ns/net",
    "flow_dissector:/proc/self/ns/net",
];

fn field<'a>(fields: &'a [SpecContextField], field_name: &str) -> &'a SpecContextField {
    fields
        .iter()
        .find(|field| field.field == field_name)
        .unwrap_or_else(|| panic!("expected ctx.{field_name} in spec context fields"))
}

fn field_absent(fields: &[SpecContextField], field_name: &str) {
    assert!(
        !fields.iter().any(|field| field.field == field_name),
        "ctx.{field_name} should not be present in spec context fields"
    );
}

fn context_write<'a>(writes: &'a [SpecContextWrite], field_name: &str) -> &'a SpecContextWrite {
    writes
        .iter()
        .find(|surface| surface.field == field_name)
        .unwrap_or_else(|| panic!("expected writable ctx.{field_name} in spec context writes"))
}

fn context_write_record(spec_text: &str, field_name: &str) -> Value {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let record = spec_record(spec_text.to_string(), spec, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    record
        .get("context_writes")
        .expect("context writes should be present")
        .as_list()
        .expect("context writes should be a list")
        .iter()
        .find(|write| {
            write
                .as_record()
                .ok()
                .and_then(|record| record.get("field"))
                .and_then(|field| field.as_str().ok())
                .is_some_and(|candidate| candidate == field_name)
        })
        .unwrap_or_else(|| panic!("expected writable ctx.{field_name} in spec context writes"))
        .clone()
}

fn assert_context_store_write_metadata(
    writes: &[SpecContextWrite],
    field_name: &str,
    requirement_key: &str,
    minimum_kernel: &str,
    source_fragment: &str,
    indexed: bool,
) {
    let write = context_write(writes, field_name);
    assert_eq!(write.kind, "store");
    assert_eq!(write.indexed, indexed);
    assert_eq!(
        write.context_field_requirement_key.as_deref(),
        Some(requirement_key)
    );
    assert_eq!(write.compatibility_minimum_kernel, Some(minimum_kernel));
    assert!(
        write
            .compatibility_minimum_kernel_source
            .is_some_and(|source| source.contains(source_fragment))
    );
    assert_eq!(write.minimum_kernel, Some(minimum_kernel));
    assert!(
        write
            .minimum_kernel_source
            .is_some_and(|source| source.contains(source_fragment))
    );
    assert!(write.helper.is_none());
    assert!(write.kfunc.is_none());
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

fn intrinsic_compatibility_floor(
    spec_text: &str,
    command: &str,
) -> (Option<String>, Option<String>) {
    let intrinsic = intrinsic_record(spec_text, command);
    let intrinsic = intrinsic.as_record().expect("intrinsic should be a record");
    let minimum_kernel = intrinsic
        .get("compatibility_minimum_kernel")
        .and_then(|value| value.as_str().ok())
        .map(str::to_string);
    let minimum_kernel_source = intrinsic
        .get("compatibility_minimum_kernel_source")
        .and_then(|value| value.as_str().ok())
        .map(str::to_string);
    (minimum_kernel, minimum_kernel_source)
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

fn intrinsic_variant_record_by(
    spec_text: &str,
    command: &str,
    selector: &str,
    value: &str,
) -> nu_protocol::Record {
    intrinsic_record(spec_text, command)
        .as_record()
        .expect("intrinsic should be a record")
        .get("variants")
        .expect("intrinsic variants should be present")
        .as_list()
        .expect("intrinsic variants should be a list")
        .iter()
        .find_map(|variant| {
            let record = variant.as_record().ok()?;
            let candidate_selector = record.get("selector")?.as_str().ok()?;
            let candidate_value = record.get("value")?.as_str().ok()?;
            (candidate_selector == selector && candidate_value == value).then(|| record.clone())
        })
        .unwrap_or_else(|| {
            panic!("expected {command} variant {selector}={value} in {spec_text} spec")
        })
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

fn intrinsic_context_field_requirements(
    spec_text: &str,
    command: &str,
) -> Vec<(String, String, String, String)> {
    intrinsic_record(spec_text, command)
        .as_record()
        .expect("intrinsic should be a record")
        .get("context_field_requirements")
        .expect("intrinsic context field requirements should be present")
        .as_list()
        .expect("intrinsic context field requirements should be a list")
        .iter()
        .map(|requirement| {
            let requirement = requirement
                .as_record()
                .expect("intrinsic context field requirement should be a record");
            let field = requirement
                .get("field")
                .expect("context field should be present")
                .as_str()
                .expect("context field should be a string")
                .to_string();
            let requirement_key = requirement
                .get("context_field_requirement_key")
                .expect("context field requirement key should be present")
                .as_str()
                .expect("context field requirement key should be a string")
                .to_string();
            let minimum_kernel = requirement
                .get("minimum_kernel")
                .expect("context field minimum kernel should be present")
                .as_str()
                .expect("context field minimum kernel should be a string")
                .to_string();
            let minimum_kernel_source = requirement
                .get("minimum_kernel_source")
                .expect("context field minimum kernel source should be present")
                .as_str()
                .expect("context field minimum kernel source should be a string")
                .to_string();
            (
                field,
                requirement_key,
                minimum_kernel,
                minimum_kernel_source,
            )
        })
        .collect()
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
    let expected_key = format!("helper:{helper}");
    assert_eq!(
        field.backing_helper_requirement_key.as_deref(),
        Some(expected_key.as_str())
    );
    assert_eq!(field.backing_helper_minimum_kernel, Some(minimum_kernel));
    assert!(
        field
            .backing_helper_minimum_kernel_source
            .is_some_and(|source| source.contains(&format!("/v{minimum_kernel}/"))),
        "ctx.{field_name} helper metadata should include a source link for {minimum_kernel}"
    );
}

fn assert_accessible_helper_backed_context_fields_report_metadata(spec_text: &str) {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let fields = spec_context_fields(&spec, false);
    let mut seen = Vec::new();
    let mut checked = 0;

    for entry in spec.program_type().ctx_field_name_entries() {
        if seen.iter().any(|field| field == &entry.field) {
            continue;
        }
        seen.push(entry.field.clone());

        if spec.ctx_field_access_error(&entry.field).is_some() {
            continue;
        }

        let Some(helper) = ctx_field_backing_helper(&entry.field) else {
            continue;
        };
        let Some(minimum_kernel) = helper.minimum_kernel() else {
            continue;
        };

        let field = field(&fields, &entry.field.display_name());
        let expected_key = format!("helper:{}", helper.name());
        assert_eq!(
            field.backing_helper,
            Some(helper.name()),
            "{spec_text} ctx.{} should report its backing helper",
            entry.field.display_name()
        );
        assert_eq!(
            field.backing_helper_requirement_key.as_deref(),
            Some(expected_key.as_str()),
            "{spec_text} ctx.{} should report its backing helper requirement key",
            entry.field.display_name()
        );
        assert_eq!(
            field.backing_helper_minimum_kernel,
            Some(minimum_kernel),
            "{spec_text} ctx.{} should report its backing helper minimum kernel",
            entry.field.display_name()
        );
        assert_eq!(
            field.compatibility_minimum_kernel,
            Some(minimum_kernel),
            "{spec_text} ctx.{} should report aggregate compatibility minimum kernel",
            entry.field.display_name()
        );
        assert!(
            field
                .backing_helper_minimum_kernel_source
                .is_some_and(|source| source.contains(&format!("/v{minimum_kernel}/"))),
            "{spec_text} ctx.{} should report a source link for backing helper {minimum_kernel}",
            entry.field.display_name()
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "{spec_text} should expose at least one helper-backed context field"
    );
}

fn assert_helper_backed_context_projections_report_metadata(spec_text: &str) {
    let spec = ProgramSpec::parse(spec_text).expect("program spec should parse");
    let projections = spec_context_projections(&spec);
    let mut checked = 0;

    for projection in projections {
        let Some(helper_name) = projection.helper else {
            continue;
        };
        let helper = BpfHelper::from_name(helper_name).unwrap_or_else(|| {
            panic!(
                "{spec_text} projection {} should use a modeled helper",
                projection.path
            )
        });
        let Some(minimum_kernel) = helper.minimum_kernel() else {
            continue;
        };
        let expected_key = format!("helper:{}", helper.name());

        assert_eq!(
            projection.helper_requirement_key.as_deref(),
            Some(expected_key.as_str()),
            "{spec_text} projection {} should report helper requirement key",
            projection.path
        );
        assert_eq!(
            projection.helper_minimum_kernel,
            Some(minimum_kernel),
            "{spec_text} projection {} should report helper minimum kernel",
            projection.path
        );
        let compatibility_minimum = projection.compatibility_minimum_kernel.unwrap_or_else(|| {
            panic!(
                "{spec_text} projection {} should report aggregate compatibility minimum kernel",
                projection.path
            )
        });
        assert!(
            ContextFieldCompatibilityRequirement::kernel_version_at_least(
                compatibility_minimum,
                minimum_kernel,
            ),
            "{spec_text} projection {} aggregate floor {compatibility_minimum} should cover helper floor {minimum_kernel}",
            projection.path
        );
        assert!(
            projection
                .helper_minimum_kernel_source
                .is_some_and(|source| source.contains(&format!("/v{minimum_kernel}/"))),
            "{spec_text} projection {} should report a source link for helper {minimum_kernel}",
            projection.path
        );
        if let Some(read_helper_name) = projection.read_helper {
            let read_helper = BpfHelper::from_name(read_helper_name).unwrap_or_else(|| {
                panic!(
                    "{spec_text} projection {} should use a modeled read helper",
                    projection.path
                )
            });
            let read_minimum_kernel = read_helper
                .minimum_kernel()
                .expect("read helper should have a minimum kernel");
            let expected_read_key = format!("helper:{}", read_helper.name());
            assert_eq!(
                projection.read_helper_requirement_key.as_deref(),
                Some(expected_read_key.as_str()),
                "{spec_text} projection {} should report read helper requirement key",
                projection.path
            );
            assert_eq!(
                projection.read_helper_minimum_kernel,
                Some(read_minimum_kernel),
                "{spec_text} projection {} should report read helper minimum kernel",
                projection.path
            );
            assert!(
                ContextFieldCompatibilityRequirement::kernel_version_at_least(
                    compatibility_minimum,
                    read_minimum_kernel,
                ),
                "{spec_text} projection {} aggregate floor {compatibility_minimum} should cover read helper floor {read_minimum_kernel}",
                projection.path
            );
        }
        checked += 1;
    }

    assert!(
        checked > 0,
        "{spec_text} should expose at least one helper-backed context projection"
    );
}

#[test]
fn test_spec_context_fields_include_program_specific_aliases() {
    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let fields = spec_context_fields(&spec, false);

    let ifindex = field(&fields, "ingress_ifindex");
    assert!(ifindex.names.contains(&"ifindex"));
    assert_eq!(
        ifindex.requirement_key.as_deref(),
        Some("ctx:ingress_ifindex")
    );
    assert_eq!(ifindex.minimum_kernel, Some("4.16"));
    assert!(
        ifindex
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.16/include/uapi/linux/bpf.h"))
    );
    let rx_queue_index = field(&fields, "rx_queue_index");
    assert_eq!(rx_queue_index.minimum_kernel, Some("4.16"));
    field_absent(&fields, "egress_ifindex");
    let devmap_spec = ProgramSpec::parse("xdp:devmap").expect("xdp devmap spec should parse");
    let devmap_fields = spec_context_fields(&devmap_spec, false);
    let egress_ifindex = field(&devmap_fields, "egress_ifindex");
    assert_eq!(
        egress_ifindex.requirement_key.as_deref(),
        Some("ctx:egress_ifindex")
    );
    assert_eq!(egress_ifindex.minimum_kernel, Some("5.8"));
    let packet_len = field(&fields, "packet_len");
    assert!(packet_len.names.contains(&"packet_len"));
    assert_eq!(packet_len.semantic_type.as_deref(), Some("u32"));
    assert_eq!(packet_len.runtime_type.as_deref(), Some("u32"));
    assert_eq!(
        packet_len.requirement_key.as_deref(),
        Some("ctx:packet_len")
    );
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
    assert_eq!(task.compatibility_minimum_kernel, Some("5.11"));
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
    assert_eq!(cgroup.compatibility_minimum_kernel, Some("5.11"));
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
    assert_eq!(flow_keys.requirement_key.as_deref(), Some("ctx:flow_keys"));
    assert_eq!(flow_keys.minimum_kernel, Some("4.20"));
    assert!(
        flow_keys
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.20/include/uapi/linux/bpf.h"))
    );
}

#[test]
fn test_spec_context_fields_label_helper_backed_scalar_fields() {
    let spec = ProgramSpec::parse("kretprobe:sys_read").expect("kretprobe spec should parse");
    let fields = spec_context_fields(&spec, false);

    let pid = field(&fields, "pid");
    assert_eq!(pid.backing_helper, Some("bpf_get_current_pid_tgid"));
    assert_eq!(pid.backing_helper_minimum_kernel, Some("4.2"));
    assert_eq!(pid.requirement_key.as_deref(), Some("ctx:pid"));
    assert_eq!(pid.minimum_kernel, Some("4.2"));
    assert_eq!(pid.compatibility_minimum_kernel, Some("4.2"));
    assert!(
        pid.minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.2/"))
    );

    let retval = field(&fields, "retval");
    assert_eq!(retval.semantic_type.as_deref(), Some("u64"));
    assert_eq!(retval.runtime_type.as_deref(), Some("u64"));
    assert_eq!(retval.backing_helper, None);
    assert_eq!(retval.minimum_kernel, Some("4.1"));
    assert_eq!(retval.compatibility_minimum_kernel, Some("4.1"));
    assert!(
        retval
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.1/include/uapi/linux/bpf.h"))
    );

    let kstack = field(&fields, "kstack");
    assert_eq!(kstack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(kstack.runtime_type.as_deref(), Some("i64"));
    assert_eq!(kstack.backing_helper, Some("bpf_get_stackid"));
    assert_eq!(kstack.backing_helper_minimum_kernel, Some("4.6"));
    assert_eq!(kstack.minimum_kernel, Some("4.6"));
    assert_eq!(kstack.compatibility_minimum_kernel, Some("4.6"));

    let ustack = field(&fields, "ustack");
    assert_eq!(ustack.semantic_type.as_deref(), Some("i64"));
    assert_eq!(ustack.runtime_type.as_deref(), Some("i64"));
    assert_eq!(ustack.backing_helper, Some("bpf_get_stackid"));
    assert_eq!(ustack.backing_helper_minimum_kernel, Some("4.6"));
    assert_eq!(ustack.minimum_kernel, Some("4.6"));
    assert_eq!(ustack.compatibility_minimum_kernel, Some("4.6"));
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
        (
            "perf_event:software:cpu-clock",
            "perf_enabled",
            "bpf_perf_prog_read_value",
            "4.15",
        ),
        (
            "perf_event:software:cpu-clock",
            "perf_running",
            "bpf_perf_prog_read_value",
            "4.15",
        ),
        (
            "kprobe:ksys_read",
            "numa_node",
            "bpf_get_numa_node_id",
            "4.10",
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
fn test_spec_context_fields_report_backing_helper_metadata_invariants() {
    for spec_text in [
        "raw_tracepoint:sys_enter",
        "fentry:security_file_open",
        "tc:lo:ingress",
        "sk_lookup:/proc/self/ns/net",
        "perf_event:software:cpu-clock",
        "xdp:lo",
        "cgroup_sysctl:/sys/fs/cgroup",
    ] {
        assert_accessible_helper_backed_context_fields_report_metadata(spec_text);
    }
}

#[test]
fn test_context_field_compatibility_metadata_invariants() {
    for spec_text in CONTEXT_FIELD_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text)
            .unwrap_or_else(|err| panic!("{spec_text} should parse: {err}"));
        let entries = spec.program_type().ctx_field_name_entries();

        for field in spec_context_fields(&spec, false) {
            let entry = entries
                .iter()
                .find(|entry| entry.field.display_name() == field.field)
                .unwrap_or_else(|| {
                    panic!(
                        "{spec_text} ctx.{} should map back to a modeled context field",
                        field.field
                    )
                });
            let context_requirement =
                ContextFieldCompatibilityRequirement::for_field_on_program_spec(
                    &entry.field,
                    &spec,
                );
            match context_requirement {
                Some(requirement) => {
                    assert_eq!(
                        field.requirement_key.as_deref(),
                        Some(requirement.key().as_str()),
                        "{spec_text} ctx.{} should report the exact context-field requirement key",
                        field.field
                    );
                    assert_eq!(
                        field.minimum_kernel,
                        Some(requirement.minimum_kernel()),
                        "{spec_text} ctx.{} should report the exact context-field minimum kernel",
                        field.field
                    );
                    assert_eq!(
                        field.minimum_kernel_source,
                        Some(requirement.minimum_kernel_source()),
                        "{spec_text} ctx.{} should report the exact context-field minimum kernel source",
                        field.field
                    );
                }
                None => {
                    assert_eq!(
                        field.requirement_key, None,
                        "{spec_text} ctx.{} should not report a context-field requirement key",
                        field.field
                    );
                    assert_eq!(
                        field.minimum_kernel, None,
                        "{spec_text} ctx.{} should not report a context-field minimum kernel",
                        field.field
                    );
                    assert_eq!(
                        field.minimum_kernel_source, None,
                        "{spec_text} ctx.{} should not report a context-field minimum kernel source",
                        field.field
                    );
                }
            }

            match ctx_field_backing_helper(&entry.field) {
                Some(helper) => {
                    let requirement =
                        HelperCompatibilityRequirement::for_helper(helper).unwrap_or_else(|| {
                            panic!(
                                "{spec_text} ctx.{} backing helper {} should expose compatibility metadata",
                                field.field,
                                helper.name()
                            )
                        });
                    assert_eq!(field.backing_helper, Some(helper.name()));
                    assert_eq!(
                        field.backing_helper_requirement_key.as_deref(),
                        Some(requirement.key().as_str()),
                        "{spec_text} ctx.{} should report the exact backing-helper requirement key",
                        field.field
                    );
                    assert_eq!(
                        field.backing_helper_minimum_kernel,
                        Some(requirement.minimum_kernel()),
                        "{spec_text} ctx.{} should report the exact backing-helper minimum kernel",
                        field.field
                    );
                    assert_eq!(
                        field.backing_helper_minimum_kernel_source,
                        Some(requirement.minimum_kernel_source()),
                        "{spec_text} ctx.{} should report the exact backing-helper source",
                        field.field
                    );
                }
                None => {
                    assert_eq!(field.backing_helper, None);
                    assert_eq!(field.backing_helper_requirement_key, None);
                    assert_eq!(field.backing_helper_minimum_kernel, None);
                    assert_eq!(field.backing_helper_minimum_kernel_source, None);
                }
            }

            let component_floors = [field.minimum_kernel, field.backing_helper_minimum_kernel];
            if component_floors.iter().any(Option::is_some) {
                let compatibility_minimum =
                    field.compatibility_minimum_kernel.unwrap_or_else(|| {
                        panic!(
                            "{spec_text} ctx.{} should report an aggregate compatibility minimum kernel",
                            field.field
                        )
                    });
                assert!(
                    field.compatibility_minimum_kernel_source.is_some(),
                    "{spec_text} ctx.{} should report an aggregate compatibility source",
                    field.field
                );
                for floor in component_floors.into_iter().flatten() {
                    assert!(
                        ContextFieldCompatibilityRequirement::kernel_version_at_least(
                            compatibility_minimum,
                            floor
                        ),
                        "{spec_text} ctx.{} aggregate floor {compatibility_minimum} should cover component floor {floor}",
                        field.field
                    );
                }
            } else {
                assert!(
                    field.compatibility_minimum_kernel.is_none(),
                    "{spec_text} ctx.{} should not report an aggregate compatibility minimum without component floors",
                    field.field
                );
                assert!(
                    field.compatibility_minimum_kernel_source.is_none(),
                    "{spec_text} ctx.{} should not report an aggregate compatibility source without component floors",
                    field.field
                );
            }
        }
    }
}

#[test]
fn test_spec_context_projections_report_helper_metadata_invariants() {
    for spec_text in [
        "tc:lo:ingress",
        "cgroup_skb:/sys/fs/cgroup:egress",
        "kprobe:sys_read",
        "xdp:lo",
        "tc:lo:egress",
    ] {
        assert_helper_backed_context_projections_report_metadata(spec_text);
    }
}

#[test]
fn test_context_abi_load_fields_report_source_backed_minimums() {
    for spec_text in CONTEXT_FIELD_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text)
            .unwrap_or_else(|err| panic!("{spec_text} should parse: {err}"));

        for field in spec_context_fields(&spec, false) {
            let Some(load_kind) = field.load_kind else {
                continue;
            };

            assert!(
                field.requirement_key.is_some(),
                "{spec_text} ctx.{} has {load_kind} load metadata but no requirement key",
                field.field
            );
            assert!(
                field.minimum_kernel.is_some(),
                "{spec_text} ctx.{} has {load_kind} load metadata but no source-backed minimum kernel",
                field.field
            );
            assert!(
                field.minimum_kernel_source.is_some(),
                "{spec_text} ctx.{} has {load_kind} load metadata but no source-backed minimum kernel source",
                field.field
            );
        }
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
fn test_spec_context_fields_include_context_load_metadata() {
    let spec = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let fields = spec_context_fields(&spec, false);
    let data = field(&fields, "data");
    assert_eq!(data.load_kind, Some("direct"));
    assert_eq!(data.direct_load_width, Some("u32"));
    assert_eq!(data.direct_load_offset, Some(0));
    assert_eq!(data.array_load_base_offset, None);
    assert_eq!(data.nested_load_pointer_offset, None);

    let spec = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
    let fields = spec_context_fields(&spec, false);
    let eth_protocol = field(&fields, "eth_protocol");
    assert_eq!(eth_protocol.load_kind, Some("direct"));
    assert_eq!(eth_protocol.direct_load_width, Some("u16"));
    assert_eq!(eth_protocol.direct_load_offset, Some(16));

    let cb = field(&fields, "cb");
    assert_eq!(cb.load_kind, Some("array"));
    assert_eq!(cb.array_load_base_offset, Some(48));
    assert_eq!(cb.array_load_count, Some(5));
    assert_eq!(cb.array_load_normalize_big_endian, Some(false));
    assert_eq!(cb.direct_load_offset, None);
    assert_eq!(cb.nested_load_pointer_offset, None);

    let spec = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:post_bind6")
        .expect("cgroup_sock spec should parse");
    let fields = spec_context_fields(&spec, false);
    let local_ip6 = field(&fields, "local_ip6");
    assert_eq!(local_ip6.load_kind, Some("array"));
    assert_eq!(local_ip6.array_load_base_offset, Some(28));
    assert_eq!(local_ip6.array_load_count, Some(4));
    assert_eq!(local_ip6.array_load_normalize_big_endian, Some(true));

    let spec = ProgramSpec::parse("netfilter:ipv4:pre_routing:priority=-100:defrag")
        .expect("netfilter spec should parse");
    let fields = spec_context_fields(&spec, false);
    let hook = field(&fields, "hook");
    assert_eq!(hook.load_kind, Some("nested"));
    assert_eq!(hook.nested_load_pointer_offset, Some(0));
    assert_eq!(hook.nested_load_width, Some("u8"));
    assert_eq!(hook.nested_load_field_offset, Some(0));
    assert_eq!(hook.direct_load_offset, None);
    assert_eq!(hook.array_load_base_offset, None);

    let pf = field(&fields, "pf");
    assert_eq!(pf.load_kind, Some("nested"));
    assert_eq!(pf.nested_load_pointer_offset, Some(0));
    assert_eq!(pf.nested_load_width, Some("u8"));
    assert_eq!(pf.nested_load_field_offset, Some(1));
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
    let packet_headers = record
        .get("packet_headers")
        .expect("packet headers should be present")
        .as_list()
        .expect("packet headers should be a list");
    let ipv4 = packet_headers
        .iter()
        .find(|header| {
            header
                .as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "ipv4")
        })
        .expect("ipv4 packet header should be present")
        .as_record()
        .expect("ipv4 packet header should be a record");
    assert!(
        ipv4.get("payload_step")
            .expect("ipv4 packet header payload metadata should be present")
            .as_bool()
            .expect("ipv4 packet header payload metadata should be a bool")
    );
    let ipv4_protocol_views = ipv4
        .get("protocol_views")
        .expect("ipv4 packet protocol views should be present")
        .as_list()
        .expect("ipv4 packet protocol views should be a list");
    assert!(
        ipv4_protocol_views.iter().any(|view| {
            view.as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "tcp")
        }),
        "ipv4 packet header should expose tcp as a protocol-following view"
    );
    let ipv4_fields = ipv4
        .get("fields")
        .expect("ipv4 packet header fields should be present")
        .as_list()
        .expect("ipv4 packet header fields should be a list");
    let version = ipv4_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "version")
        })
        .expect("ipv4 version field should be present")
        .as_record()
        .expect("ipv4 version field should be a record");
    assert_eq!(
        version
            .get("semantic_type")
            .expect("ipv4 version semantic type should be present")
            .as_str()
            .expect("ipv4 version semantic type should be a string"),
        "u8"
    );
    assert_eq!(
        version
            .get("offset")
            .expect("ipv4 version offset should be present")
            .as_int()
            .expect("ipv4 version offset should be an int"),
        0
    );
    assert_eq!(
        version
            .get("bit_offset")
            .expect("ipv4 version bit offset should be present")
            .as_int()
            .expect("ipv4 version bit offset should be an int"),
        4
    );
    assert_eq!(
        version
            .get("bit_size")
            .expect("ipv4 version bit size should be present")
            .as_int()
            .expect("ipv4 version bit size should be an int"),
        4
    );
    assert!(
        !version
            .get("packet_big_endian")
            .expect("ipv4 version endian metadata should be present")
            .as_bool()
            .expect("ipv4 version endian metadata should be a bool")
    );
    let fragment_offset = ipv4_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "fragment_offset")
        })
        .expect("ipv4 fragment_offset field should be present")
        .as_record()
        .expect("ipv4 fragment_offset field should be a record");
    assert_eq!(
        fragment_offset
            .get("bit_size")
            .expect("ipv4 fragment_offset bit size should be present")
            .as_int()
            .expect("ipv4 fragment_offset bit size should be an int"),
        13
    );
    assert!(
        fragment_offset
            .get("packet_big_endian")
            .expect("ipv4 fragment_offset endian metadata should be present")
            .as_bool()
            .expect("ipv4 fragment_offset endian metadata should be a bool")
    );
    let total_len = ipv4_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "total_len")
        })
        .expect("ipv4 total_len field should be present")
        .as_record()
        .expect("ipv4 total_len field should be a record");
    assert!(
        total_len
            .get("names")
            .expect("ipv4 total_len names should be present")
            .as_list()
            .expect("ipv4 total_len names should be a list")
            .iter()
            .any(|name| name.as_str().is_ok_and(|name| name == "tot_len")),
        "ipv4 total_len should expose its kernel-header alias"
    );

    let ipv6 = packet_headers
        .iter()
        .find(|header| {
            header
                .as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "ipv6")
        })
        .expect("ipv6 packet header should be present")
        .as_record()
        .expect("ipv6 packet header should be a record");
    let ipv6_fields = ipv6
        .get("fields")
        .expect("ipv6 packet header fields should be present")
        .as_list()
        .expect("ipv6 packet header fields should be a list");
    let flow_label = ipv6_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "flow_label")
        })
        .expect("ipv6 flow_label field should be present")
        .as_record()
        .expect("ipv6 flow_label field should be a record");
    assert_eq!(
        flow_label
            .get("bit_size")
            .expect("ipv6 flow_label bit size should be present")
            .as_int()
            .expect("ipv6 flow_label bit size should be an int"),
        20
    );
    assert!(
        flow_label
            .get("packet_big_endian")
            .expect("ipv6 flow_label endian metadata should be present")
            .as_bool()
            .expect("ipv6 flow_label endian metadata should be a bool")
    );

    let icmp = packet_headers
        .iter()
        .find(|header| {
            header
                .as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "icmp")
        })
        .expect("icmp packet header should be present")
        .as_record()
        .expect("icmp packet header should be a record");
    let icmp_fields = icmp
        .get("fields")
        .expect("icmp packet header fields should be present")
        .as_list()
        .expect("icmp packet header fields should be a list");
    let echo_id = icmp_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "echo_id")
        })
        .expect("icmp echo_id field should be present")
        .as_record()
        .expect("icmp echo_id field should be a record");
    assert_eq!(
        echo_id
            .get("offset")
            .expect("icmp echo_id offset should be present")
            .as_int()
            .expect("icmp echo_id offset should be an int"),
        4
    );
    assert!(
        echo_id
            .get("packet_big_endian")
            .expect("icmp echo_id endian metadata should be present")
            .as_bool()
            .expect("icmp echo_id endian metadata should be a bool")
    );
    assert!(
        echo_id
            .get("names")
            .expect("icmp echo_id names should be present")
            .as_list()
            .expect("icmp echo_id names should be a list")
            .iter()
            .any(|name| name.as_str().is_ok_and(|name| name == "identifier")),
        "icmp echo_id should expose identifier alias"
    );

    let eth = packet_headers
        .iter()
        .find(|header| {
            header
                .as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "eth")
        })
        .expect("eth packet header should be present")
        .as_record()
        .expect("eth packet header should be a record");
    let eth_protocol_views = eth
        .get("protocol_views")
        .expect("eth packet protocol views should be present")
        .as_list()
        .expect("eth packet protocol views should be a list");
    assert!(
        eth_protocol_views.iter().any(|view| {
            let Ok(view) = view.as_record() else {
                return false;
            };
            let header = view.get("header").and_then(|header| header.as_str().ok());
            let names = view.get("names").and_then(|names| names.as_list().ok());
            header.is_some_and(|header| header == "ipv6")
                && names.is_some_and(|names| {
                    names
                        .iter()
                        .any(|name| name.as_str().is_ok_and(|name| name == "ip6hdr"))
                })
        }),
        "eth packet header should expose ipv6 aliases for protocol-following views"
    );
    assert!(
        eth_protocol_views.iter().any(|view| {
            view.as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "arp")
        }),
        "eth packet header should expose arp as a protocol-following view"
    );

    let arp = packet_headers
        .iter()
        .find(|header| {
            header
                .as_record()
                .ok()
                .and_then(|record| record.get("header"))
                .and_then(|header| header.as_str().ok())
                .is_some_and(|header| header == "arp")
        })
        .expect("arp packet header should be present")
        .as_record()
        .expect("arp packet header should be a record");
    assert!(
        !arp.get("payload_step")
            .expect("arp packet header payload metadata should be present")
            .as_bool()
            .expect("arp packet header payload metadata should be a bool")
    );
    let arp_fields = arp
        .get("fields")
        .expect("arp packet header fields should be present")
        .as_list()
        .expect("arp packet header fields should be a list");
    let opcode = arp_fields
        .iter()
        .find(|field| {
            field
                .as_record()
                .ok()
                .and_then(|record| record.get("name"))
                .and_then(|name| name.as_str().ok())
                .is_some_and(|name| name == "opcode")
        })
        .expect("arp opcode field should be present")
        .as_record()
        .expect("arp opcode field should be a record");
    assert_eq!(
        opcode
            .get("offset")
            .expect("arp opcode offset should be present")
            .as_int()
            .expect("arp opcode offset should be an int"),
        6
    );
    assert!(
        opcode
            .get("packet_big_endian")
            .expect("arp opcode endian metadata should be present")
            .as_bool()
            .expect("arp opcode endian metadata should be a bool")
    );
    assert!(
        opcode
            .get("names")
            .expect("arp opcode names should be present")
            .as_list()
            .expect("arp opcode names should be a list")
            .iter()
            .any(|name| name.as_str().is_ok_and(|name| name == "ar_op")),
        "arp opcode should expose its kernel-header alias"
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
    assert!(
        record
            .get("packet_headers")
            .expect("packet headers should be present")
            .as_list()
            .expect("packet headers should be a list")
            .is_empty()
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
    assert_eq!(
        record
            .get("live_attach_status")
            .expect("live_attach_status should be present")
            .as_str()
            .expect("live_attach_status should be a string"),
        "unsupported"
    );
    assert!(
        record
            .get("live_attach_status_description")
            .expect("live_attach_status_description should be present")
            .as_str()
            .expect("live_attach_status_description should be a string")
            .contains("not implemented")
    );
    assert_eq!(
        record
            .get("live_attach_unsupported_reason")
            .expect("live_attach_unsupported_reason should be present")
            .as_str()
            .expect("live_attach_unsupported_reason should be a string"),
        "cgroup-sock-addr-unix-loader"
    );
    assert!(
        record
            .get("live_attach_unsupported_reason_description")
            .expect("live_attach_unsupported_reason_description should be present")
            .as_str()
            .expect("live_attach_unsupported_reason_description should be a string")
            .contains("Cgroup UNIX socket-address hooks")
    );
    assert!(
        record
            .get("live_attach_opt_in_reason")
            .expect("live_attach_opt_in_reason should be present")
            .is_nothing()
    );
    assert!(
        record
            .get("live_attach_opt_in_reason_description")
            .expect("live_attach_opt_in_reason_description should be present")
            .is_nothing()
    );
    assert_eq!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string"),
        ProgramLiveAttachUnsupportedReason::CgroupSockAddrUnix.note()
    );
    assert_eq!(
        record
            .get("compatibility_default_test_lane")
            .expect("compatibility_default_test_lane should be present")
            .as_str()
            .expect("compatibility_default_test_lane should be a string"),
        "host-gated"
    );
    assert_eq!(
        record
            .get("live_attach_default_test_lane")
            .expect("live_attach_default_test_lane should be present")
            .as_str()
            .expect("live_attach_default_test_lane should be a string"),
        "dry-run"
    );
    assert!(
        record
            .get("live_attach_default_test_lane_description")
            .expect("live_attach_default_test_lane_description should be present")
            .as_str()
            .expect("live_attach_default_test_lane_description should be a string")
            .contains("dry-run")
    );
    assert_eq!(
        record
            .get("external_alpha_status")
            .expect("external_alpha_status should be present")
            .as_str()
            .expect("external_alpha_status should be a string"),
        "dry-run-only"
    );
    assert!(
        record
            .get("external_alpha_status_description")
            .expect("external_alpha_status_description should be present")
            .as_str()
            .expect("external_alpha_status_description should be a string")
            .contains("compile/dry-run")
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
    assert_eq!(
        record
            .get("live_attach_status")
            .expect("live_attach_status should be present")
            .as_str()
            .expect("live_attach_status should be a string"),
        "requires-opt-in"
    );
    assert!(
        record
            .get("live_attach_unsupported_reason")
            .expect("live_attach_unsupported_reason should be present")
            .is_nothing()
    );
    assert!(
        record
            .get("live_attach_unsupported_reason_description")
            .expect("live_attach_unsupported_reason_description should be present")
            .is_nothing()
    );
    assert_eq!(
        record
            .get("live_attach_opt_in_reason")
            .expect("live_attach_opt_in_reason should be present")
            .as_str()
            .expect("live_attach_opt_in_reason should be a string"),
        "unclassified-struct-ops"
    );
    assert!(
        record
            .get("live_attach_opt_in_reason_description")
            .expect("live_attach_opt_in_reason_description should be present")
            .as_str()
            .expect("live_attach_opt_in_reason_description should be a string")
            .contains("Unclassified struct_ops")
    );
    assert_eq!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string"),
        ProgramLiveAttachOptInReason::UnclassifiedStructOps.note()
    );
    assert_eq!(
        record
            .get("live_attach_default_test_lane")
            .expect("live_attach_default_test_lane should be present")
            .as_str()
            .expect("live_attach_default_test_lane should be a string"),
        "vm-only"
    );
    assert_eq!(
        record
            .get("external_alpha_status")
            .expect("external_alpha_status should be present")
            .as_str()
            .expect("external_alpha_status should be a string"),
        "unsafe-opt-in"
    );
    assert!(
        record
            .get("external_alpha_status_description")
            .expect("external_alpha_status_description should be present")
            .as_str()
            .expect("external_alpha_status_description should be a string")
            .contains("unsafe opt-in")
    );

    for (spec_text, opt_in_reason, description_fragment) in [
        (
            "struct_ops:hid_bpf_ops",
            ProgramLiveAttachOptInReason::HidBpf,
            "hid_bpf_ops",
        ),
        (
            "struct_ops:Qdisc_ops",
            ProgramLiveAttachOptInReason::Qdisc,
            "Qdisc_ops",
        ),
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("struct_ops spec should parse");
        let record = spec_record(spec_text.to_string(), spec, Span::test_data(), false)
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
        assert_eq!(
            record
                .get("live_attach_status")
                .expect("live_attach_status should be present")
                .as_str()
                .expect("live_attach_status should be a string"),
            "requires-opt-in"
        );
        assert!(
            record
                .get("live_attach_unsupported_reason")
                .expect("live_attach_unsupported_reason should be present")
                .is_nothing()
        );
        assert_eq!(
            record
                .get("live_attach_opt_in_reason")
                .expect("live_attach_opt_in_reason should be present")
                .as_str()
                .expect("live_attach_opt_in_reason should be a string"),
            opt_in_reason.key()
        );
        assert!(
            record
                .get("live_attach_opt_in_reason_description")
                .expect("live_attach_opt_in_reason_description should be present")
                .as_str()
                .expect("live_attach_opt_in_reason_description should be a string")
                .contains(description_fragment)
        );
        assert_eq!(
            record
                .get("live_attach_note")
                .expect("live_attach_note should be present")
                .as_str()
                .expect("live_attach_note should be a string"),
            opt_in_reason.note()
        );
        assert_eq!(
            record
                .get("live_attach_default_test_lane")
                .expect("live_attach_default_test_lane should be present")
                .as_str()
                .expect("live_attach_default_test_lane should be a string"),
            "vm-only"
        );
        assert_eq!(
            record
                .get("external_alpha_status")
                .expect("external_alpha_status should be present")
                .as_str()
                .expect("external_alpha_status should be a string"),
            "unsafe-opt-in"
        );
    }
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
            .get("requirement_key")
            .expect("requirement key should be present")
            .as_str()
            .expect("requirement key should be a string"),
        "ctx:packet_len"
    );
    assert_eq!(
        packet_len
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "4.8"
    );
    assert!(
        packet_len
            .get("compatibility_minimum_kernel_source")
            .expect("compatibility minimum kernel source should be present")
            .as_str()
            .expect("compatibility minimum kernel source should be a string")
            .contains("/v4.8/")
    );
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
            .get("helper_requirement_key")
            .expect("helper requirement key should be present")
            .as_str()
            .expect("helper requirement key should be a string"),
        "helper:bpf_tcp_sock"
    );
    assert_eq!(
        tcp_snd_cwnd
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "5.5"
    );
    assert!(
        tcp_snd_cwnd
            .get("compatibility_minimum_kernel_source")
            .expect("compatibility minimum kernel source should be present")
            .as_str()
            .expect("compatibility minimum kernel source should be a string")
            .contains("/v5.5/")
    );
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
    assert_eq!(
        tcp_snd_cwnd
            .get("read_helper_requirement_key")
            .expect("read helper requirement key should be present")
            .as_str()
            .expect("read helper requirement key should be a string"),
        "helper:bpf_probe_read_kernel"
    );
    assert_eq!(
        tcp_snd_cwnd
            .get("read_helper_minimum_kernel")
            .expect("read helper minimum kernel should be present")
            .as_str()
            .expect("read helper minimum kernel should be a string"),
        "5.5"
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
            .get("context_field_requirement_key")
            .expect("context field requirement key should be present")
            .as_str()
            .expect("context field requirement key should be a string"),
        "ctx:sk"
    );
    assert_eq!(
        sk_family
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "5.5"
    );
    assert_eq!(
        sk_family
            .get("minimum_kernel")
            .expect("minimum kernel should be present")
            .as_str()
            .expect("minimum kernel should be a string"),
        "5.1"
    );
    assert_eq!(
        sk_family
            .get("read_helper_requirement_key")
            .expect("read helper requirement key should be present")
            .as_str()
            .expect("read helper requirement key should be a string"),
        "helper:bpf_probe_read_kernel"
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
fn test_context_projection_compatibility_metadata_invariants() {
    for spec_source in [
        "tc:lo:ingress",
        "cgroup_skb:/sys/fs/cgroup:egress",
        "cgroup_sock:/sys/fs/cgroup:post_bind4",
        "cgroup_sockopt:/sys/fs/cgroup:get",
        "cgroup_sock_addr:/sys/fs/cgroup:connect4",
        "sk_reuseport:select",
        "flow_dissector:/proc/self/ns/net",
    ] {
        let spec = ProgramSpec::parse(spec_source)
            .unwrap_or_else(|err| panic!("{spec_source} should parse: {err}"));

        for projection in spec_context_projections(&spec) {
            if let Some(read_helper_name) = projection.read_helper {
                let read_helper = BpfHelper::from_name(read_helper_name).unwrap_or_else(|| {
                    panic!(
                        "{spec_source} projection {} should use a modeled read helper",
                        projection.path
                    )
                });
                let expected_key = format!("helper:{}", read_helper.name());
                let minimum_kernel = read_helper
                    .minimum_kernel()
                    .expect("read helper should have a minimum kernel");
                assert_eq!(
                    projection.read_helper_requirement_key.as_deref(),
                    Some(expected_key.as_str()),
                    "{spec_source} projection {} should report read helper requirement key",
                    projection.path
                );
                assert_eq!(
                    projection.read_helper_minimum_kernel,
                    Some(minimum_kernel),
                    "{spec_source} projection {} should report read helper minimum kernel",
                    projection.path
                );
                assert!(
                    projection
                        .read_helper_minimum_kernel_source
                        .is_some_and(|source| source.contains(&format!("/v{minimum_kernel}/"))),
                    "{spec_source} projection {} should report read helper source",
                    projection.path
                );
            }
            let component_floors = [
                projection.minimum_kernel,
                projection.helper_minimum_kernel,
                projection.read_helper_minimum_kernel,
            ];
            if component_floors.iter().any(Option::is_some) {
                let compatibility_minimum = projection
                    .compatibility_minimum_kernel
                    .unwrap_or_else(|| {
                        panic!(
                            "{spec_source} projection {} should report an aggregate compatibility minimum kernel",
                            projection.path
                        )
                    });
                assert!(
                    projection.compatibility_minimum_kernel_source.is_some(),
                    "{spec_source} projection {} should report an aggregate compatibility source",
                    projection.path
                );
                for floor in component_floors.into_iter().flatten() {
                    assert!(
                        ContextFieldCompatibilityRequirement::kernel_version_at_least(
                            compatibility_minimum,
                            floor
                        ),
                        "{spec_source} projection {} aggregate floor {compatibility_minimum} should cover component floor {floor}",
                        projection.path
                    );
                }
            }
        }
    }
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
    assert!(
        record
            .get("kernel_target_validation_help")
            .expect("kernel target validation help should be present")
            .as_str()
            .expect("kernel target validation help should be a string")
            .contains("trampoline-compatible target")
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
            .get("kernel_target_validation_help")
            .expect("kernel target validation help should be present")
            .is_nothing()
    );
    assert!(
        record
            .get("btf_callable_surface")
            .expect("BTF callable surface should be present")
            .is_nothing()
    );

    let tp_btf = ProgramSpec::parse("tp_btf:sched_switch").expect("tp_btf spec should parse");
    let record = spec_record(
        "tp_btf:sched_switch".to_string(),
        tp_btf,
        Span::test_data(),
        false,
    )
    .into_record()
    .expect("spec output should be a record");
    assert_eq!(
        record
            .get("kernel_target_validation")
            .expect("kernel target validation should be present")
            .as_str()
            .expect("kernel target validation should be a string"),
        "tp-btf-tracepoint"
    );
    assert!(
        record
            .get("kernel_target_validation_help")
            .expect("kernel target validation help should be present")
            .as_str()
            .expect("kernel target validation help should be a string")
            .contains("BTF-enabled tracepoint")
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
fn test_spec_record_includes_kfunc_call_surface_metadata() {
    let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
    let kfuncs = spec_kfunc_calls(&xdp);
    let timestamp = kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_xdp_metadata_rx_timestamp")
        .expect("XDP metadata timestamp kfunc should be advertised");
    assert_eq!(timestamp.policy, "xdp-only");
    assert_eq!(timestamp.note, "xdp");
    assert_eq!(
        timestamp.requirement_key.as_deref(),
        Some("kfunc:bpf_xdp_metadata_rx_timestamp")
    );
    assert_eq!(timestamp.min_args, Some(2));
    assert_eq!(timestamp.max_args, Some(2));
    assert_eq!(timestamp.arg_kinds, vec!["pointer", "pointer"]);
    assert_eq!(timestamp.return_kind, Some("scalar"));
    assert_eq!(timestamp.pointer_arg_rules.len(), 1);
    assert_eq!(timestamp.pointer_arg_rules[0].arg_idx, 1);
    assert_eq!(timestamp.pointer_arg_rules[0].fixed_size, Some(8));
    assert!(timestamp.pointer_arg_rules[0].allow_stack);
    assert!(timestamp.pointer_arg_rules[0].allow_map);
    assert!(!timestamp.pointer_arg_rules[0].allow_kernel);
    assert_eq!(timestamp.minimum_kernel, Some("6.3"));
    assert!(
        timestamp
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v6.3/net/core/xdp.c"))
    );

    let vlan = kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_xdp_metadata_rx_vlan_tag")
        .expect("XDP metadata VLAN kfunc should be advertised");
    assert_eq!(vlan.minimum_kernel, Some("6.8"));

    let xfrm_get = kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_xdp_get_xfrm_state")
        .expect("XDP XFRM acquire kfunc should be advertised");
    assert_eq!(xfrm_get.policy, "xdp-only");
    assert_eq!(xfrm_get.minimum_kernel, Some("6.8"));
    assert!(
        xfrm_get
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v6.8/net/xfrm/xfrm_state_bpf.c"))
    );
    assert_eq!(xfrm_get.acquire_ref_kind, Some("xfrm_state"));
    assert_eq!(xfrm_get.release_ref_kind, None);
    assert_eq!(xfrm_get.release_arg_idx, None);

    let xfrm_release = kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_xdp_xfrm_state_release")
        .expect("XDP XFRM release kfunc should be advertised");
    assert_eq!(xfrm_release.release_ref_kind, Some("xfrm_state"));
    assert_eq!(xfrm_release.release_arg_idx, Some(0));
    assert_eq!(
        xfrm_release.pointer_arg_ref_kinds,
        vec![SpecKfuncArgRefKind {
            arg_idx: 0,
            ref_kind: "xfrm_state",
        }]
    );

    let xdp_dynptr = kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_dynptr_from_xdp")
        .expect("XDP dynptr kfunc should be advertised");
    assert_eq!(xdp_dynptr.policy, "xdp-only");
    assert_eq!(xdp_dynptr.note, "xdp");

    let record = spec_record("xdp:lo".to_string(), xdp, Span::test_data(), false)
        .into_record()
        .expect("spec output should be a record");
    let record_kfuncs = record
        .get("kfunc_calls")
        .expect("kfunc_calls should be present")
        .as_list()
        .expect("kfunc_calls should be a list");
    assert!(record_kfuncs.iter().any(|value| {
        value
            .as_record()
            .ok()
            .and_then(|record| record.get("kfunc"))
            .and_then(|value| value.as_str().ok())
            .is_some_and(|name| name == "bpf_xdp_metadata_rx_hash")
    }));
    let timestamp_record = record_kfuncs
        .iter()
        .find_map(|value| {
            let record = value.as_record().ok()?;
            (record
                .get("kfunc")?
                .as_str()
                .ok()
                .is_some_and(|name| name == "bpf_xdp_metadata_rx_timestamp"))
            .then_some(record)
        })
        .expect("timestamp kfunc record should be present");
    assert_eq!(
        timestamp_record
            .get("return_kind")
            .expect("return kind should be present")
            .as_str()
            .expect("return kind should be a string"),
        "scalar"
    );
    let pointer_arg_rules = timestamp_record
        .get("pointer_arg_rules")
        .expect("pointer arg rules should be present")
        .as_list()
        .expect("pointer arg rules should be a list");
    let timestamp_rule = pointer_arg_rules
        .first()
        .expect("timestamp kfunc should report a pointer arg rule")
        .as_record()
        .expect("pointer arg rule should be a record");
    assert_eq!(
        timestamp_rule
            .get("fixed_size")
            .expect("fixed size should be present")
            .as_int()
            .expect("fixed size should be an int"),
        8
    );
    let xfrm_release_record = record_kfuncs
        .iter()
        .find_map(|value| {
            let record = value.as_record().ok()?;
            (record
                .get("kfunc")?
                .as_str()
                .ok()
                .is_some_and(|name| name == "bpf_xdp_xfrm_state_release"))
            .then_some(record)
        })
        .expect("xfrm release kfunc record should be present");
    assert_eq!(
        xfrm_release_record
            .get("release_ref_kind")
            .expect("release ref kind should be present")
            .as_str()
            .expect("release ref kind should be a string"),
        "xfrm_state"
    );
    assert_eq!(
        xfrm_release_record
            .get("release_arg_idx")
            .expect("release arg index should be present")
            .as_int()
            .expect("release arg index should be an int"),
        0
    );
    let release_arg_ref_kinds = xfrm_release_record
        .get("pointer_arg_ref_kinds")
        .expect("pointer arg ref kinds should be present")
        .as_list()
        .expect("pointer arg ref kinds should be a list");
    let release_ref_kind = release_arg_ref_kinds
        .first()
        .expect("xfrm release should report one pointer arg ref kind")
        .as_record()
        .expect("pointer arg ref kind should be a record");
    assert_eq!(
        release_ref_kind
            .get("ref_kind")
            .expect("ref kind should be present")
            .as_str()
            .expect("ref kind should be a string"),
        "xfrm_state"
    );
    assert_eq!(
        release_ref_kind
            .get("arg_idx")
            .expect("arg index should be present")
            .as_int()
            .expect("arg index should be an int"),
        0
    );

    let tc = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
    let tc_kfuncs = spec_kfunc_calls(&tc);
    let skb_dynptr = tc_kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_dynptr_from_skb")
        .expect("TC skb dynptr kfunc should be advertised");
    assert_eq!(skb_dynptr.policy, "skb-packet-dynptr");
    assert_eq!(skb_dynptr.note, "skb-backed program");
    assert_eq!(skb_dynptr.minimum_kernel, Some("6.4"));

    let fentry = ProgramSpec::parse("fentry:tcp_sendmsg").expect("fentry spec should parse");
    let fentry_kfuncs = spec_kfunc_calls(&fentry);
    let tracing_skb_dynptr = fentry_kfuncs
        .iter()
        .find(|surface| surface.kfunc == "bpf_dynptr_from_skb")
        .expect("tracing skb dynptr kfunc should be advertised");
    assert_eq!(tracing_skb_dynptr.policy, "skb-tracing-dynptr");
    assert_eq!(
        tracing_skb_dynptr.note,
        "tracing program with sk_buff argument"
    );
    assert_eq!(tracing_skb_dynptr.minimum_kernel, Some("6.12"));
    assert!(
        tracing_skb_dynptr
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v6.12/net/core/filter.c"))
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
    assert_eq!(
        intrinsic_context_field_requirements("tc:lo:ingress", "assign-socket")
            .into_iter()
            .map(|(field, key, minimum, _source)| (field, key, minimum))
            .collect::<Vec<_>>(),
        vec![("sk".to_string(), "ctx:sk".to_string(), "5.1".to_string())]
    );
    assert_eq!(
        intrinsic_context_field_requirements("tc_action:diff-action", "assign-socket")
            .into_iter()
            .map(|(field, key, minimum, _source)| (field, key, minimum))
            .collect::<Vec<_>>(),
        vec![("sk".to_string(), "ctx:sk".to_string(), "5.1".to_string())]
    );
    let sk_lookup_assign_socket_context =
        intrinsic_context_field_requirements("sk_lookup:/proc/self/ns/net", "assign-socket");
    assert_eq!(
        sk_lookup_assign_socket_context
            .iter()
            .map(|(field, key, minimum, _source)| {
                (field.as_str(), key.as_str(), minimum.as_str())
            })
            .collect::<Vec<_>>(),
        vec![("sk", "ctx:sk", "5.9")]
    );
    assert!(
        sk_lookup_assign_socket_context
            .first()
            .is_some_and(|(_field, _key, _minimum, source)| source.contains("/v5.9/")),
        "{sk_lookup_assign_socket_context:?}"
    );
    let (tc_assign_minimum, tc_assign_source) =
        intrinsic_compatibility_floor("tc:lo:ingress", "assign-socket");
    assert_eq!(tc_assign_minimum.as_deref(), Some("5.7"));
    assert!(
        tc_assign_source
            .as_deref()
            .is_some_and(|source| source.contains("include/uapi/linux/bpf.h")),
        "{tc_assign_source:?}"
    );
    let (sk_lookup_assign_minimum, sk_lookup_assign_source) =
        intrinsic_compatibility_floor("sk_lookup:/proc/self/ns/net", "assign-socket");
    assert_eq!(sk_lookup_assign_minimum.as_deref(), Some("5.9"));
    assert!(
        sk_lookup_assign_source
            .as_deref()
            .is_some_and(|source| source.contains("/v5.9/")),
        "{sk_lookup_assign_source:?}"
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
    let (redirect_map_compatibility_minimum, redirect_map_compatibility_source) =
        intrinsic_compatibility_floor("xdp:lo", "redirect-map");
    assert_eq!(redirect_map_compatibility_minimum.as_deref(), Some("4.14"));
    assert!(
        redirect_map_compatibility_source
            .as_deref()
            .is_some_and(|source| source.contains("include/uapi/linux/bpf.h")),
        "{redirect_map_compatibility_source:?}"
    );
    let redirect_map_intrinsic = intrinsic_record("xdp:lo", "redirect-map");
    let redirect_map_helpers = redirect_map_intrinsic
        .as_record()
        .expect("redirect-map intrinsic should be a record")
        .get("backing_helpers")
        .expect("backing helpers should be present")
        .as_list()
        .expect("backing helpers should be a list");
    let redirect_map_helper = redirect_map_helpers
        .first()
        .expect("redirect-map should have a backing helper")
        .as_record()
        .expect("backing helper should be a record");
    assert_eq!(
        redirect_map_helper
            .get("helper_requirement_key")
            .expect("helper requirement key should be present")
            .as_str()
            .expect("helper requirement key should be a string"),
        "helper:bpf_redirect_map"
    );

    let (assign_socket_minimum, assign_socket_source) =
        intrinsic_backing_helper_kernel_floor("tc:lo:ingress", "assign-socket", "bpf_sk_assign");
    assert_eq!(assign_socket_minimum, "5.7");
    assert!(
        assign_socket_source.contains("include/uapi/linux/bpf.h"),
        "{assign_socket_source}"
    );

    let (helper_call_minimum, helper_call_source) =
        intrinsic_compatibility_floor("raw_tracepoint:sys_enter", "helper-call");
    assert_eq!(helper_call_minimum, None);
    assert_eq!(helper_call_source, None);
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

    let xdp_redirect_map = intrinsic_variant_entries("xdp:lo", "redirect-map");
    assert!(xdp_redirect_map.contains(&(
        "kind".to_string(),
        "devmap".to_string(),
        "bpf_redirect_map".to_string()
    )));
    assert!(xdp_redirect_map.contains(&(
        "kind".to_string(),
        "devmap-hash".to_string(),
        "bpf_redirect_map".to_string()
    )));
    assert!(xdp_redirect_map.contains(&(
        "kind".to_string(),
        "cpumap".to_string(),
        "bpf_redirect_map".to_string()
    )));
    assert!(xdp_redirect_map.contains(&(
        "kind".to_string(),
        "xskmap".to_string(),
        "bpf_redirect_map".to_string()
    )));
    let devmap_hash = intrinsic_variant_record_by("xdp:lo", "redirect-map", "kind", "devmap-hash");
    assert_eq!(
        devmap_hash
            .get("map_kind")
            .expect("map kind should be present")
            .as_str()
            .expect("map kind should be a string"),
        "devmap-hash"
    );
    assert_eq!(
        devmap_hash
            .get("map_requirement_key")
            .expect("map requirement key should be present")
            .as_str()
            .expect("map requirement key should be a string"),
        "map:BPF_MAP_TYPE_DEVMAP_HASH"
    );
    assert_eq!(
        devmap_hash
            .get("map_minimum_kernel")
            .expect("map minimum kernel should be present")
            .as_str()
            .expect("map minimum kernel should be a string"),
        "5.4"
    );
    assert!(
        devmap_hash
            .get("map_minimum_kernel_source")
            .expect("map minimum kernel source should be present")
            .as_str()
            .expect("map minimum kernel source should be a string")
            .contains("/v5.4/")
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
    let sockhash = intrinsic_variant_record_by(
        "sk_skb:/sys/fs/bpf/demo_sockmap",
        "redirect-socket",
        "kind",
        "sockhash",
    );
    assert_eq!(
        sockhash
            .get("map_minimum_kernel")
            .expect("socket map variant minimum kernel should be present")
            .as_str()
            .expect("socket map variant minimum kernel should be a string"),
        "4.18"
    );
    assert_eq!(
        intrinsic_variant_entries("sk_reuseport:select", "redirect-socket"),
        vec![(
            "kind".to_string(),
            "reuseport-sockarray".to_string(),
            "bpf_sk_select_reuseport".to_string(),
        )]
    );

    let raw_map_get = intrinsic_variant_entries("raw_tracepoint:sys_enter", "map-get");
    assert!(raw_map_get.contains(&(
        "kind".to_string(),
        "hash".to_string(),
        "bpf_map_lookup_elem".to_string()
    )));
    assert!(raw_map_get.contains(&(
        "kind".to_string(),
        "lru-per-cpu-hash".to_string(),
        "bpf_map_lookup_elem".to_string()
    )));
    assert!(raw_map_get.contains(&(
        "kind".to_string(),
        "task-storage".to_string(),
        "bpf_task_storage_get".to_string()
    )));
    assert!(!raw_map_get.iter().any(|(_, value, _)| value == "sockmap"));

    let tc_map_contains = intrinsic_variant_entries("tc:lo:ingress", "map-contains");
    assert!(tc_map_contains.contains(&(
        "kind".to_string(),
        "bloom-filter".to_string(),
        "bpf_map_peek_elem".to_string()
    )));
    assert!(tc_map_contains.contains(&(
        "kind".to_string(),
        "cgroup-array".to_string(),
        "bpf_skb_under_cgroup".to_string()
    )));
    let xdp_cgroup_array =
        intrinsic_variant_record_by("xdp:lo", "map-contains", "kind", "cgroup-array");
    assert_eq!(
        xdp_cgroup_array
            .get("backing_helper")
            .expect("cgroup-array map-contains helper should be present")
            .as_str()
            .expect("cgroup-array helper should be a string"),
        "bpf_current_task_under_cgroup"
    );
    assert_eq!(
        xdp_cgroup_array
            .get("helper_requirement_key")
            .expect("cgroup-array helper requirement key should be present")
            .as_str()
            .expect("cgroup-array helper requirement key should be a string"),
        "helper:bpf_current_task_under_cgroup"
    );

    let sock_ops_map_put = intrinsic_variant_entries("sock_ops:/sys/fs/cgroup", "map-put");
    assert!(sock_ops_map_put.contains(&(
        "kind".to_string(),
        "sockmap".to_string(),
        "bpf_sock_map_update".to_string()
    )));
    assert!(sock_ops_map_put.contains(&(
        "kind".to_string(),
        "sockhash".to_string(),
        "bpf_sock_hash_update".to_string()
    )));

    assert_eq!(
        intrinsic_variant_entries("raw_tracepoint:sys_enter", "map-pop"),
        vec![
            (
                "kind".to_string(),
                "queue".to_string(),
                "bpf_map_pop_elem".to_string(),
            ),
            (
                "kind".to_string(),
                "stack".to_string(),
                "bpf_map_pop_elem".to_string(),
            ),
        ]
    );
    let bloom_push = intrinsic_variant_record_by(
        "raw_tracepoint:sys_enter",
        "map-push",
        "kind",
        "bloom-filter",
    );
    assert_eq!(
        bloom_push
            .get("map_requirement_key")
            .expect("bloom-filter map-push requirement should be present")
            .as_str()
            .expect("bloom-filter map-push requirement should be a string"),
        "map:BPF_MAP_TYPE_BLOOM_FILTER"
    );
    assert_eq!(
        intrinsic_variant_entries("raw_tracepoint:sys_enter", "tail-call"),
        vec![(
            "kind".to_string(),
            "prog-array".to_string(),
            "bpf_tail_call".to_string(),
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

    let state = field(&fields, "state");
    assert!(state.names.contains(&"nf_state"));
    let pf = field(&fields, "pf");
    assert!(pf.names.contains(&"protocol_family"));
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

    let sample = field(&fields, "sample");
    assert!(sample.names.contains(&"raw"));
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
fn test_spec_context_fields_include_tc_action_skb_metadata_minimum_kernel_metadata() {
    let spec = ProgramSpec::parse("tc_action:demo-action").expect("tc_action spec should parse");
    let fields = spec_context_fields(&spec, false);

    for (field_name, minimum_kernel, source_fragment) in [
        ("queue_mapping", "4.1", "/v4.1/include/uapi/linux/bpf.h"),
        ("tc_index", "4.7", "/v4.7/include/uapi/linux/bpf.h"),
        ("tc_classid", "4.7", "/v4.7/include/uapi/linux/bpf.h"),
        ("data_meta", "4.15", "/v4.15/include/uapi/linux/bpf.h"),
        ("wire_len", "5.0", "/v5.0/include/uapi/linux/bpf.h"),
        ("gso_segs", "5.1", "/v5.1/include/uapi/linux/bpf.h"),
        ("gso_size", "5.7", "/v5.7/include/uapi/linux/bpf.h"),
        ("hwtstamp", "5.16", "/v5.16/include/uapi/linux/bpf.h"),
        ("tstamp_type", "5.18", "/v5.18/include/uapi/linux/bpf.h"),
    ] {
        let field = field(&fields, field_name);
        assert_eq!(field.minimum_kernel, Some(minimum_kernel));
        assert!(
            field
                .minimum_kernel_source
                .is_some_and(|source| source.contains(source_fragment)),
            "ctx.{field_name} should point at {source_fragment}"
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
        (
            "iter:ipv6_route",
            "iter_ipv6_route",
            "5.8",
            "/v5.8/net/ipv6/route.c",
        ),
        ("iter:ksym", "iter_ksym", "6.0", "/v6.0/kernel/kallsyms.c"),
        (
            "iter:netlink",
            "iter_netlink_sk",
            "5.8",
            "/v5.8/net/netlink/af_netlink.c",
        ),
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

    let packet_len = field(&select_fields, "packet_len");
    assert!(packet_len.names.contains(&"len"));
    let protocol = field(&select_fields, "protocol");
    assert!(protocol.names.contains(&"ip_protocol"));
    let socket_cookie = field(&select_fields, "socket_cookie");
    assert_eq!(socket_cookie.minimum_kernel, Some("4.12"));
    assert_eq!(
        socket_cookie.requirement_key.as_deref(),
        Some("ctx:socket_cookie")
    );
    assert_eq!(
        socket_cookie.backing_helper_requirement_key.as_deref(),
        Some("helper:bpf_get_socket_cookie")
    );
    assert!(
        socket_cookie
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.12/include/uapi/linux/bpf.h"))
    );

    for spec_text in ["sk_reuseport:select", "sk_reuseport:migrate"] {
        let spec = ProgramSpec::parse(spec_text).expect("sk_reuseport spec should parse");
        let fields = spec_context_fields(&spec, false);

        for field_name in ["sk", "migrating_sk"] {
            let field = field(&fields, field_name);
            assert_eq!(field.minimum_kernel, Some("5.14"));
            assert!(
                field
                    .minimum_kernel_source
                    .is_some_and(|source| source.contains("/v5.14/include/uapi/linux/bpf.h"))
            );
        }
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

    let iter = ProgramSpec::parse("iter:bpf_link").expect("iter bpf_link spec should parse");
    let record = spec_record("iter:bpf_link".to_string(), iter, Span::test_data(), false)
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
        "iterator"
    );
    assert_eq!(
        attach_shape
            .get("target_kind")
            .expect("iterator target kind should be present")
            .as_str()
            .expect("iterator target kind should be a string"),
        "bpf_link"
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
    assert_eq!(
        record
            .get("live_attach_status")
            .expect("live_attach_status should be present")
            .as_str()
            .expect("live_attach_status should be a string"),
        "unsupported"
    );
    assert_eq!(
        record
            .get("live_attach_unsupported_reason")
            .expect("live_attach_unsupported_reason should be present")
            .as_str()
            .expect("live_attach_unsupported_reason should be a string"),
        "struct-ops-callback-target"
    );
    assert_eq!(
        record
            .get("live_attach_note")
            .expect("live_attach_note should be present")
            .as_str()
            .expect("live_attach_note should be a string"),
        ProgramLiveAttachUnsupportedReason::StructOpsCallback.note()
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
    assert_eq!(
        family.context_field_requirement_key.as_deref(),
        Some("ctx:family")
    );
    assert_eq!(family.minimum_kernel, Some("4.10"));
    assert_eq!(family.compatibility_minimum_kernel, Some("5.5"));
    assert!(
        family
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.10/include/uapi/linux/bpf.h"))
    );
    assert_eq!(family.helper, None);
    assert_eq!(family.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(
        family.read_helper_requirement_key.as_deref(),
        Some("helper:bpf_probe_read_kernel")
    );
    assert_eq!(family.read_helper_minimum_kernel, Some("5.5"));
    assert_eq!(family.ty, "u32");
    assert_eq!(family.offset, Some(4));
    assert!(family.supported);
    assert!(family.unsupported_reason.is_none());

    let remote_port = projection(&projections, "sk.remote_port");
    assert_eq!(remote_port.root, "sk");
    assert_eq!(remote_port.name, "remote_port");
    assert_eq!(remote_port.source, "context_field_alias");
    assert_eq!(
        remote_port.context_field_requirement_key.as_deref(),
        Some("ctx:remote_port")
    );
    assert_eq!(remote_port.minimum_kernel, Some("5.1"));
    assert_eq!(remote_port.compatibility_minimum_kernel, Some("5.5"));
    assert_eq!(remote_port.helper, None);
    assert_eq!(remote_port.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(remote_port.ty, "u16");
    assert_eq!(remote_port.offset, Some(48));
    assert!(remote_port.supported);
    assert!(remote_port.unsupported_reason.is_none());

    let sock_family = projection(&projections, "sock.family");
    assert_eq!(sock_family.root, "sock");
    assert_eq!(sock_family.name, "family");
    assert_eq!(sock_family.source, "context_field_root_alias");
    assert_eq!(sock_family.ty, "u32");
    assert_eq!(sock_family.offset, Some(4));

    let socket_remote_port = projection(&projections, "socket.remote_port");
    assert_eq!(socket_remote_port.root, "socket");
    assert_eq!(socket_remote_port.source, "context_field_alias");
    assert_eq!(socket_remote_port.offset, remote_port.offset);

    projection_absent(&projections, "sk.src_ip4");
    projection_absent(&projections, "sk.local_ip4");
}

#[test]
fn test_spec_context_projections_include_flow_key_alias_members() {
    let spec = ProgramSpec::parse("flow_dissector:/proc/self/ns/net")
        .expect("flow_dissector spec should parse");
    let projections = spec_context_projections(&spec);

    let protocol = projection(&projections, "flow_keys.protocol");
    assert_eq!(protocol.root, "flow_keys");
    assert_eq!(protocol.name, "protocol");
    assert_eq!(protocol.source, "context_field_alias");
    assert_eq!(
        protocol.context_field_requirement_key.as_deref(),
        Some("ctx:flow_keys")
    );
    assert_eq!(protocol.minimum_kernel, Some("4.20"));
    assert_eq!(protocol.compatibility_minimum_kernel, Some("4.20"));
    assert_eq!(protocol.ty, "u8");
    assert_eq!(protocol.offset, Some(9));
    assert!(protocol.supported);
    assert!(protocol.unsupported_reason.is_none());

    let dst_ip6 = projection(&projections, "flow_keys.dst_ip6");
    assert_eq!(dst_ip6.source, "context_field_alias");
    assert_eq!(dst_ip6.ty, "array<u32; 4>");
    assert_eq!(dst_ip6.offset, Some(32));

    let canonical_dst_ip6 = projection(&projections, "flow_keys.ipv6_dst");
    assert_eq!(dst_ip6.offset, canonical_dst_ip6.offset);
}

#[test]
fn test_spec_context_projections_include_helper_backed_socket_members() {
    let spec = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
    let projections = spec_context_projections(&spec);
    let mut seen_paths = HashSet::new();
    for projection in &projections {
        assert!(
            seen_paths.insert(projection.path.as_str()),
            "duplicate context projection path {}",
            projection.path
        );
    }

    let tcp_snd_cwnd = projection(&projections, "sk.tcp.snd_cwnd");
    assert_eq!(tcp_snd_cwnd.root, "sk.tcp");
    assert_eq!(tcp_snd_cwnd.name, "snd_cwnd");
    assert_eq!(tcp_snd_cwnd.source, "helper_return");
    assert_eq!(tcp_snd_cwnd.helper, Some("bpf_tcp_sock"));
    assert_eq!(tcp_snd_cwnd.context_field_requirement_key, None);
    assert_eq!(tcp_snd_cwnd.helper_minimum_kernel, Some("5.1"));
    assert_eq!(tcp_snd_cwnd.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(
        tcp_snd_cwnd.read_helper_requirement_key.as_deref(),
        Some("helper:bpf_probe_read_kernel")
    );
    assert_eq!(tcp_snd_cwnd.read_helper_minimum_kernel, Some("5.5"));
    assert_eq!(tcp_snd_cwnd.compatibility_minimum_kernel, Some("5.5"));
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
    assert_eq!(full_family.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(full_family.compatibility_minimum_kernel, Some("5.5"));
    assert_eq!(full_family.ty, "u32");
    assert!(full_family.supported);
    assert!(full_family.unsupported_reason.is_none());

    let full_remote_port = projection(&projections, "sk.full.remote_port");
    assert_eq!(full_remote_port.root, "sk.full");
    assert_eq!(full_remote_port.name, "remote_port");
    assert_eq!(full_remote_port.source, "helper_return_alias");
    assert_eq!(full_remote_port.helper, Some("bpf_sk_fullsock"));
    assert_eq!(full_remote_port.helper_minimum_kernel, Some("5.1"));
    assert_eq!(full_remote_port.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(full_remote_port.compatibility_minimum_kernel, Some("5.5"));
    assert_eq!(full_remote_port.ty, "u16");
    assert_eq!(full_remote_port.offset, Some(48));
    assert!(full_remote_port.supported);
    assert!(full_remote_port.unsupported_reason.is_none());

    let sk_family = projection(&projections, "sk.family");
    assert_eq!(
        sk_family.context_field_requirement_key.as_deref(),
        Some("ctx:sk")
    );
    assert_eq!(sk_family.minimum_kernel, Some("5.1"));
    assert_eq!(sk_family.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(sk_family.compatibility_minimum_kernel, Some("5.5"));

    let sock_tcp_snd_cwnd = projection(&projections, "sock.tcp.snd_cwnd");
    assert_eq!(sock_tcp_snd_cwnd.root, "sock.tcp");
    assert_eq!(sock_tcp_snd_cwnd.source, "helper_return");
    assert_eq!(sock_tcp_snd_cwnd.helper, Some("bpf_tcp_sock"));
    assert_eq!(sock_tcp_snd_cwnd.read_helper, Some("bpf_probe_read_kernel"));
    assert_eq!(sock_tcp_snd_cwnd.offset, tcp_snd_cwnd.offset);

    let socket_full_remote_port = projection(&projections, "socket.full.remote_port");
    assert_eq!(socket_full_remote_port.root, "socket.full");
    assert_eq!(socket_full_remote_port.source, "helper_return_alias");
    assert_eq!(socket_full_remote_port.helper, Some("bpf_sk_fullsock"));
    assert_eq!(socket_full_remote_port.offset, full_remote_port.offset);
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

    let local_ip4 = projection(&projections, "sk.local_ip4");
    assert!(local_ip4.supported);
    assert_eq!(local_ip4.source, "context_field_alias");
    assert_eq!(local_ip4.minimum_kernel, Some("4.17"));
    assert_eq!(local_ip4.offset, src_ip4.offset);
    assert!(local_ip4.unsupported_reason.is_none());

    projection_absent(&projections, "sk.src_ip6");
    projection_absent(&projections, "sk.local_ip6");
}

#[test]
fn test_spec_context_projections_include_migrating_socket_alias_members() {
    let spec =
        ProgramSpec::parse("sk_reuseport:migrate").expect("sk_reuseport migrate spec should parse");
    let projections = spec_context_projections(&spec);

    let root_alias_family = projection(&projections, "migrating_socket.family");
    assert_eq!(root_alias_family.root, "migrating_socket");
    assert_eq!(root_alias_family.name, "family");
    assert_eq!(root_alias_family.source, "context_field_root_alias");
    assert_eq!(root_alias_family.ty, "u32");
    assert_eq!(root_alias_family.offset, Some(4));
    assert!(root_alias_family.supported);
    assert!(root_alias_family.unsupported_reason.is_none());

    let remote_port = projection(&projections, "migrating_sk.remote_port");
    assert_eq!(remote_port.root, "migrating_sk");
    assert_eq!(remote_port.name, "remote_port");
    assert_eq!(remote_port.source, "context_field_alias");
    assert_eq!(remote_port.ty, "u16");
    assert_eq!(remote_port.offset, Some(48));
    assert!(remote_port.supported);
    assert!(remote_port.unsupported_reason.is_none());

    let root_alias_remote_port = projection(&projections, "migrating_socket.remote_port");
    assert_eq!(root_alias_remote_port.root, "migrating_socket");
    assert_eq!(root_alias_remote_port.source, "context_field_alias");
    assert_eq!(root_alias_remote_port.offset, remote_port.offset);
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

    let sock_cgroup = projection(&cgroup_skb_projections, "sock.cgroup_id");
    assert_eq!(sock_cgroup.root, "sock");
    assert_eq!(sock_cgroup.helper, Some("bpf_sk_cgroup_id"));
    assert_eq!(sock_cgroup.helper_minimum_kernel, Some("5.8"));
    assert_eq!(sock_cgroup.ty, "u64");
    assert_eq!(sock_cgroup.offset, None);

    let sk_ancestor = projection(&cgroup_skb_projections, "sk.ancestor_cgroup_id.N");
    assert_eq!(sk_ancestor.root, "sk");
    assert_eq!(sk_ancestor.name, "ancestor_cgroup_id.N");
    assert_eq!(sk_ancestor.helper, Some("bpf_sk_ancestor_cgroup_id"));
    assert_eq!(sk_ancestor.helper_minimum_kernel, Some("5.8"));
    assert_eq!(sk_ancestor.ty, "u64");
    assert_eq!(sk_ancestor.offset, None);

    let socket_ancestor = projection(&cgroup_skb_projections, "socket.ancestor_cgroup_id.N");
    assert_eq!(socket_ancestor.root, "socket");
    assert_eq!(socket_ancestor.helper, Some("bpf_sk_ancestor_cgroup_id"));
    assert_eq!(socket_ancestor.helper_minimum_kernel, Some("5.8"));
    assert_eq!(socket_ancestor.ty, "u64");
    assert_eq!(socket_ancestor.offset, None);

    let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
    let tc_ingress_projections = spec_context_projections(&tc_ingress);
    projection_absent(&tc_ingress_projections, "skb_ancestor_cgroup_id.N");

    let sk_msg =
        ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap").expect("sk_msg spec should parse");
    let sk_msg_projections = spec_context_projections(&sk_msg);
    projection_absent(&sk_msg_projections, "sk.cgroup_id");
    projection_absent(&sk_msg_projections, "sock.cgroup_id");
    projection_absent(&sk_msg_projections, "sk.ancestor_cgroup_id.N");
    projection_absent(&sk_msg_projections, "socket.ancestor_cgroup_id.N");
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

        let projections = spec_context_projections(&spec);
        let mut seen_paths = HashSet::new();
        for projection in projections {
            assert!(
                seen_paths.insert(projection.path.clone()),
                "{program_type:?} exposed duplicate projection {}",
                projection.path
            );
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
    for field in &fields {
        if field.source == "well-known-syscall-fallback" {
            assert_eq!(field.minimum_kernel, Some("4.7"));
            assert!(
                field
                    .minimum_kernel_source
                    .is_some_and(|source| source.contains("/v4.7/include/trace/events/syscalls.h"))
            );
        } else {
            assert_eq!(field.minimum_kernel, None);
            assert_eq!(field.minimum_kernel_source, None);
        }
    }
}

#[test]
fn test_spec_tracepoint_openat2_uses_kernel_argument_names() {
    let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat2")
        .expect("tracepoint spec should parse");
    let (fields, err) = spec_tracepoint_fields(&spec, true);

    if fields.is_empty() {
        assert!(err.is_some(), "expected tracepoint fields or an error");
        return;
    }

    assert!(
        tracepoint_field(&fields, "usize").is_some(),
        "openat2 should expose the kernel syscall argument name 'usize'"
    );
    assert!(
        tracepoint_field(&fields, "size").is_none(),
        "openat2 fallback should not invent a 'size' alias that tracefs does not expose"
    );
}

#[test]
fn test_spec_tracepoint_fallback_fields_use_field_specific_kernel_metadata() {
    let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_connect")
        .expect("tracepoint spec should parse");
    let fields = spec_tracepoint_fields_from_context(
        &spec,
        crate::kernel_btf::TracepointContext::sys_enter("sys_enter_connect"),
    );
    let uservaddr =
        tracepoint_field(&fields, "uservaddr").expect("connect fallback should expose uservaddr");
    assert_eq!(uservaddr.source, "well-known-syscall-fallback");
    assert_eq!(uservaddr.minimum_kernel, Some("4.7"));
    assert!(
        uservaddr
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.7/net/socket.c"))
    );

    let args = tracepoint_field(&fields, "args").expect("connect fallback should expose args");
    assert_eq!(args.minimum_kernel, Some("4.7"));
    assert!(
        args.minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.7/include/trace/events/syscalls.h"))
    );
}

#[test]
fn test_tracepoint_field_records_include_fallback_kernel_metadata() {
    let records = tracepoint_field_records(
        vec![SpecTracepointField {
            name: "args".to_string(),
            ty: "array<u64;6>".to_string(),
            offset: 16,
            size: 48,
            bit_offset: None,
            bit_size: None,
            source: "well-known-syscall-fallback",
            source_path: None,
            context_struct: "trace_event_raw_sys_enter_openat".to_string(),
            context_size: 64,
            minimum_kernel: Some("4.7"),
            minimum_kernel_source: Some(
                "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h",
            ),
        }],
        Span::test_data(),
    );
    let record = records
        .first()
        .expect("expected tracepoint field record")
        .as_record()
        .expect("tracepoint field should render as a record");
    assert_eq!(
        record
            .get("minimum_kernel")
            .expect("minimum_kernel should be present")
            .as_str()
            .expect("minimum_kernel should be a string"),
        "4.7"
    );
    assert!(
        record
            .get("minimum_kernel_source")
            .expect("minimum_kernel_source should be present")
            .as_str()
            .expect("minimum_kernel_source should be a string")
            .contains("/v4.7/include/trace/events/syscalls.h")
    );
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
    fn assert_socket_assign_writes(writes: &[SpecContextWrite], context: &str) {
        for field_name in ["sk", "sock", "socket"] {
            assert!(
                writes.iter().any(|surface| {
                    surface.field == field_name
                        && surface.kind == "assign-socket"
                        && !surface.indexed
                }),
                "{context} should advertise ctx.{field_name} assignment"
            );
        }
    }

    fn assert_no_socket_assign_writes(writes: &[SpecContextWrite], context: &str) {
        for field_name in ["sk", "sock", "socket"] {
            assert!(
                !writes.iter().any(|surface| surface.field == field_name),
                "{context} should not advertise ctx.{field_name} assignment"
            );
        }
    }

    let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
    let tc_ingress_writes = spec_context_writes(&tc_ingress);
    assert_socket_assign_writes(&tc_ingress_writes, "tc ingress");

    let tc_egress = ProgramSpec::parse("tc:lo:egress").expect("tc egress spec should parse");
    let tc_egress_writes = spec_context_writes(&tc_egress);
    assert_no_socket_assign_writes(&tc_egress_writes, "tc egress");

    let tcx_ingress = ProgramSpec::parse("tcx:lo:ingress").expect("tcx ingress spec should parse");
    let tcx_ingress_writes = spec_context_writes(&tcx_ingress);
    assert_socket_assign_writes(&tcx_ingress_writes, "tcx ingress");

    let tcx_egress = ProgramSpec::parse("tcx:lo:egress").expect("tcx egress spec should parse");
    let tcx_egress_writes = spec_context_writes(&tcx_egress);
    assert_no_socket_assign_writes(&tcx_egress_writes, "tcx egress");

    let tc_action =
        ProgramSpec::parse("tc_action:diff-action").expect("tc_action spec should parse");
    let tc_action_writes = spec_context_writes(&tc_action);
    assert_socket_assign_writes(&tc_action_writes, "tc_action");

    let sk_lookup =
        ProgramSpec::parse("sk_lookup:/proc/self/ns/net").expect("sk_lookup spec should parse");
    let sk_lookup_writes = spec_context_writes(&sk_lookup);
    assert_socket_assign_writes(&sk_lookup_writes, "sk_lookup");

    let netkit = ProgramSpec::parse("netkit:lo:primary").expect("netkit spec should parse");
    let netkit_writes = spec_context_writes(&netkit);
    assert_no_socket_assign_writes(&netkit_writes, "netkit");
}

#[test]
fn test_context_write_records_include_backing_abi_metadata() {
    let sock_ops =
        ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let sock_ops_writes = spec_context_writes(&sock_ops);
    let reply = context_write(&sock_ops_writes, "reply");
    assert_eq!(reply.kind, "store");
    assert_eq!(
        reply.context_field_requirement_key.as_deref(),
        Some("ctx:reply")
    );
    assert_eq!(reply.minimum_kernel, Some("4.14"));
    assert!(reply.helper.is_none());

    let replylong = context_write(&sock_ops_writes, "replylong");
    assert_eq!(replylong.kind, "store");
    assert!(replylong.indexed);
    assert_eq!(
        replylong.context_field_requirement_key.as_deref(),
        Some("ctx:replylong")
    );
    assert_eq!(replylong.minimum_kernel, Some("4.14"));

    let cb_flags = context_write(&sock_ops_writes, "cb_flags");
    assert_eq!(cb_flags.kind, "store");
    assert_eq!(
        cb_flags.context_field_requirement_key.as_deref(),
        Some("ctx:cb_flags")
    );
    assert_eq!(cb_flags.minimum_kernel, Some("4.16"));
    assert_eq!(cb_flags.helper, Some("bpf_sock_ops_cb_flags_set"));
    assert_eq!(
        cb_flags.helper_requirement_key.as_deref(),
        Some("helper:bpf_sock_ops_cb_flags_set")
    );
    assert_eq!(cb_flags.helper_minimum_kernel, Some("4.16"));
    assert!(cb_flags.kfunc.is_none());

    let cgroup_sock = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
        .expect("cgroup_sock spec should parse");
    let cgroup_sock_writes = spec_context_writes(&cgroup_sock);
    let bound_dev_if = context_write(&cgroup_sock_writes, "bound_dev_if");
    assert_eq!(
        bound_dev_if.context_field_requirement_key.as_deref(),
        Some("ctx:bound_dev_if")
    );
    assert_eq!(bound_dev_if.minimum_kernel, Some("4.10"));
    let mark = context_write(&cgroup_sock_writes, "mark");
    assert_eq!(
        mark.context_field_requirement_key.as_deref(),
        Some("ctx:mark")
    );
    assert_eq!(mark.minimum_kernel, Some("4.14"));

    let cgroup_sysctl = ProgramSpec::parse("cgroup_sysctl:/sys/fs/cgroup")
        .expect("cgroup_sysctl spec should parse");
    let cgroup_sysctl_writes = spec_context_writes(&cgroup_sysctl);
    let new_value = context_write(&cgroup_sysctl_writes, "new_value");
    assert_eq!(new_value.kind, "sysctl-new-value");
    assert_eq!(
        new_value.context_field_requirement_key.as_deref(),
        Some("ctx:sysctl_new_value")
    );
    assert_eq!(new_value.helper, Some("bpf_sysctl_set_new_value"));
    assert_eq!(
        new_value.helper_requirement_key.as_deref(),
        Some("helper:bpf_sysctl_set_new_value")
    );
    assert_eq!(new_value.helper_minimum_kernel, Some("5.2"));
    assert_eq!(new_value.compatibility_minimum_kernel, Some("5.2"));

    let tc_ingress = ProgramSpec::parse("tc:lo:ingress").expect("tc ingress spec should parse");
    let tc_ingress_writes = spec_context_writes(&tc_ingress);
    let sk = context_write(&tc_ingress_writes, "sk");
    assert_eq!(sk.kind, "assign-socket");
    assert_eq!(sk.context_field_requirement_key.as_deref(), Some("ctx:sk"));
    assert_eq!(sk.minimum_kernel, Some("5.1"));
    assert_eq!(sk.helper, Some("bpf_sk_assign"));
    assert_eq!(sk.helper_minimum_kernel, Some("5.7"));
    assert_eq!(sk.compatibility_minimum_kernel, Some("5.7"));
    let socket = context_write(&tc_ingress_writes, "socket");
    assert_eq!(socket.kind, "assign-socket");
    assert_eq!(
        socket.context_field_requirement_key.as_deref(),
        Some("ctx:sk")
    );
    assert_eq!(socket.minimum_kernel, Some("5.1"));
    assert_eq!(socket.helper, Some("bpf_sk_assign"));
    assert_eq!(socket.helper_minimum_kernel, Some("5.7"));
    assert_eq!(socket.compatibility_minimum_kernel, Some("5.7"));

    let cgroup_sockopt_set = ProgramSpec::parse("cgroup_sockopt:/sys/fs/cgroup:set")
        .expect("cgroup_sockopt set spec should parse");
    let cgroup_sockopt_writes = spec_context_writes(&cgroup_sockopt_set);
    let optval = context_write(&cgroup_sockopt_writes, "optval");
    assert_eq!(optval.kind, "sockopt-optval-byte");
    assert_eq!(
        optval.context_field_requirement_key.as_deref(),
        Some("ctx:optval")
    );
    assert_eq!(optval.minimum_kernel, Some("5.3"));

    let unix_sock_addr = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("cgroup_sock_addr unix spec should parse");
    let unix_sock_addr_writes = spec_context_writes(&unix_sock_addr);
    let sun_path = context_write(&unix_sock_addr_writes, "sun_path");
    assert_eq!(sun_path.kind, "sun-path");
    assert_eq!(sun_path.context_field_requirement_key, None);
    assert_eq!(sun_path.kfunc, Some("bpf_sock_addr_set_sun_path"));
    assert_eq!(
        sun_path.kfunc_requirement_key.as_deref(),
        Some("kfunc:bpf_sock_addr_set_sun_path")
    );
    assert_eq!(sun_path.kfunc_minimum_kernel, Some("6.7"));
    assert_eq!(sun_path.kfunc_maximum_kernel_exclusive, None);
    assert_eq!(sun_path.compatibility_minimum_kernel, Some("6.7"));
    assert!(sun_path.helper.is_none());

    let flow_dissector = ProgramSpec::parse("flow_dissector:/proc/self/ns/net")
        .expect("flow_dissector spec should parse");
    let flow_dissector_writes = spec_context_writes(&flow_dissector);
    let flow_keys = context_write(&flow_dissector_writes, "flow_keys");
    assert_eq!(flow_keys.kind, "context-pointer-scalar-field");
    assert!(!flow_keys.indexed);
    assert_eq!(
        flow_keys.context_field_requirement_key.as_deref(),
        Some("ctx:flow_keys")
    );
    assert_eq!(flow_keys.minimum_kernel, Some("4.20"));
    assert_eq!(flow_keys.compatibility_minimum_kernel, Some("4.20"));
    assert!(flow_keys.helper.is_none());
    assert!(flow_keys.kfunc.is_none());
}

#[test]
fn test_context_write_backing_abi_metadata_invariants() {
    for spec_source in CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_source)
            .unwrap_or_else(|err| panic!("{spec_source} should parse: {err}"));
        let surfaces = spec.ctx_write_surfaces_for_spec();
        let writes = spec_context_writes(&spec);

        assert_eq!(
            writes.len(),
            surfaces.len(),
            "{spec_source} spec output should report every available context write surface"
        );

        for (surface, write) in surfaces.iter().zip(writes.iter()) {
            assert_eq!(write.field, surface.field_name);
            assert_eq!(write.kind, surface.kind);
            assert_eq!(write.indexed, surface.indexed);
            assert_eq!(write.minimum_kernel, surface.minimum_kernel);
            assert_eq!(write.minimum_kernel_source, surface.minimum_kernel_source);

            match surface.context_field_requirement.as_ref() {
                Some(requirement) => {
                    assert_eq!(
                        write.context_field_requirement_key.as_deref(),
                        Some(requirement.key().as_str()),
                        "{spec_source} ctx.{} write should report the exact context-field requirement key",
                        write.field
                    );
                    assert!(
                        write.minimum_kernel.is_some(),
                        "{spec_source} ctx.{} write should report a context-field minimum kernel",
                        write.field
                    );
                    assert!(
                        write.minimum_kernel_source.is_some(),
                        "{spec_source} ctx.{} write should report a context-field minimum kernel source",
                        write.field
                    );
                }
                None => {
                    assert_eq!(
                        write.context_field_requirement_key, None,
                        "{spec_source} ctx.{} write should not report a context-field requirement key",
                        write.field
                    );
                    assert_eq!(
                        write.minimum_kernel, None,
                        "{spec_source} ctx.{} write should not report a context-field minimum kernel",
                        write.field
                    );
                    assert_eq!(
                        write.minimum_kernel_source, None,
                        "{spec_source} ctx.{} write should not report a context-field minimum kernel source",
                        write.field
                    );
                }
            }

            match surface.helper {
                Some(helper) => {
                    let requirement =
                        HelperCompatibilityRequirement::for_helper(helper).unwrap_or_else(|| {
                            panic!(
                                "{spec_source} ctx.{} helper {} should expose compatibility metadata",
                                write.field,
                                helper.name()
                            )
                        });
                    assert_eq!(write.helper, Some(helper.name()));
                    assert_eq!(
                        write.helper_requirement_key.as_deref(),
                        Some(requirement.key().as_str()),
                        "{spec_source} ctx.{} helper-backed write should report the exact helper requirement key",
                        write.field
                    );
                    assert_eq!(
                        write.helper_minimum_kernel,
                        Some(requirement.minimum_kernel()),
                        "{spec_source} ctx.{} helper-backed write should report the exact helper minimum kernel",
                        write.field
                    );
                    assert_eq!(
                        write.helper_minimum_kernel_source,
                        Some(requirement.minimum_kernel_source()),
                        "{spec_source} ctx.{} helper-backed write should report the exact helper source",
                        write.field
                    );
                }
                None => {
                    assert_eq!(write.helper, None);
                    assert_eq!(write.helper_requirement_key, None);
                    assert_eq!(write.helper_minimum_kernel, None);
                    assert_eq!(write.helper_minimum_kernel_source, None);
                }
            }

            match surface.kfunc {
                Some(kfunc) => {
                    let requirement = spec
                        .kfunc_compatibility_requirement_for_name(kfunc)
                        .unwrap_or_else(|| {
                            panic!(
                                "{spec_source} ctx.{} kfunc {kfunc} should expose compatibility metadata",
                                write.field
                            )
                        });
                    assert_eq!(write.kfunc, Some(kfunc));
                    assert_eq!(
                        write.kfunc_requirement_key.as_deref(),
                        Some(requirement.key().as_str()),
                        "{spec_source} ctx.{} kfunc-backed write should report the exact kfunc requirement key",
                        write.field
                    );
                    assert_eq!(
                        write.kfunc_minimum_kernel,
                        Some(requirement.minimum_kernel()),
                        "{spec_source} ctx.{} kfunc-backed write should report the exact kfunc minimum kernel",
                        write.field
                    );
                    assert_eq!(
                        write.kfunc_minimum_kernel_source,
                        Some(requirement.minimum_kernel_source()),
                        "{spec_source} ctx.{} kfunc-backed write should report the exact kfunc source",
                        write.field
                    );
                    assert_eq!(
                        write.kfunc_maximum_kernel_exclusive,
                        requirement.maximum_kernel_exclusive(),
                        "{spec_source} ctx.{} kfunc-backed write should report the exact kfunc upper bound",
                        write.field
                    );
                }
                None => {
                    assert_eq!(write.kfunc, None);
                    assert_eq!(write.kfunc_requirement_key, None);
                    assert_eq!(write.kfunc_minimum_kernel, None);
                    assert_eq!(write.kfunc_minimum_kernel_source, None);
                    assert_eq!(write.kfunc_maximum_kernel_exclusive, None);
                }
            }

            let component_floors = [
                write.minimum_kernel,
                write.helper_minimum_kernel,
                write.kfunc_minimum_kernel,
            ];
            if component_floors.iter().any(Option::is_some) {
                let compatibility_minimum = write.compatibility_minimum_kernel.unwrap_or_else(|| {
                    panic!(
                        "{spec_source} ctx.{} should report an aggregate compatibility minimum kernel",
                        write.field
                    )
                });
                assert!(
                    write.compatibility_minimum_kernel_source.is_some(),
                    "{spec_source} ctx.{} should report an aggregate compatibility source",
                    write.field
                );
                for floor in component_floors.into_iter().flatten() {
                    assert!(
                        ContextFieldCompatibilityRequirement::kernel_version_at_least(
                            compatibility_minimum,
                            floor
                        ),
                        "{spec_source} ctx.{} aggregate floor {compatibility_minimum} should cover component floor {floor}",
                        write.field
                    );
                }
            } else {
                assert!(
                    write.compatibility_minimum_kernel.is_none(),
                    "{spec_source} ctx.{} should not report an aggregate compatibility minimum without component floors",
                    write.field
                );
                assert!(
                    write.compatibility_minimum_kernel_source.is_none(),
                    "{spec_source} ctx.{} should not report an aggregate compatibility source without component floors",
                    write.field
                );
            }
        }
    }
}

#[test]
fn test_context_write_records_include_packet_field_metadata() {
    let tc_action =
        ProgramSpec::parse("tc_action:diff-action").expect("tc_action spec should parse");
    let tc_action_writes = spec_context_writes(&tc_action);

    assert_context_store_write_metadata(
        &tc_action_writes,
        "mark",
        "ctx:mark",
        "4.1",
        "/v4.1/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &tc_action_writes,
        "queue_mapping",
        "ctx:queue_mapping",
        "4.1",
        "/v4.1/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &tc_action_writes,
        "tc_index",
        "ctx:tc_index",
        "4.7",
        "/v4.7/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &tc_action_writes,
        "cb",
        "ctx:cb",
        "4.7",
        "/v4.7/include/uapi/linux/bpf.h",
        true,
    );
    assert_context_store_write_metadata(
        &tc_action_writes,
        "tc_classid",
        "ctx:tc_classid",
        "4.7",
        "/v4.7/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &tc_action_writes,
        "tstamp",
        "ctx:tstamp",
        "5.0",
        "/v5.0/include/uapi/linux/bpf.h",
        false,
    );

    let lwt_xmit = ProgramSpec::parse("lwt_xmit:eth0").expect("lwt_xmit spec should parse");
    let lwt_xmit_writes = spec_context_writes(&lwt_xmit);
    assert_context_store_write_metadata(
        &lwt_xmit_writes,
        "mark",
        "ctx:mark",
        "4.1",
        "/v4.1/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &lwt_xmit_writes,
        "priority",
        "ctx:priority",
        "4.1",
        "/v4.1/include/uapi/linux/bpf.h",
        false,
    );
    assert_context_store_write_metadata(
        &lwt_xmit_writes,
        "cb",
        "ctx:cb",
        "4.7",
        "/v4.7/include/uapi/linux/bpf.h",
        true,
    );
}

#[test]
fn test_context_write_records_include_store_shape_metadata() {
    let sock_ops =
        ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
    let sock_ops_writes = spec_context_writes(&sock_ops);
    let reply = context_write(&sock_ops_writes, "reply");
    assert_eq!(reply.direct_store_offset, Some(4));
    assert_eq!(reply.indexed_store_base_offset, None);
    assert_eq!(reply.transformed_store_offset, None);

    let replylong = context_write(&sock_ops_writes, "replylong");
    assert_eq!(replylong.direct_store_offset, None);
    assert_eq!(replylong.indexed_store_base_offset, Some(4));
    assert_eq!(replylong.indexed_store_count, Some(4));
    assert_eq!(replylong.indexed_store_convert_to_big_endian, Some(false));
    assert_eq!(replylong.transformed_store_offset, None);

    let tc_action =
        ProgramSpec::parse("tc_action:diff-action").expect("tc_action spec should parse");
    let tc_action_writes = spec_context_writes(&tc_action);
    let mark = context_write(&tc_action_writes, "mark");
    assert_eq!(mark.direct_store_offset, Some(8));
    let cb = context_write(&tc_action_writes, "cb");
    assert_eq!(cb.indexed_store_base_offset, Some(48));
    assert_eq!(cb.indexed_store_count, Some(5));
    assert_eq!(cb.indexed_store_convert_to_big_endian, Some(false));

    let connect4 = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect4")
        .expect("cgroup_sock_addr connect4 spec should parse");
    let connect4_writes = spec_context_writes(&connect4);
    let remote_ip4 = context_write(&connect4_writes, "remote_ip4");
    assert_eq!(remote_ip4.transformed_store_offset, Some(4));
    assert_eq!(
        remote_ip4.transformed_store_transform,
        Some("host-u32-to-big-endian")
    );
    let remote_port = context_write(&connect4_writes, "remote_port");
    assert_eq!(remote_port.transformed_store_offset, Some(24));
    assert_eq!(
        remote_port.transformed_store_transform,
        Some("host-port-to-big-endian-u32")
    );

    let connect6 = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect6")
        .expect("cgroup_sock_addr connect6 spec should parse");
    let connect6_writes = spec_context_writes(&connect6);
    let remote_ip6 = context_write(&connect6_writes, "remote_ip6");
    assert_eq!(remote_ip6.indexed_store_base_offset, Some(8));
    assert_eq!(remote_ip6.indexed_store_count, Some(4));
    assert_eq!(remote_ip6.indexed_store_convert_to_big_endian, Some(true));

    let sendmsg4 = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg4")
        .expect("cgroup_sock_addr sendmsg4 spec should parse");
    let sendmsg4_writes = spec_context_writes(&sendmsg4);
    let local_ip4 = context_write(&sendmsg4_writes, "local_ip4");
    assert_eq!(local_ip4.minimum_kernel, Some("4.18"));
    assert_eq!(local_ip4.compatibility_minimum_kernel, Some("4.18"));
    assert!(
        local_ip4
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.18/include/uapi/linux/bpf.h"))
    );
    assert_eq!(local_ip4.transformed_store_offset, Some(40));
    assert_eq!(
        local_ip4.transformed_store_transform,
        Some("host-u32-to-big-endian")
    );

    let sendmsg6 = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg6")
        .expect("cgroup_sock_addr sendmsg6 spec should parse");
    let sendmsg6_writes = spec_context_writes(&sendmsg6);
    let local_ip6 = context_write(&sendmsg6_writes, "local_ip6");
    assert_eq!(local_ip6.minimum_kernel, Some("4.18"));
    assert_eq!(local_ip6.compatibility_minimum_kernel, Some("4.18"));
    assert!(
        local_ip6
            .minimum_kernel_source
            .is_some_and(|source| source.contains("/v4.18/include/uapi/linux/bpf.h"))
    );
    assert_eq!(local_ip6.indexed_store_base_offset, Some(44));
    assert_eq!(local_ip6.indexed_store_count, Some(4));
    assert_eq!(local_ip6.indexed_store_convert_to_big_endian, Some(true));
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
            .get("context_field_requirement_key")
            .expect("context field requirement key should be present")
            .as_str()
            .expect("context field requirement key should be a string"),
        "ctx:cb_flags"
    );
    assert_eq!(
        cb_flags
            .get("compatibility_minimum_kernel")
            .expect("compatibility minimum kernel should be present")
            .as_str()
            .expect("compatibility minimum kernel should be a string"),
        "4.16"
    );
    assert!(
        cb_flags
            .get("compatibility_minimum_kernel_source")
            .expect("compatibility minimum kernel source should be present")
            .as_str()
            .expect("compatibility minimum kernel source should be a string")
            .contains("/v4.16/")
    );
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
            .get("helper_requirement_key")
            .expect("helper requirement key should be present")
            .as_str()
            .expect("helper requirement key should be a string"),
        "helper:bpf_sock_ops_cb_flags_set"
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

#[test]
fn test_spec_record_context_writes_include_store_shape_metadata() {
    let reply = context_write_record("sock_ops:/sys/fs/cgroup", "reply");
    let reply = reply
        .as_record()
        .expect("ctx.reply write should be a record");
    assert_eq!(
        reply
            .get("direct_store_offset")
            .expect("direct store offset should be present")
            .as_int()
            .expect("direct store offset should be an int"),
        4
    );
    assert!(
        reply
            .get("indexed_store_base_offset")
            .expect("indexed store base offset should be present")
            .is_nothing()
    );
    assert!(
        reply
            .get("transformed_store_offset")
            .expect("transformed store offset should be present")
            .is_nothing()
    );

    let replylong = context_write_record("sock_ops:/sys/fs/cgroup", "replylong");
    let replylong = replylong
        .as_record()
        .expect("ctx.replylong write should be a record");
    assert!(
        replylong
            .get("direct_store_offset")
            .expect("direct store offset should be present")
            .is_nothing()
    );
    assert_eq!(
        replylong
            .get("indexed_store_base_offset")
            .expect("indexed store base offset should be present")
            .as_int()
            .expect("indexed store base offset should be an int"),
        4
    );
    assert_eq!(
        replylong
            .get("indexed_store_count")
            .expect("indexed store count should be present")
            .as_int()
            .expect("indexed store count should be an int"),
        4
    );
    assert!(
        !replylong
            .get("indexed_store_convert_to_big_endian")
            .expect("indexed store endian flag should be present")
            .as_bool()
            .expect("indexed store endian flag should be a bool")
    );

    let remote_ip4 = context_write_record("cgroup_sock_addr:/sys/fs/cgroup:connect4", "remote_ip4");
    let remote_ip4 = remote_ip4
        .as_record()
        .expect("ctx.remote_ip4 write should be a record");
    assert_eq!(
        remote_ip4
            .get("transformed_store_offset")
            .expect("transformed store offset should be present")
            .as_int()
            .expect("transformed store offset should be an int"),
        4
    );
    assert_eq!(
        remote_ip4
            .get("transformed_store_transform")
            .expect("transformed store transform should be present")
            .as_str()
            .expect("transformed store transform should be a string"),
        "host-u32-to-big-endian"
    );
}
