use super::*;

const REPRESENTATIVE_CONTEXT_FIELD_SPEC_SOURCES: &[&str] = &[
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
    "cgroup_sock:/sys/fs/cgroup:post_bind6",
    "cgroup_sock_addr:/sys/fs/cgroup:connect4",
    "cgroup_sock_addr:/sys/fs/cgroup:bind6",
    "cgroup_sock_addr:/sys/fs/cgroup:getpeername4",
    "cgroup_sock_addr:/sys/fs/cgroup:getsockname6",
    "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6",
    "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
    "cgroup_sockopt:/sys/fs/cgroup:get",
    "cgroup_sockopt:/sys/fs/cgroup:set",
    "cgroup_sysctl:/sys/fs/cgroup",
    "cgroup_device:/sys/fs/cgroup",
    "sock_ops:/sys/fs/cgroup",
    "lwt_xmit:demo-route",
    "flow_dissector:/proc/self/ns/net",
    "netfilter:ipv4:pre_routing:priority=-100:defrag",
    "perf_event:software:cpu-clock:period=100000",
    "lirc_mode2:/dev/lirc0",
    "iter:task_file",
    "iter:task_vma",
    "iter:bpf_map_elem",
    "iter:bpf_sk_storage_map",
    "iter:sockmap",
    "iter:udp",
    "iter:unix",
];

#[test]
fn test_verifier_diff_context_field_feature_metadata_matches_rust() {
    let verifier_diff = verifier_diff_source();
    let records = verifier_diff_feature_table_records(
        &verifier_diff,
        "CONTEXT_FIELD_KERNEL_FEATURES",
        "field",
    );

    for (field_name, record) in &records {
        let field =
            EbpfProgramType::resolve_untyped_ctx_field_name(field_name).unwrap_or_else(|err| {
                panic!("scripts/verifier_diff.nu context field {field_name} should resolve: {err}")
            });
        assert!(
            !matches!(field, CtxField::TracepointField(_)),
            "scripts/verifier_diff.nu context field {field_name} resolved as an unversioned tracepoint payload field"
        );
        let requirement = ContextFieldCompatibilityRequirement::for_field(&field).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu context field {field_name} ({}) has no Rust compatibility requirement",
                field.display_name()
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            field_name,
            &requirement,
            record,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu context-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_context_field_feature_metadata_covers_representative_rust_fields() {
    #[derive(Clone)]
    struct ExpectedContextFieldFeature {
        target: String,
        field: String,
        requirement: ContextFieldCompatibilityRequirement,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_FIELD_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context field target {spec_text} should parse: {err}")
        });
        let mut seen_requirement_keys = BTreeSet::new();

        for entry in spec.program_type().ctx_field_name_entries() {
            if spec.ctx_field_access_error(&entry.field).is_some() {
                continue;
            }
            let Some(requirement) = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
                &entry.field,
                &spec,
            ) else {
                continue;
            };
            let requirement_key = requirement.key();
            if !seen_requirement_keys.insert(requirement_key.clone()) {
                continue;
            }

            expected.push(ExpectedContextFieldFeature {
                target: (*spec_text).to_string(),
                field: entry.name.to_string(),
                requirement,
            });
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.field.clone()))
        .collect::<Vec<_>>();
    let Some(actual) =
        verifier_diff_nu_field_target_feature_records("context-field-kernel-feature", &checks)
    else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, record) in expected.iter().zip(actual.iter()) {
        if !verifier_feature_record_matches_context_requirement(&check.requirement, record) {
            mismatches.push(format!(
                "{} ctx.{} expected key={} min_kernel={} source={} actual key={} min_kernel={} source={}",
                check.target,
                check.field,
                check.requirement.key(),
                check.requirement.minimum_kernel(),
                check.requirement.minimum_kernel_source(),
                record.key,
                record.min_kernel,
                record.source
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu context-field scanner drifted from Rust metadata: {}",
        mismatches.join(", ")
    );
}
