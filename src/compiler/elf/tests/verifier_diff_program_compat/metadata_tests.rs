use super::*;

#[test]
fn test_verifier_diff_target_context_field_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records = verifier_diff_target_context_field_feature_records(verifier_diff);

    for record in &records {
        let spec = ProgramSpec::parse(&record.target).unwrap_or_else(|err| {
            panic!(
                "verifier_diff.nu target context expectation target {} should parse: {err}",
                record.target
            )
        });
        let field = spec
            .resolve_ctx_field_name(&record.field)
            .unwrap_or_else(|err| {
                panic!(
                    "verifier_diff.nu target context expectation {} ctx.{} should resolve: {err}",
                    record.target, record.field
                )
            });
        let target = if spec.program_type() == EbpfProgramType::Iter {
            record.target.strip_prefix("iter:")
        } else {
            None
        };
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_target(
            &field,
            Some(spec.program_type()),
            target,
        )
        .unwrap_or_else(|| {
            panic!(
                "verifier_diff.nu target context expectation {} ctx.{} ({}) has no Rust compatibility requirement",
                record.target,
                record.field,
                field.display_name()
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            &format!("{} ctx.{}", record.target, record.field),
            &requirement,
            &record.feature,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu target-aware context-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_tracepoint_field_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records = verifier_diff_tracepoint_field_feature_records(verifier_diff);

    for record in &records {
        let spec = ProgramSpec::parse(&record.target).unwrap_or_else(|err| {
            panic!(
                "verifier_diff.nu tracepoint field target {} should parse: {err}",
                record.target
            )
        });
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
            &CtxField::TracepointField(record.field.clone()),
            &spec,
        )
        .unwrap_or_else(|| {
            panic!(
                "verifier_diff.nu tracepoint field expectation {} ctx.{} has no Rust compatibility requirement",
                record.target, record.field
            )
        });

        assert_verifier_feature_record_matches_context_requirement(
            &format!("{} ctx.{}", record.target, record.field),
            &requirement,
            &record.feature,
        );
    }

    assert!(
        !records.is_empty(),
        "expected verifier_diff.nu tracepoint-field feature metadata"
    );
}

#[test]
fn test_verifier_diff_kfunc_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let explicit_records =
        verifier_diff_feature_table_records(verifier_diff, "KFUNC_KERNEL_FEATURES", "name");
    let fallback_records = verifier_diff_kfunc_fallback_records(verifier_diff);

    for (name, record) in &explicit_records {
        let requirement = KfuncCompatibilityRequirement::for_name(name).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu KFUNC_KERNEL_FEATURES has unknown kfunc {name}")
        });
        assert_verifier_feature_record_matches_kfunc_requirement(name, requirement, record);

        if let Some(fallback_record) = fallback_records.get(name) {
            assert_eq!(
                record, fallback_record,
                "scripts/verifier_diff.nu explicit and fallback kfunc metadata drifted for {name}"
            );
        }
    }

    for (name, record) in &fallback_records {
        let requirement = KfuncCompatibilityRequirement::for_name(name).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu KFUNC_KERNEL_FEATURE_FALLBACKS has unknown kfunc {name}"
            )
        });
        assert_verifier_feature_record_matches_kfunc_requirement(name, requirement, record);
    }

    assert!(
        !explicit_records.is_empty() && !fallback_records.is_empty(),
        "expected verifier_diff.nu kfunc feature metadata"
    );
}

#[test]
fn test_verifier_diff_program_kfunc_scanner_matches_program_specific_rust_floors() {
    let checks = [
        ("socket_filter:udp4:127.0.0.1:31337", "bpf_dynptr_from_skb"),
        ("tc:lo:ingress", "bpf_dynptr_from_skb"),
        ("tcx:lo:ingress", "bpf_dynptr_from_skb"),
        ("netkit:lo:primary", "bpf_dynptr_from_skb"),
        ("netfilter:ipv4:pre_routing", "bpf_dynptr_from_skb"),
        ("fentry:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fentry.s:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fexit:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fexit.s:tcp_v4_rcv", "bpf_dynptr_from_skb"),
        ("fmod_ret:bpf_modify_return_test", "bpf_dynptr_from_skb"),
        ("fmod_ret.s:bpf_modify_return_test", "bpf_dynptr_from_skb"),
        ("tp_btf:sys_enter", "bpf_dynptr_from_skb"),
        ("sock_ops:/sys/fs/cgroup", "bpf_sock_ops_enable_tx_tstamp"),
        (
            "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
            "bpf_sock_addr_set_sun_path",
        ),
    ]
    .into_iter()
    .map(|(target, kfunc)| (target.to_string(), kfunc.to_string()))
    .collect::<Vec<_>>();

    let Some(records) = verifier_diff_nu_program_kfunc_feature_records(&checks) else {
        return;
    };

    for ((target, kfunc), record) in checks.iter().zip(records.iter()) {
        let spec = ProgramSpec::parse(target).unwrap_or_else(|err| {
            panic!("program-specific kfunc target {target} should parse: {err}")
        });
        let requirement = spec
            .kfunc_compatibility_requirement_for_name(kfunc)
            .unwrap_or_else(|| {
                panic!(
                    "program-specific kfunc target {target} should expose Rust metadata for {kfunc}"
                )
            });
        assert_verifier_feature_record_matches_kfunc_requirement(
            &format!("{target} {kfunc}"),
            requirement,
            record,
        );
    }
}

#[test]
fn test_verifier_diff_tracepoint_payload_scanner_covers_all_modeled_rust_fallback_fields() {
    let checks = all_modeled_tracepoint_payload_scanner_checks();
    assert!(
        checks.len() > 500,
        "expected broad tracepoint payload scanner coverage, got {} checks",
        checks.len()
    );

    let Some(records) = verifier_diff_nu_field_target_feature_records(
        "tracepoint-payload-field-kernel-feature",
        &checks,
    ) else {
        return;
    };

    let mut mismatches = Vec::new();
    for ((target, field), record) in checks.iter().zip(records.iter()) {
        let spec = ProgramSpec::parse(target)
            .unwrap_or_else(|err| panic!("tracepoint target {target} should parse: {err}"));
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
            &CtxField::TracepointField(field.clone()),
            &spec,
        )
        .unwrap_or_else(|| panic!("{target} ctx.{field} should have Rust fallback metadata"));

        if !verifier_feature_record_matches_context_requirement(&requirement, record) {
            mismatches.push(format!(
                "{target} ctx.{field} expected key={} min_kernel={} source={} actual key={} min_kernel={} source={}",
                requirement.key(),
                requirement.minimum_kernel(),
                requirement.minimum_kernel_source(),
                record.key,
                record.min_kernel,
                record.source
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu tracepoint payload scanner drifted from all modeled Rust fallback metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_target_kernel_features_cover_representative_rust_program_specs() {
    let mut checks = Vec::new();

    for program_type in EbpfProgramType::supported_program_types() {
        let target = ProgramSpec::representative_target_for_program_type(*program_type);
        let spec = ProgramSpec::from_program_type_target(*program_type, target)
            .unwrap_or_else(|err| panic!("{program_type:?} representative target failed: {err}"));
        let expected_keys = spec
            .compatibility_requirements()
            .iter()
            .filter_map(|requirement| program_compatibility_verifier_feature_key(*requirement))
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        checks.push((spec.to_string(), expected_keys));
    }

    let targets = checks
        .iter()
        .map(|(target, _)| target.clone())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_target_feature_keys(&targets) else {
        return;
    };

    for ((target, expected_keys), actual_keys) in checks.iter().zip(actual.iter()) {
        assert_eq!(
            actual_keys, expected_keys,
            "scripts/verifier_diff.nu target-kernel-features drifted from ProgramSpec for {target}"
        );
    }
}

#[test]
fn test_verifier_diff_program_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let verifier_records = verifier_diff_program_feature_records(verifier_diff);
    let vm_only_keys = verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "vm-only");
    let dry_run_keys = verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "dry-run");
    let host_gated_keys =
        verifier_diff_kernel_feature_default_lane_keys(verifier_diff, "host-gated");
    let mut expected_keys = BTreeSet::new();

    for requirement in ProgramCompatibilityRequirement::all() {
        let Some(verifier_key) = program_compatibility_verifier_feature_key(*requirement) else {
            assert!(
                requirement.minimum_kernel().is_none(),
                "{requirement:?} has a kernel floor and needs verifier_diff.nu feature metadata"
            );
            continue;
        };
        assert!(
            expected_keys.insert(verifier_key),
            "duplicate verifier feature key mapping for {requirement:?}"
        );
        let record = verifier_records.get(verifier_key).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu is missing program feature {verifier_key}")
        });
        assert_eq!(
            Some(record.min_kernel.as_str()),
            requirement.minimum_kernel(),
            "scripts/verifier_diff.nu min_kernel drifted for {requirement:?}"
        );
        assert_eq!(
            Some(record.source.as_str()),
            requirement.minimum_kernel_source(),
            "scripts/verifier_diff.nu source drifted for {requirement:?}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "program compatibility features should not use max_kernel_exclusive"
        );

        let verifier_lane =
            if verifier_key.starts_with("struct_ops:") || vm_only_keys.contains(verifier_key) {
                "vm-only"
            } else if dry_run_keys.contains(verifier_key) {
                "dry-run"
            } else if host_gated_keys.contains(verifier_key) {
                "host-gated"
            } else {
                "host-safe"
            };
        assert_eq!(
            verifier_lane,
            requirement.default_test_lane(),
            "scripts/verifier_diff.nu default test lane drifted for {requirement:?}"
        );
    }

    for requirement in CompiledFeatureCompatibilityRequirement::all() {
        let verifier_key = requirement.key();
        assert!(
            expected_keys.insert(verifier_key),
            "duplicate verifier feature key mapping for {requirement:?}"
        );
        let record = verifier_records.get(verifier_key).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu is missing compiled feature {verifier_key}")
        });
        assert_eq!(
            record.min_kernel.as_str(),
            requirement.minimum_kernel(),
            "scripts/verifier_diff.nu min_kernel drifted for {requirement:?}"
        );
        assert_eq!(
            record.source.as_str(),
            requirement.minimum_kernel_source(),
            "scripts/verifier_diff.nu source drifted for {requirement:?}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "compiled compatibility features should not use max_kernel_exclusive"
        );

        let verifier_lane =
            if verifier_key.starts_with("struct_ops:") || vm_only_keys.contains(verifier_key) {
                "vm-only"
            } else if dry_run_keys.contains(verifier_key) {
                "dry-run"
            } else if host_gated_keys.contains(verifier_key) {
                "host-gated"
            } else {
                "host-safe"
            };
        assert_eq!(
            verifier_lane, "host-safe",
            "compiled compatibility features should not force fixture lanes by themselves"
        );
    }

    let unexpected_verifier_keys = verifier_records
        .keys()
        .filter(|key| !expected_keys.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unexpected_verifier_keys.is_empty(),
        "scripts/verifier_diff.nu has program feature metadata without a Rust requirement: {unexpected_verifier_keys:?}"
    );
}

#[test]
fn test_verifier_diff_program_target_expectations_match_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let expectations = verifier_diff_program_target_expectations(verifier_diff);
    assert!(
        !expectations.is_empty(),
        "expected verifier_diff.nu program target compatibility expectations"
    );

    for (target, expected_feature_keys) in expectations {
        let spec = ProgramSpec::parse(&target)
            .unwrap_or_else(|err| panic!("verifier_diff.nu target {target} should parse: {err}"));
        let actual_feature_keys = spec
            .compatibility_requirements()
            .iter()
            .filter_map(|requirement| program_compatibility_verifier_feature_key(*requirement))
            .map(str::to_string)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            actual_feature_keys, expected_feature_keys,
            "verifier_diff.nu program target feature expectation drifted from ProgramSpec for {target}"
        );
    }
}
