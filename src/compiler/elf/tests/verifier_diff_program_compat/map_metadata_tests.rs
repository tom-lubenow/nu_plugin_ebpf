use super::*;

fn assert_verifier_feature_record_matches_map_kind(
    kind: MapKind,
    record: &VerifierDiffFeatureRecord,
) {
    let requirement = kind.compatibility_requirement();
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu map feature key drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu map min_kernel drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu map source drifted for {}",
        kind.key()
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "map compatibility features should not use max_kernel_exclusive"
    );
}

#[test]
fn test_verifier_diff_map_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records =
        verifier_diff_feature_table_records(verifier_diff, "MAP_KIND_KERNEL_FEATURES", "kind");

    for kind in MapKind::all() {
        let record = records.get(kind.key()).unwrap_or_else(|| {
            panic!(
                "scripts/verifier_diff.nu MAP_KIND_KERNEL_FEATURES is missing {}",
                kind.key()
            )
        });
        assert_verifier_feature_record_matches_map_kind(*kind, record);
    }

    for (kind_name, record) in &records {
        let kind = MapKind::from_name(kind_name).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu has unknown map kind feature entry {kind_name}")
        });
        assert_verifier_feature_record_matches_map_kind(kind, record);
    }
}

fn verifier_diff_map_value_token(requirement: MapValueCompatibilityRequirement) -> &'static str {
    match requirement {
        MapValueCompatibilityRequirement::BpfSpinLock => "bpf_spin_lock",
        MapValueCompatibilityRequirement::BpfTimer => "bpf_timer",
        MapValueCompatibilityRequirement::BpfKptr => "kptr:",
        MapValueCompatibilityRequirement::BpfWorkqueue => "bpf_wq",
        MapValueCompatibilityRequirement::BpfRefcount => "bpf_refcount",
        MapValueCompatibilityRequirement::BpfListHead => "bpf_list_head",
        MapValueCompatibilityRequirement::BpfListNode => "bpf_list_node",
        MapValueCompatibilityRequirement::BpfRbRoot => "bpf_rb_root",
        MapValueCompatibilityRequirement::BpfRbNode => "bpf_rb_node",
    }
}

fn assert_verifier_feature_record_matches_map_value(
    requirement: MapValueCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu map-value feature key drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu map-value min_kernel drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu map-value source drifted for {}",
        requirement.key()
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "map-value compatibility features should not use max_kernel_exclusive"
    );
}

#[test]
fn test_verifier_diff_map_value_feature_metadata_matches_rust() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
    let records =
        verifier_diff_feature_table_records(verifier_diff, "MAP_VALUE_KERNEL_FEATURES", "token");
    let mut expected_tokens = BTreeSet::new();

    for requirement in MapValueCompatibilityRequirement::all() {
        let token = verifier_diff_map_value_token(*requirement);
        assert!(
            expected_tokens.insert(token),
            "duplicate verifier_diff.nu map-value token mapping for {requirement:?}"
        );
        let record = records.get(token).unwrap_or_else(|| {
            panic!("scripts/verifier_diff.nu MAP_VALUE_KERNEL_FEATURES is missing {token}")
        });
        assert_verifier_feature_record_matches_map_value(*requirement, record);
    }

    let unexpected_tokens = records
        .keys()
        .filter(|token| !expected_tokens.contains(token.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unexpected_tokens.is_empty(),
        "scripts/verifier_diff.nu has map-value feature metadata without a Rust requirement: {unexpected_tokens:?}"
    );
}
