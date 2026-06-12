use super::*;

#[test]
fn test_verifier_diff_iter_target_feature_table_matches_rust() {
    let verifier_diff = verifier_diff_source();
    let records = verifier_diff_feature_table_records(
        &verifier_diff,
        "ITER_TARGET_KERNEL_FEATURES",
        "target",
    );
    let mut expected_targets = BTreeSet::new();

    for target_kind in IterTargetKind::all() {
        let target = target_kind.key();
        expected_targets.insert(target.to_string());
        let spec = ProgramSpec::parse(&format!("iter:{target}"))
            .unwrap_or_else(|err| panic!("iter:{target} should parse: {err}"));
        let requirement = spec
            .compatibility_requirements()
            .into_iter()
            .find(|requirement| {
                program_compatibility_verifier_feature_key(*requirement)
                    .is_some_and(|key| key.starts_with("iter-target:"))
            })
            .unwrap_or_else(|| panic!("iter:{target} should have a target requirement"));
        let expected_feature_key = program_compatibility_verifier_feature_key(requirement)
            .unwrap_or_else(|| panic!("{requirement:?} should have verifier feature metadata"));
        let record = records
            .get(target)
            .unwrap_or_else(|| panic!("ITER_TARGET_KERNEL_FEATURES missing iter target {target}"));

        assert_eq!(
            record.key, expected_feature_key,
            "ITER_TARGET_KERNEL_FEATURES key drifted for iter:{target}"
        );
        assert_eq!(
            Some(record.min_kernel.as_str()),
            requirement.minimum_kernel(),
            "ITER_TARGET_KERNEL_FEATURES minimum kernel drifted for iter:{target}"
        );
        assert_eq!(
            Some(record.source.as_str()),
            requirement.minimum_kernel_source(),
            "ITER_TARGET_KERNEL_FEATURES source drifted for iter:{target}"
        );
        assert_eq!(
            record.max_kernel_exclusive, None,
            "iterator target features should not use max_kernel_exclusive"
        );
    }

    assert_eq!(
        records.keys().cloned().collect::<BTreeSet<_>>(),
        expected_targets,
        "ITER_TARGET_KERNEL_FEATURES should exactly cover modeled iterator targets"
    );
}
