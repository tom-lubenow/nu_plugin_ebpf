use super::*;

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
