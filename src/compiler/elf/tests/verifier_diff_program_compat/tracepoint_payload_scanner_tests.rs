use super::*;

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
