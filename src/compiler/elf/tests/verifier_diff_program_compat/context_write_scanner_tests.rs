use super::*;

#[test]
fn test_verifier_diff_context_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedWriteFeature {
        target: String,
        form: &'static str,
        field_names: Vec<&'static str>,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        let write_surfaces = spec.ctx_write_surfaces_for_spec();
        for form in ContextWriteScannerForm::ALL {
            let mut assignments = Vec::new();
            let mut field_names = Vec::new();
            let mut expected_keys = BTreeSet::new();

            for surface in &write_surfaces {
                let Some(requirement) = surface.context_field_requirement.as_ref() else {
                    continue;
                };
                assignments.push(context_write_scanner_assignment(
                    surface.field_name,
                    surface.indexed,
                    form,
                ));
                field_names.push(surface.field_name);
                expected_keys.insert(requirement.key());
            }

            if !expected_keys.is_empty() {
                expected.push(ExpectedWriteFeature {
                    target: (*spec_text).to_string(),
                    form: form.label(),
                    field_names,
                    program: context_write_scanner_source_from_assignments(&assignments, form),
                    expected_keys,
                });
            }
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.program.clone()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, actual_keys) in expected.iter().zip(actual.iter()) {
        if actual_keys != &check.expected_keys {
            mismatches.push(format!(
                "{} {} ctx.{:?} expected {:?} actual {:?}",
                check.target, check.form, check.field_names, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}
