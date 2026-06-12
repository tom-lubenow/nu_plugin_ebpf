use super::*;

#[test]
fn test_verifier_diff_context_helper_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedHelperWriteFeature {
        target: String,
        field_name: &'static str,
        form: &'static str,
        helper_name: &'static str,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        for surface in spec.ctx_write_surfaces_for_spec() {
            let Some(helper) = surface.helper else {
                continue;
            };
            let requirement =
                HelperCompatibilityRequirement::for_helper(helper).unwrap_or_else(|| {
                    panic!(
                        "{spec_text} ctx.{} helper {} should expose Rust metadata",
                        surface.field_name,
                        helper.name()
                    )
                });
            for form in ContextWriteScannerForm::ALL {
                expected.push(ExpectedHelperWriteFeature {
                    target: (*spec_text).to_string(),
                    field_name: surface.field_name,
                    form: form.label(),
                    helper_name: helper.name(),
                    program: context_write_scanner_source(
                        surface.field_name,
                        surface.indexed,
                        form,
                    ),
                    expected_keys: BTreeSet::from([requirement.key()]),
                });
            }
        }
    }

    let checks = expected
        .iter()
        .map(|check| (check.target.clone(), check.program.clone()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_surface_feature_keys(&checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (check, actual_keys) in expected.iter().zip(actual.iter()) {
        if actual_keys != &check.expected_keys {
            mismatches.push(format!(
                "{} {} ctx.{} {} expected {:?} actual {:?}",
                check.target,
                check.form,
                check.field_name,
                check.helper_name,
                check.expected_keys,
                actual_keys
            ));
        }
    }

    assert!(
        !expected.is_empty(),
        "expected at least one helper-backed context write surface"
    );
    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu helper-backed context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}
