use super::*;

#[derive(Clone, Copy)]
enum ContextWriteScannerForm {
    Direct,
    RecordAlias,
    ReturnedContextAlias,
    RecordWrapper,
    RecordSpread,
    UserFunctionRecordWrapper,
    NestedUserFunctionRecordWrapper,
    RecordInsert,
    RecordUpdate,
    RecordUpsert,
    RecordGetAlias,
    RecordPipelineGetAlias,
    UserFunctionRecordGetAlias,
    UserFunctionRecordPipelineGetAlias,
    RecordSelect,
    RecordReject,
    RecordRename,
    RecordMerge,
    RecordDefault,
}

impl ContextWriteScannerForm {
    const ALL: [Self; 19] = [
        Self::Direct,
        Self::RecordAlias,
        Self::ReturnedContextAlias,
        Self::RecordWrapper,
        Self::RecordSpread,
        Self::UserFunctionRecordWrapper,
        Self::NestedUserFunctionRecordWrapper,
        Self::RecordInsert,
        Self::RecordUpdate,
        Self::RecordUpsert,
        Self::RecordGetAlias,
        Self::RecordPipelineGetAlias,
        Self::UserFunctionRecordGetAlias,
        Self::UserFunctionRecordPipelineGetAlias,
        Self::RecordSelect,
        Self::RecordReject,
        Self::RecordRename,
        Self::RecordMerge,
        Self::RecordDefault,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::RecordAlias => "record-alias",
            Self::ReturnedContextAlias => "returned-context-alias",
            Self::RecordWrapper => "record-wrapper",
            Self::RecordSpread => "record-spread",
            Self::UserFunctionRecordWrapper => "user-function-record-wrapper",
            Self::NestedUserFunctionRecordWrapper => "nested-user-function-record-wrapper",
            Self::RecordInsert => "record-insert",
            Self::RecordUpdate => "record-update",
            Self::RecordUpsert => "record-upsert",
            Self::RecordGetAlias => "record-get-alias",
            Self::RecordPipelineGetAlias => "record-pipeline-get-alias",
            Self::UserFunctionRecordGetAlias => "user-function-record-get-alias",
            Self::UserFunctionRecordPipelineGetAlias => "user-function-record-pipeline-get-alias",
            Self::RecordSelect => "record-select",
            Self::RecordReject => "record-reject",
            Self::RecordRename => "record-rename",
            Self::RecordMerge => "record-merge",
            Self::RecordDefault => "record-default",
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::Direct => "$ctx",
            Self::RecordAlias | Self::ReturnedContextAlias => "$event",
            Self::RecordGetAlias
            | Self::RecordPipelineGetAlias
            | Self::UserFunctionRecordGetAlias
            | Self::UserFunctionRecordPipelineGetAlias => "$event",
            Self::RecordWrapper
            | Self::RecordSpread
            | Self::UserFunctionRecordWrapper
            | Self::NestedUserFunctionRecordWrapper
            | Self::RecordInsert
            | Self::RecordUpdate
            | Self::RecordUpsert
            | Self::RecordSelect
            | Self::RecordReject
            | Self::RecordMerge
            | Self::RecordDefault => "$rec.event",
            Self::RecordRename => "$rec.alias",
        }
    }
}

fn context_write_scanner_assignment(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    let root = form.root();
    let assignment = if field_name == "flow_keys" {
        format!("  {root}.{field_name}.ip_proto = 6")
    } else if indexed {
        format!("  {root}.{field_name}.0 = 42")
    } else if matches!(field_name, "new_value" | "sysctl_new_value" | "sun_path") {
        format!("  {root}.{field_name} = \"1\"")
    } else {
        format!("  {root}.{field_name} = 1")
    };

    assignment
}

fn context_write_scanner_source_from_assignments(
    assignments: &[String],
    form: ContextWriteScannerForm,
) -> String {
    let assignments = assignments.join("\n");
    match form {
        ContextWriteScannerForm::Direct => format!("{{|ctx|\n{assignments}\n  \"allow\"\n}}"),
        ContextWriteScannerForm::RecordAlias => {
            format!("{{|ctx|\n  mut event = $ctx\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::ReturnedContextAlias => format!(
            "{{|ctx|\n  def id [event] {{ $event }}\n  mut event = (id $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordWrapper => {
            format!("{{|ctx|\n  mut rec = {{ event: $ctx }}\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::RecordSpread => format!(
            "{{|ctx|\n  let base = {{ event: $ctx }}\n  mut rec = {{ ok: true, ...$base }}\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  mut rec = (wrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::NestedUserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  def outer [event] {{ wrap $event }}\n  mut rec = (outer $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordInsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | insert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpdate => format!(
            "{{|ctx|\n  mut rec = ({{ event: 0 }} | update event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | upsert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordGetAlias => format!(
            "{{|ctx|\n  let rec = {{ event: $ctx }}\n  mut event = ($rec | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordPipelineGetAlias => format!(
            "{{|ctx|\n  mut event = ({{ other: 1 }} | insert event $ctx | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    let rec = {{ event: $event }}\n    $rec | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordPipelineGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    {{ other: 1 }} | insert event $event | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordSelect => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | select event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordReject => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | reject other)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordRename => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx }} | rename alias)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordMerge => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | merge {{ event: $ctx }})\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordDefault => format!(
            "{{|ctx|\n  mut rec = ({{ }} | default $ctx event)\n{assignments}\n  \"allow\"\n}}"
        ),
    }
}

fn context_write_scanner_source(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    context_write_scanner_source_from_assignments(
        &[context_write_scanner_assignment(field_name, indexed, form)],
        form,
    )
}

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

#[test]
fn test_verifier_diff_context_kfunc_write_scanner_covers_rust_write_surfaces() {
    #[derive(Clone)]
    struct ExpectedKfuncWriteFeature {
        target: String,
        field_name: &'static str,
        form: &'static str,
        kfunc: &'static str,
        program: String,
        expected_keys: BTreeSet<String>,
    }

    let mut expected = Vec::new();

    for spec_text in REPRESENTATIVE_CONTEXT_WRITE_SPEC_SOURCES {
        let spec = ProgramSpec::parse(spec_text).unwrap_or_else(|err| {
            panic!("representative context write target {spec_text} should parse: {err}")
        });
        for surface in spec.ctx_write_surfaces_for_spec() {
            let Some(kfunc) = surface.kfunc else {
                continue;
            };
            let requirement = spec
                .kfunc_compatibility_requirement_for_name(kfunc)
                .unwrap_or_else(|| {
                    panic!(
                        "{spec_text} ctx.{} should expose Rust metadata for {kfunc}",
                        surface.field_name
                    )
                });
            for form in ContextWriteScannerForm::ALL {
                expected.push(ExpectedKfuncWriteFeature {
                    target: (*spec_text).to_string(),
                    field_name: surface.field_name,
                    form: form.label(),
                    kfunc,
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
    let Some(actual) = verifier_diff_nu_program_kfunc_feature_keys(&checks) else {
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
                check.kfunc,
                check.expected_keys,
                actual_keys
            ));
        }
    }

    assert!(
        !expected.is_empty(),
        "expected at least one kfunc-backed context write surface"
    );
    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu kfunc-backed context write scanner drifted from Rust write surfaces: {}",
        mismatches.join(", ")
    );
}
