use std::collections::BTreeSet;
use std::process::Output;

use super::source_support::run_nu_script;

pub(super) fn verifier_diff_nu_target_feature_keys(
    targets: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    let target_rows = targets
        .iter()
        .map(|target| format!("    {target:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let targets = [
{target_rows}
]
$targets
| enumerate
| each {{|row|
    {{
        index: $row.index
        keys: (
            target-kernel-features $row.item
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, "target-kernel-features coverage")?;
    assert_verifier_diff_nu_success(&output, "target-kernel-features");

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        "target-kernel-features",
        targets.len(),
        "target",
    ))
}

fn verifier_diff_nu_program_feature_keys(
    function_name: &str,
    label: &str,
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    let check_rows = checks
        .iter()
        .map(|(target, program)| format!("    {{ target: {:?} program: {:?} }}", target, program))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let checks = [
{check_rows}
]
$checks
| enumerate
| each {{|row|
    let check = $row.item
    {{
        index: $row.index
        keys: (
            {function_name} $check.program $check.target
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, label)?;
    assert_verifier_diff_nu_success(&output, function_name);

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        function_name,
        checks.len(),
        "checked program",
    ))
}

fn verifier_diff_nu_program_only_feature_keys(
    function_name: &str,
    label: &str,
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    let program_rows = programs
        .iter()
        .map(|program| format!("    {program:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    let script = format!(
        r#"source scripts/verifier_diff.nu
let programs = [
{program_rows}
]
$programs
| enumerate
| each {{|row|
    {{
        index: $row.index
        keys: (
            {function_name} $row.item
            | each {{|feature| $feature.key }}
            | sort
        )
    }}
}}
| to json"#
    );

    let output = run_nu_script(&script, label)?;
    assert_verifier_diff_nu_success(&output, function_name);

    Some(verifier_diff_nu_indexed_feature_keys(
        &output.stdout,
        function_name,
        programs.len(),
        "checked program",
    ))
}

fn assert_verifier_diff_nu_success(output: &Output, function_name: &str) {
    assert!(
        output.status.success(),
        "verifier_diff.nu {function_name} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verifier_diff_nu_indexed_feature_keys(
    stdout: &[u8],
    function_name: &str,
    expected_len: usize,
    subject: &str,
) -> Vec<BTreeSet<String>> {
    let actual: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|_| panic!("verifier_diff.nu {function_name} should emit JSON"));
    let actual = actual
        .as_array()
        .unwrap_or_else(|| panic!("verifier_diff.nu {function_name} output should be a JSON list"));
    assert_eq!(
        actual.len(),
        expected_len,
        "verifier_diff.nu {function_name} should return one result per {subject}"
    );

    let mut keys_by_index = vec![BTreeSet::new(); expected_len];
    for value in actual {
        let index = value
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                panic!("verifier_diff.nu {function_name} result should include index")
            }) as usize;
        assert!(
            index < expected_len,
            "verifier_diff.nu {function_name} index should refer to a {subject}"
        );
        let keys = value
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| {
                panic!("verifier_diff.nu {function_name} result should include keys")
            });
        keys_by_index[index] = keys
            .iter()
            .map(|key| {
                key.as_str()
                    .unwrap_or_else(|| {
                        panic!("verifier_diff.nu {function_name} keys should be strings")
                    })
                    .to_string()
            })
            .collect();
    }

    keys_by_index
}

pub(super) fn verifier_diff_nu_program_map_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-map-kernel-features",
        "program-map-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_reserved_map_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-reserved-map-kernel-features",
        "program-reserved-map-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_language_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-language-kernel-features",
        "program-language-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_map_value_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-map-value-kernel-features",
        "program-map-value-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_global_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-global-kernel-features",
        "program-global-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_helper_feature_keys(
    programs: &[String],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_only_feature_keys(
        "program-helper-kernel-features",
        "program-helper-kernel-features coverage",
        programs,
    )
}

pub(super) fn verifier_diff_nu_program_context_field_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-context-field-kernel-features",
        "program-context-field-kernel-features write coverage",
        checks,
    )
}

pub(super) fn verifier_diff_nu_program_kfunc_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-kfunc-kernel-features",
        "program-kfunc-kernel-features write coverage",
        checks,
    )
}

pub(super) fn verifier_diff_nu_program_struct_ops_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-struct-ops-kernel-features",
        "program-struct-ops-kernel-features coverage",
        checks,
    )
}

pub(super) fn verifier_diff_nu_program_surface_feature_keys(
    checks: &[(String, String)],
) -> Option<Vec<BTreeSet<String>>> {
    verifier_diff_nu_program_feature_keys(
        "program-surface-kernel-features",
        "program-surface-kernel-features write coverage",
        checks,
    )
}
