use super::*;

#[test]
fn test_verifier_diff_fixture_summary_reports_too_new_kfunc_window() {
    let script = r#"source scripts/verifier_diff.nu
let fixture = {
    name: "unit-kfunc-window"
    category: "kfunc"
    target: "struct_ops:sched_ext_ops"
    program: [
        "{"
        "    name: \"nu.demo_1\""
        "    cpu_release: {|ctx|"
        "        let ignored = (kfunc-call \"scx_bpf_reenqueue_local\")"
        "        0"
        "    }"
        "}"
    ]
    local: "accept"
    kernel: "skip"
}
let features = (fixture-kernel-features $fixture)
let derived = (fixture-derived-metadata $fixture $features)
let summary = (fixture-summary-from-derived $derived "6.23.0")
{
    effective_min_kernel: $summary.effective_min_kernel
    effective_max_kernel_exclusive: $summary.effective_max_kernel_exclusive
    effective_max_kernel_exclusive_sources: $summary.effective_max_kernel_exclusive_sources
    compatible_with_compat_kernel: $summary.compatible_with_compat_kernel
    compat_kernel_reason: $summary.compat_kernel_reason
    kernel_features: (kernel-feature-labels $summary.kernel_features)
} | to json"#;

    let Some(output) = run_nu_script(script, "compat-kernel max-exclusive kfunc summary") else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu compat-kernel summary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu compat-kernel summary should emit JSON");
    assert_eq!(
        actual
            .get("effective_min_kernel")
            .and_then(serde_json::Value::as_str),
        Some("6.12")
    );
    assert_eq!(
        actual
            .get("effective_max_kernel_exclusive")
            .and_then(serde_json::Value::as_str),
        Some("6.23")
    );
    let max_sources = actual
        .get("effective_max_kernel_exclusive_sources")
        .and_then(serde_json::Value::as_array)
        .expect("summary should include effective max-kernel source list");
    assert!(max_sources.iter().any(|source| {
        source
            .as_str()
            .is_some_and(|source| source.contains("kernel/sched/ext.c"))
    }));
    assert_eq!(
        actual
            .get("compatible_with_compat_kernel")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        actual
            .get("compat_kernel_reason")
            .and_then(serde_json::Value::as_str),
        Some("kernel<6.23")
    );
    let feature_labels = actual
        .get("kernel_features")
        .and_then(serde_json::Value::as_array)
        .expect("summary should include kernel feature labels");
    assert!(feature_labels.iter().any(|label| {
        label
            .as_str()
            .is_some_and(|label| label.contains("kfunc:scx_bpf_reenqueue_local>=6.12,<6.23"))
    }));
}

#[test]
fn test_verifier_diff_matrix_counts_bounded_kernel_windows() {
    let script = r#"source scripts/verifier_diff.nu
let bounded = {
    name: "unit-bounded-kfunc-window"
    category: "kfunc"
    target: "struct_ops:sched_ext_ops"
    program: [
        "{"
        "    name: \"nu.demo_1\""
        "    cpu_release: {|ctx|"
        "        let ignored = (kfunc-call \"scx_bpf_reenqueue_local\")"
        "        0"
        "    }"
        "}"
    ]
    local: "accept"
    kernel: "accept"
}
let unbounded = {
    name: "unit-unbounded-kfunc"
    category: "kfunc"
    target: "kprobe:ksys_read"
    program: [
        "{|ctx|"
        "  let ignored = (kfunc-call \"bpf_get_task_exe_file\")"
        "  0"
        "}"
    ]
    local: "accept"
    kernel: "accept"
}
let derived = (
    [$bounded $unbounded]
    | each {|fixture|
        let features = (fixture-kernel-features $fixture)
        fixture-derived-metadata $fixture $features
    }
)
fixture-matrix-rows-from-derived $derived "6.23.0"
| where category == "kfunc"
| first
| to json"#;

    let Some(output) = run_nu_script(script, "compat-kernel bounded matrix counts") else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu compat-kernel matrix failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("verifier_diff.nu compat-kernel matrix should emit JSON");
    let int_field = |field: &str| {
        actual
            .get(field)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("matrix row should include integer field {field}"))
    };

    assert_eq!(int_field("kernel_accept"), 2);
    assert_eq!(int_field("kernel_accept_versioned"), 2);
    assert_eq!(int_field("kernel_accept_unversioned"), 0);
    assert_eq!(int_field("kernel_accept_bounded"), 1);
    assert_eq!(int_field("kernel_accept_unbounded"), 1);
    assert_eq!(int_field("kernel_accept_compatible"), 1);
    assert_eq!(int_field("kernel_accept_incompatible"), 1);
    assert_eq!(int_field("kernel_accept_requires_newer"), 0);
    assert_eq!(int_field("kernel_accept_requires_older"), 1);
}

#[test]
fn test_verifier_diff_compat_kernel_parser_preserves_dotted_versions() {
    let script = r#"source scripts/verifier_diff.nu
let ok = (parse-main-args ["--matrix" "--compat-kernel=5.10"])
let bad = try {
    parse-main-args ["--matrix" "--compat-kernel" 5.10]
    { rejected: false message: "" }
} catch {|err|
    { rejected: true message: $err.msg }
}
{
    compat_kernel: $ok.compat_kernel
    rejected_unquoted_numeric: $bad.rejected
    rejection_message: $bad.message
} | to json"#;

    let Some(output) = run_nu_script(script, "compat-kernel parser preserves dotted versions")
    else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu compat-kernel parser check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("compat-kernel parser check should emit JSON");
    assert_eq!(
        actual
            .get("compat_kernel")
            .and_then(serde_json::Value::as_str),
        Some("5.10")
    );
    assert_eq!(
        actual
            .get("rejected_unquoted_numeric")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        actual
            .get("rejection_message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("--compat-kernel=5.10")),
        "rejection should tell users to preserve dotted versions with assignment syntax"
    );
}
