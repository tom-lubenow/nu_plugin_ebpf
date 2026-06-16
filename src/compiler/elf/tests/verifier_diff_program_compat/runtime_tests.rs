use super::*;

#[test]
fn test_verifier_diff_fixture_summary_exposes_target() {
    let verifier_diff = verifier_diff_source();
    let summary_body = verifier_diff
        .split_once("def fixture-summary [fixture compat_kernel] {")
        .expect("expected fixture-summary function")
        .1
        .split_once("\ndef fixture-status-count")
        .expect("expected fixture-status-count after fixture-summary")
        .0;
    assert!(
        summary_body.contains("target: (optional $fixture target \"\")"),
        "fixture-summary should expose the raw fixture target in --list --json output"
    );

    let list_body = verifier_diff
        .split_once("if $list {")
        .expect("expected list output branch")
        .1
        .split_once("\n    if $matrix {")
        .expect("expected matrix branch after list output branch")
        .0;
    assert!(
        list_body.contains("target=($summary.target)"),
        "human --list output should include the raw fixture target"
    );
    assert!(
        list_body.contains("select-fixture-gap-fixtures $validated_fixtures $gap_only"),
        "--list --gap-only should filter fixture summaries to local-accept/kernel-skip gaps"
    );
}

#[test]
fn test_verifier_diff_kernel_preflight_runs_before_local_execution() {
    let verifier_diff = verifier_diff_source();
    let preflight = verifier_diff
        .find("let required_kernel_candidates = (")
        .expect("expected required --kernel preflight block");
    let plugin_resolution = verifier_diff
        .find("let plugin_bin = (resolve-plugin-bin $REPO_ROOT)")
        .expect("expected plugin resolution before local checks");
    let local_execution = verifier_diff
        .find("let local_results = (check-local-fixtures")
        .expect("expected local fixture execution");

    assert!(
        preflight < plugin_resolution,
        "--kernel availability should be checked before resolving the plugin"
    );
    assert!(
        preflight < local_execution,
        "--kernel availability should be checked before running local fixtures"
    );
}

#[test]
fn test_verifier_diff_diagnostics_tag_requires_local_reject() {
    let script = r#"source scripts/verifier_diff.nu
let bad = [{
    name: "bad-diagnostics-tag"
    tags: [diagnostics accept]
    local: "accept"
}]
try {
    validate-fixture-tags ($bad | first)
    { rejected: false message: "" }
} catch {|err|
    { rejected: true message: $err.msg }
} | to json"#;

    let Some(output) = run_nu_script(script, "diagnostics tag metadata validation") else {
        return;
    };
    assert!(
        output.status.success(),
        "verifier_diff.nu diagnostics tag validation check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("diagnostics tag validation check should emit JSON");
    assert_eq!(
        actual.get("rejected").and_then(serde_json::Value::as_bool),
        Some(true),
        "diagnostics-tagged accept fixture should be rejected"
    );
    assert!(
        actual
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("diagnostics fixtures must be local rejects")),
        "unexpected diagnostics validation error: {actual:?}"
    );
}

#[test]
fn test_verifier_diff_matrix_includes_aggregate_row() {
    let verifier_diff = verifier_diff_source();
    let matrix_rows_body = verifier_diff
        .split_once(
            "def fixture-matrix-rows-from-matrix-summaries [matrix_fixtures compat_kernel] {",
        )
        .expect("expected fixture matrix row builder")
        .1
        .split_once("\ndef print-fixture-matrix")
        .expect("expected matrix print function after row builder")
        .0;

    assert!(
        verifier_diff.contains(
            "def fixture-matrix-row [tier: string category: string fixtures compat_kernel]"
        ),
        "matrix row count logic should stay centralized for category and aggregate rows"
    );
    assert!(
        matrix_rows_body
            .contains("fixture-matrix-row \"all\" \"all\" $matrix_fixtures $compat_kernel"),
        "matrix output should include an aggregate row over the selected fixture corpus"
    );
    assert!(
        verifier_diff.contains("local_accept_kernel_skip=($row.local_accept_kernel_skip)"),
        "human matrix output should expose local accepts that still skip kernel comparison"
    );
    assert!(
        verifier_diff
            .contains("local_accept_kernel_skip_dry_run=($row.local_accept_kernel_skip_dry_run)"),
        "human matrix output should split local-accept/kernel-skip gaps by default lane"
    );
    assert!(
        verifier_diff.contains("--gap-only"),
        "verifier_diff.nu should expose gap-focused list and matrix modes in the CLI"
    );
    assert!(
        verifier_diff.contains("select-fixture-matrix-rows $matrix_rows $gap_only"),
        "matrix output should pass rows through the gap-only selector"
    );
    assert!(
        verifier_diff.contains("$rows | where {|row| $row.local_accept_kernel_skip > 0 }"),
        "gap-only matrix output should filter out rows without local-accept/kernel-skip gaps"
    );
}

#[test]
fn test_verifier_diff_chunk_index_reports_chunk_growth_metadata() {
    let verifier_diff = verifier_diff_source();

    assert!(
        verifier_diff.contains("--chunks"),
        "verifier_diff.nu should expose the fixture chunk index mode in the CLI"
    );
    assert!(
        verifier_diff.contains("def fixture-chunk-index-row [\n    path: path\n    fixture_names"),
        "chunk index rows should keep per-file fixture metadata centralized"
    );
    assert!(
        verifier_diff.contains("line_count: (fixture-chunk-line-count $path)"),
        "chunk index output should include source line counts for review-growth checks"
    );
    assert!(
        verifier_diff.contains("def fixture-chunk-index-summary [rows]"),
        "chunk index output should keep aggregate summary counts centralized"
    );
    assert!(
        verifier_diff.contains(
            "chunk=($row.file) lines=($row.line_count) total=($row.total) selected=($row.selected)"
        ),
        "human chunk index output should expose per-file line and fixture counts"
    );
    assert!(
        verifier_diff.contains("summary chunks=($summary.chunks) lines=($summary.line_count)"),
        "human chunk index output should include an aggregate summary line"
    );
}
