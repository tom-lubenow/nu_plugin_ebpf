use super::*;

#[test]
fn test_verifier_diff_fixture_summary_exposes_target() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
}

#[test]
fn test_verifier_diff_kernel_preflight_runs_before_local_execution() {
    let verifier_diff = VERIFIER_DIFF_SOURCE;
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
