#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
source ($REPO_ROOT | path join scripts verifier_diff metadata core_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata tracepoint_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata context_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata expectations.nu)

source ($REPO_ROOT | path join scripts verifier_diff fixtures.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime core.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime source_text.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_fields.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_roots.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime program_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime matrix_validation.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime expectation_validation.nu)

def main [] {
    validate-verifier-feature-expectations
    let _validated_fixtures = (validate-fixture-metadata $FIXTURES)
    print $"ok: (($FIXTURES | length)) verifier fixtures metadata-valid"
}
