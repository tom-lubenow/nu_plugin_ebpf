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
source ($REPO_ROOT | path join scripts verifier_diff runtime execution.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime cli_options.nu)

def --wrapped main [...args] {
    if (($env | get -o VERIFIER_DIFF_SOURCE_ONLY) == "1") {
        return
    }

    let options = (parse-main-args $args)
    if $options.help {
        print-main-help
        return
    }

    verifier-diff-main $options
}

def verifier-diff-main [options] {
    let validate = $options.validate
    let check_host_syscall_tracepoints = $options.check_host_syscall_tracepoints
    let list = $options.list
    let matrix = $options.matrix
    let json = $options.json
    let compat_kernel = $options.compat_kernel
    let kernel = $options.kernel
    let no_kernel = $options.no_kernel
    let smoke = $options.smoke
    let fast = $options.fast
    let full = $options.full
    let fixture = $options.fixture
    let fixtures = $options.fixtures
    let category = $options.category
    let tag = $options.tag
    let tier = $options.tier
    let exclude_tier = $options.exclude_tier
    let test_lane = $options.test_lane
    let local_status = $options.local_status
    let kernel_status = $options.kernel_status
    let jobs = $options.jobs

    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }
    if $list and $matrix {
        fail "--list and --matrix are mutually exclusive"
    }
    if $validate and ($list or $matrix) {
        fail "--validate cannot be combined with --list or --matrix"
    }
    if $check_host_syscall_tracepoints and ($validate or $list or $matrix) {
        fail "--check-host-syscall-tracepoints cannot be combined with --validate, --list, or --matrix"
    }
    if $json and not ($list or $matrix) {
        fail "--json is only supported with --list or --matrix"
    }
    if $compat_kernel != null and not ($list or $matrix) {
        fail "--compat-kernel is only supported with --list or --matrix"
    }
    if $fast and $tier != null {
        fail "--fast and --tier are mutually exclusive"
    }
    if $fast and $exclude_tier != null {
        fail "--fast and --exclude-tier are mutually exclusive"
    }
    if $smoke and $fast {
        fail "--smoke and --fast are mutually exclusive"
    }
    if $smoke and $full {
        fail "--smoke and --full are mutually exclusive"
    }
    if $fast and $full {
        fail "--fast and --full are mutually exclusive"
    }
    if $smoke and $tier != null {
        fail "--smoke and --tier are mutually exclusive"
    }
    if $smoke and $exclude_tier != null {
        fail "--smoke and --exclude-tier are mutually exclusive"
    }
    if $smoke and $test_lane != null {
        fail "--smoke and --test-lane are mutually exclusive"
    }
    if $fixture != null and $fixtures != null {
        fail "--fixture and --fixtures are mutually exclusive"
    }

    if $check_host_syscall_tracepoints and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--check-host-syscall-tracepoints is a standalone host coverage audit and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--validate checks all fixture metadata and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate {
        let _validated_fixtures = (validate-fixture-metadata $FIXTURES)
        print $"ok: (($FIXTURES | length)) verifier fixtures metadata-valid"
        return
    }

    if $check_host_syscall_tracepoints {
        check-host-syscall-tracepoint-coverage
        return
    }

    if $compat_kernel != null {
        parse-kernel-version $compat_kernel | ignore
    }

    let explicit_selection = (
        has-explicit-fixture-selection
            $fixture
            $fixtures
            $category
            $tag
            $tier
            $exclude_tier
            $test_lane
            $local_status
            $kernel_status
            $fast
            $smoke
            $full
    )
    let default_smoke = (not ($list or $matrix) and not $explicit_selection)
    let selected_tier = if ($smoke or $default_smoke or $fast) { "fast" } else { $tier }
    let selected_test_lane = if ($smoke or $default_smoke) { "host-safe" } else { $test_lane }
    let fixture_names = if $fixture == null { $fixtures } else { $fixture }
    let fixtures = (select-fixtures $fixture_names $category $tag $selected_tier $exclude_tier $local_status $kernel_status $selected_test_lane)
    let validated_fixtures = (validate-fixture-metadata $fixtures)

    if $list {
        let summaries = ($validated_fixtures | each {|fixture| fixture-summary-from-derived $fixture $compat_kernel })
        if $json {
            print ($summaries | to json)
            return
        }

        for summary in $summaries {
            let compat_text = if $compat_kernel == null {
                ""
            } else {
                $" compat_kernel=($summary.compat_kernel) compatible=($summary.compatible_with_compat_kernel) compat_reason=($summary.compat_kernel_reason)"
            }
            print $"($summary.name) target=($summary.target) local=($summary.local) kernel=($summary.kernel) category=($summary.category) tier=($summary.tier) default_test_lane=($summary.default_test_lane) requires=($summary.requires | str join ',') kernel_requires=($summary.kernel_requires | str join ',') effective_min_kernel=($summary.effective_min_kernel) effective_max_kernel_exclusive=($summary.effective_max_kernel_exclusive) kernel_features=(kernel-feature-labels $summary.kernel_features | str join ',') tags=($summary.tags | str join ',')($compat_text)"
        }
        return
    }
    if $matrix {
        if $json {
            print ((fixture-matrix-rows-from-derived $validated_fixtures $compat_kernel) | to json)
        } else {
            print-fixture-matrix-from-derived $validated_fixtures $compat_kernel
        }
        return
    }

    let local_jobs = (resolve-local-jobs $jobs)
    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    print $"Using plugin: ($plugin_bin)"
    if $local_jobs > 1 {
        print $"Using local fixture jobs: ($local_jobs)"
    }
    if $default_smoke {
        print "Using default smoke lane: --tier fast --test-lane host-safe. Pass --full for the complete fixture sweep."
    }

    let local_fixtures = (select-fixtures-with-requirements $fixtures $kernel "local")
    if (($local_fixtures | length) == 0) {
        print "ok: 0 local fixtures"
        return
    }

    let local_results = (check-local-fixtures $plugin_bin $local_fixtures $local_jobs)

    let local_accepts = (
        $local_fixtures
        | zip $local_results
        | where {|pair| ($pair.1 | get local) == "accept" }
        | each {|pair| $pair.0 }
    )

    if $no_kernel {
        print $"ok: (($local_fixtures | length)) local fixtures, kernel checks disabled"
        return
    }

    let kernel_candidates = (
        $local_accepts
        | where {|fixture| $fixture.kernel != "skip" }
    )
    let kernel_fixtures = (select-kernel-fixtures $kernel_candidates $kernel)
    if (($kernel_fixtures | length) == 0) {
        print $"ok: (($local_fixtures | length)) local fixtures, no kernel fixtures"
        return
    }

    let preflight = (kernel-preflight)
    if not $preflight.available {
        let reason = ($preflight.reasons | str join "; ")
        if $kernel {
            fail $"kernel verifier checks requested but unavailable: ($reason)"
        }
        print $"kernel skip: ($reason)"
        print $"ok: (($local_fixtures | length)) local fixtures"
        return
    }

    let tmp_dir = (^mktemp -d | str trim)
    try {
        $kernel_fixtures
        | each {|fixture|
            let result = (run-kernel-fixture $plugin_bin $fixture $tmp_dir)
            print $"kernel ($result.kernel)  ($fixture.name)"
            $result
        }
        | ignore
        rm -rf $tmp_dir
    } catch { |err|
        try { rm -rf $tmp_dir } catch { |_| null }
        error make $err
    }

    print $"ok: (($local_fixtures | length)) local fixtures, (($kernel_fixtures | length)) kernel fixtures"
}
