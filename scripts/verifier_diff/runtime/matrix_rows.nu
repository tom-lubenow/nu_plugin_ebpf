def fixture-matrix-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-matrix-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-matrix-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        tier: $derived.tier
        category: $derived.category
        local: $derived.local
        kernel: $derived.kernel
        default_test_lane: $derived.default_test_lane
        has_effective_min_kernel: ($derived.effective_min_kernel_raw != null)
        has_effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw != null)
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
    }
}

def matrix-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def matrix-status-pair-count [fixtures left_field: string left_status: string right_field: string right_status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $left_field) == $left_status }
    | where {|fixture| ($fixture | get $right_field) == $right_status }
    | length
}

def matrix-status-pair-lane-count [fixtures left_field: string left_status: string right_field: string right_status: string lane: string] {
    $fixtures
    | where {|fixture| ($fixture | get $left_field) == $left_status }
    | where {|fixture| ($fixture | get $right_field) == $right_status }
    | where {|fixture| $fixture.default_test_lane == $lane }
    | length
}

def matrix-kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel == $versioned }
    | length
}

def matrix-kernel-accept-bounded-count [fixtures bounded: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_max_kernel_exclusive == $bounded }
    | length
}

def matrix-kernel-accept-compatible-count [fixtures compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel }
    | where {|fixture| $fixture.compatible_with_compat_kernel == $compatible }
    | length
}

def matrix-kernel-accept-compat-reason-count [fixtures reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ($fixture.compat_kernel_reason | str starts-with $reason_prefix) }
    | length
}

def matrix-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| $fixture.default_test_lane == $lane }
    | length
}

def fixture-matrix-row [tier: string category: string fixtures compat_kernel] {
    let base = {
        tier: $tier
        category: $category
        total: ($fixtures | length)
        local_accept: (matrix-status-count $fixtures local accept)
        local_reject: (matrix-status-count $fixtures local reject)
        local_skip: (matrix-status-count $fixtures local skip)
        kernel_accept: (matrix-status-count $fixtures kernel accept)
        kernel_reject: (matrix-status-count $fixtures kernel reject)
        kernel_skip: (matrix-status-count $fixtures kernel skip)
        local_accept_kernel_skip: (matrix-status-pair-count $fixtures local accept kernel skip)
        local_accept_kernel_skip_dry_run: (matrix-status-pair-lane-count $fixtures local accept kernel skip "dry-run")
        local_accept_kernel_skip_host_gated: (matrix-status-pair-lane-count $fixtures local accept kernel skip "host-gated")
        local_accept_kernel_skip_vm_only: (matrix-status-pair-lane-count $fixtures local accept kernel skip "vm-only")
        kernel_accept_versioned: (matrix-kernel-accept-versioned-count $fixtures true)
        kernel_accept_unversioned: (matrix-kernel-accept-versioned-count $fixtures false)
        kernel_accept_bounded: (matrix-kernel-accept-bounded-count $fixtures true)
        kernel_accept_unbounded: (matrix-kernel-accept-bounded-count $fixtures false)
        lane_host_safe: (matrix-test-lane-count $fixtures "host-safe")
        lane_host_gated: (matrix-test-lane-count $fixtures "host-gated")
        lane_dry_run: (matrix-test-lane-count $fixtures "dry-run")
        lane_vm_only: (matrix-test-lane-count $fixtures "vm-only")
    }

    if $compat_kernel == null {
        $base
    } else {
        $base
        | upsert compat_kernel $compat_kernel
        | upsert kernel_accept_compatible (matrix-kernel-accept-compatible-count $fixtures true)
        | upsert kernel_accept_incompatible (matrix-kernel-accept-compatible-count $fixtures false)
        | upsert kernel_accept_requires_newer (matrix-kernel-accept-compat-reason-count $fixtures "kernel>=")
        | upsert kernel_accept_requires_older (matrix-kernel-accept-compat-reason-count $fixtures "kernel<")
    }
}

def fixture-matrix-rows [fixtures compat_kernel] {
    let matrix_fixtures = (
        $fixtures
        | each {|fixture| fixture-matrix-summary $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-derived [derived_fixtures compat_kernel] {
    let matrix_fixtures = (
        $derived_fixtures
        | each {|fixture| fixture-matrix-summary-from-derived $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-matrix-summaries [matrix_fixtures compat_kernel] {
    mut rows = []

    for tier in $VALID_TIERS {
        let tier_fixtures = (
            $matrix_fixtures
            | where {|fixture| $fixture.tier == $tier }
        )

        if (($tier_fixtures | length) == 0) {
            continue
        }

        let categories = (
            $tier_fixtures
            | each {|fixture| optional $fixture category "" }
            | uniq
            | sort
        )

        for category in $categories {
            let category_fixtures = (
                $tier_fixtures
                | where {|fixture| (optional $fixture category "") == $category }
            )

            $rows = ($rows | append (fixture-matrix-row $tier $category $category_fixtures $compat_kernel))
        }
    }

    if (($matrix_fixtures | length) > 0) {
        $rows = ($rows | append (fixture-matrix-row "all" "all" $matrix_fixtures $compat_kernel))
    }

    $rows
}

def print-fixture-matrix [fixtures compat_kernel] {
    for row in (fixture-matrix-rows $fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-from-derived [derived_fixtures compat_kernel] {
    for row in (fixture-matrix-rows-from-derived $derived_fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-row [row] {
    let compat_text = if (($row | get -o compat_kernel) == null) {
        ""
    } else {
        $" compat_kernel=($row.compat_kernel) kernel_accept_compatible=($row.kernel_accept_compatible) kernel_accept_incompatible=($row.kernel_accept_incompatible) kernel_accept_requires_newer=($row.kernel_accept_requires_newer) kernel_accept_requires_older=($row.kernel_accept_requires_older)"
    }
    print $"tier=($row.tier) category=($row.category) total=($row.total) local_accept=($row.local_accept) local_reject=($row.local_reject) local_skip=($row.local_skip) kernel_accept=($row.kernel_accept) kernel_reject=($row.kernel_reject) kernel_skip=($row.kernel_skip) local_accept_kernel_skip=($row.local_accept_kernel_skip) local_accept_kernel_skip_dry_run=($row.local_accept_kernel_skip_dry_run) local_accept_kernel_skip_host_gated=($row.local_accept_kernel_skip_host_gated) local_accept_kernel_skip_vm_only=($row.local_accept_kernel_skip_vm_only) kernel_accept_versioned=($row.kernel_accept_versioned) kernel_accept_unversioned=($row.kernel_accept_unversioned) kernel_accept_bounded=($row.kernel_accept_bounded) kernel_accept_unbounded=($row.kernel_accept_unbounded) lane_host_safe=($row.lane_host_safe) lane_host_gated=($row.lane_host_gated) lane_dry_run=($row.lane_dry_run) lane_vm_only=($row.lane_vm_only)($compat_text)"
}
