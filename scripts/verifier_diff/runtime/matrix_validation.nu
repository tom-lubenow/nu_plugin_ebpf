const VERIFIER_DIFF_MATRIX_RUNTIME_DIR = (path self | path dirname)

def effective-min-kernel-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature.min_kernel }
    )

    kernel-version-max $versions
}

def effective-max-kernel-exclusive-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature | get -o max_kernel_exclusive }
        | where {|version| $version != null and $version != "" }
    )

    kernel-version-min $versions
}

def effective-max-kernel-exclusive-sources-from-features [features] {
    let max_kernel = (effective-max-kernel-exclusive-from-features $features)
    if $max_kernel == null {
        return []
    }

    $features
    | where {|feature| ($feature | get -o max_kernel_exclusive) == $max_kernel }
    | each {|feature| $feature | get -o max_kernel_exclusive_source }
    | where {|source| $source != null and $source != "" }
    | uniq
}

def effective-min-kernel-sources-from-features [features] {
    let min_kernel = (effective-min-kernel-from-features $features)
    if $min_kernel == null {
        return []
    }

    $features
    | where {|feature| $feature.min_kernel == $min_kernel }
    | each {|feature| $feature.source }
    | uniq
}

def kernel-feature-compatibility [min_kernel max_kernel kernel_release] {
    if $kernel_release == null or ($min_kernel == null and $max_kernel == null) {
        return {
            compatible: true
            required: ""
            reason: ""
        }
    }

    let too_old = ($min_kernel != null and not (kernel-version-at-least $kernel_release $min_kernel))
    let too_new = ($max_kernel != null and not (kernel-version-before $kernel_release $max_kernel))
    let compatible = (not $too_old and not $too_new)
    let reason = if $too_old {
        $"kernel>=($min_kernel)"
    } else if $too_new {
        $"kernel<($max_kernel)"
    } else {
        ""
    }
    {
        compatible: $compatible
        required: ($min_kernel | default "")
        maximum_exclusive: ($max_kernel | default "")
        reason: $reason
    }
}

def fixture-effective-min-kernel [fixture] {
    effective-min-kernel-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-max-kernel-exclusive [fixture] {
    effective-max-kernel-exclusive-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-min-kernel-sources [fixture] {
    effective-min-kernel-sources-from-features (fixture-kernel-features $fixture)
}

def fixture-kernel-compatibility [fixture kernel_release] {
    let features = (fixture-kernel-features $fixture)
    kernel-feature-compatibility (effective-min-kernel-from-features $features) (effective-max-kernel-exclusive-from-features $features) $kernel_release
}

def test-lane-rank [lane: string] {
    if $lane == "host-safe" {
        0
    } else if $lane == "host-gated" {
        1
    } else if $lane == "dry-run" {
        2
    } else if $lane == "vm-only" {
        3
    } else {
        0
    }
}

def stricter-test-lane [left: string right: string] {
    if (test-lane-rank $right) > (test-lane-rank $left) {
        $right
    } else {
        $left
    }
}

def aggregate-test-lanes [lanes] {
    mut lane = "host-safe"

    for candidate in $lanes {
        if $candidate != null and $candidate != "" {
            $lane = (stricter-test-lane $lane $candidate)
        }
    }

    $lane
}

def kernel-feature-default-test-lane [feature] {
    let key = ($feature | get -o key | default "")

    if ($key | str starts-with "struct_ops:") {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_STRUCT_OPS"
        "program:BPF_PROG_TYPE_LWT"
        "attach:netfilter-link"
    ] {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_EXT"
        "program:BPF_PROG_TYPE_SYSCALL"
    ] {
        return "dry-run"
    }

    if $key in [
        "section:raw_tracepoint.w"
        "program:BPF_PROG_TYPE_SOCKET_FILTER"
        "program:BPF_PROG_TYPE_XDP"
        "attach:xdp-skb"
        "attach:xdp-drv"
        "attach:xdp-hw"
        "attach:BPF_XDP_DEVMAP"
        "attach:BPF_XDP_CPUMAP"
        "section:xdp.frags"
        "program:BPF_PROG_TYPE_SCHED_CLS"
        "program:BPF_PROG_TYPE_SCHED_ACT"
        "program:BPF_PROG_TYPE_SK_LOOKUP"
        "attach:BPF_LSM_CGROUP"
        "program:BPF_PROG_TYPE_FLOW_DISSECTOR"
        "attach:tcx"
        "attach:netkit"
        "attach:netfilter-defrag"
        "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"
        "program:BPF_PROG_TYPE_SK_MSG"
        "program:BPF_PROG_TYPE_SK_SKB"
        "attach:BPF_SK_REUSEPORT_SELECT"
        "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
        "program:BPF_PROG_TYPE_CGROUP_SKB"
        "program:BPF_PROG_TYPE_CGROUP_SOCK"
        "program:BPF_PROG_TYPE_CGROUP_DEVICE"
        "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
        "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
        "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
        "program:BPF_PROG_TYPE_SOCK_OPS"
        "attach:BPF_CGROUP_UNIX_SOCK_ADDR"
        "program:BPF_PROG_TYPE_LIRC_MODE2"
    ] {
        return "host-gated"
    }

    "host-safe"
}

def fixture-default-test-lane-from-features [fixture features] {
    let explicit = ($fixture | get -o default_test_lane)
    if $explicit != null {
        return $explicit
    }

    let lanes = (
        $features
        | each {|feature| kernel-feature-default-test-lane $feature }
    )
    aggregate-test-lanes $lanes
}

def fixture-default-test-lane [fixture] {
    fixture-default-test-lane-from-features $fixture (fixture-kernel-features $fixture)
}

def kernel-feature-labels [features] {
    $features
    | each {|feature|
        let max_kernel = ($feature | get -o max_kernel_exclusive)
        if $max_kernel == null or $max_kernel == "" {
            $"($feature.key)>=($feature.min_kernel)"
        } else {
            $"($feature.key)>=($feature.min_kernel),<($max_kernel)"
        }
    }
}

def fixture-tier [fixture] {
    let explicit = ($fixture | get -o tier)
    if $explicit != null {
        return $explicit
    }

    let requirements = (
        optional $fixture requires []
        | append (optional $fixture kernel_requires [])
    )

    if ($requirements | any {|feature| ($feature in ["kernel-btf" "tracefs"]) or ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) }) {
        "btf"
    } else {
        "fast"
    }
}

def fixture-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-derived-metadata [fixture kernel_features] {
    let effective_min_kernel = (effective-min-kernel-from-features $kernel_features)
    let effective_max_kernel_exclusive = (effective-max-kernel-exclusive-from-features $kernel_features)
    let default_test_lane = (fixture-default-test-lane-from-features $fixture $kernel_features)

    {
        fixture: $fixture
        name: $fixture.name
        target: (optional $fixture target "")
        category: (optional $fixture category "")
        tier: (fixture-tier $fixture)
        local: $fixture.local
        kernel: $fixture.kernel
        requires: (optional $fixture requires [])
        kernel_requires: (optional $fixture kernel_requires [])
        kernel_features: $kernel_features
        default_test_lane: $default_test_lane
        default_test_lane_description: (test-lane-description $default_test_lane)
        effective_min_kernel_raw: $effective_min_kernel
        effective_max_kernel_exclusive_raw: $effective_max_kernel_exclusive
        effective_min_kernel_sources: (effective-min-kernel-sources-from-features $kernel_features)
        effective_max_kernel_exclusive_sources: (effective-max-kernel-exclusive-sources-from-features $kernel_features)
        min_kernel: (optional $fixture min_kernel "")
        min_kernel_source: (optional $fixture min_kernel_source "")
        tags: (optional $fixture tags [])
    }
}

def fixture-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        name: $derived.name
        target: $derived.target
        category: $derived.category
        tier: $derived.tier
        local: $derived.local
        kernel: $derived.kernel
        requires: $derived.requires
        kernel_requires: $derived.kernel_requires
        kernel_features: $derived.kernel_features
        default_test_lane: $derived.default_test_lane
        default_test_lane_description: $derived.default_test_lane_description
        effective_min_kernel: ($derived.effective_min_kernel_raw | default "")
        effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw | default "")
        effective_min_kernel_sources: $derived.effective_min_kernel_sources
        effective_max_kernel_exclusive_sources: $derived.effective_max_kernel_exclusive_sources
        compat_kernel: ($compat_kernel | default "")
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
        min_kernel: $derived.min_kernel
        min_kernel_source: $derived.min_kernel_source
        tags: $derived.tags
    }
}

def fixture-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def fixture-has-effective-min-kernel [fixture] {
    (fixture-effective-min-kernel $fixture) != null
}

def kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| (fixture-has-effective-min-kernel $fixture) == $versioned }
    | length
}

def kernel-accept-compatible-count [fixtures kernel_release compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| fixture-has-effective-min-kernel $fixture }
    | where {|fixture| (fixture-kernel-compatibility $fixture $kernel_release).compatible == $compatible }
    | length
}

def kernel-accept-compat-reason-count [fixtures kernel_release reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ((fixture-kernel-compatibility $fixture $kernel_release).reason | str starts-with $reason_prefix) }
    | length
}

def fixture-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| (fixture-default-test-lane $fixture) == $lane }
    | length
}

source ($VERIFIER_DIFF_MATRIX_RUNTIME_DIR | path join matrix_rows.nu)
source ($VERIFIER_DIFF_MATRIX_RUNTIME_DIR | path join matrix_metadata_validation.nu)
