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

def validate-tier-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TIERS {
        fail $"invalid ($label) tier '($value)'; expected one of ($VALID_TIERS | str join ', ')"
    }
}

def validate-test-lane-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TEST_LANES {
        fail $"invalid ($label) test lane '($value)'; expected one of ($VALID_TEST_LANES | str join ', ')"
    }
}

def validate-status-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in [accept reject skip] {
        fail $"invalid ($label) status '($value)'; expected accept, reject, or skip"
    }
}

def validate-host-features [fixture field: string] {
    for feature in (optional $fixture $field []) {
        if ($feature | str starts-with "tracepoint:") {
            continue
        }
        if ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) {
            let kfunc = ($feature | str substring ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC | str length)..)
            if $kfunc == "" {
                fail $"fixture ($fixture.name) declares empty ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) host feature in ($field)"
            }
            continue
        }
        if $feature not-in $VALID_HOST_FEATURES {
            fail $"fixture ($fixture.name) declares unknown ($field) feature '($feature)'; expected one of ($VALID_HOST_FEATURES | str join ', '), tracepoint:<system>/<event>, or ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC)<symbol>"
        }
    }
}

def validate-fixture-tags [fixture] {
    let tags = (optional $fixture tags [])
    for tag in $tags {
        if (($tag | describe) != "string") {
            fail $"fixture ($fixture.name) declares non-string tag value '($tag)'"
        }
        if ($tag | str trim) == "" {
            fail $"fixture ($fixture.name) declares an empty tag"
        }
    }

    for tag in ($tags | uniq) {
        let count = ($tags | where {|candidate| $candidate == $tag } | length)
        if $count > 1 {
            fail $"fixture ($fixture.name) declares duplicate tag '($tag)'"
        }
    }
}

def validate-kernel-feature-key-uniqueness [fixture_name: string origin: string features] {
    let keys = ($features | each {|feature| $feature | get -o key })

    for key in ($keys | uniq) {
        if $key == null or $key == "" {
            fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
        }

        let count = ($keys | where {|candidate| $candidate == $key } | length)
        if $count > 1 {
            fail $"fixture ($fixture_name) ($origin) declares duplicate kernel feature key: ($key)"
        }
    }
}

def validate-kernel-feature-record [fixture_name: string origin: string feature] {
    let key = ($feature | get -o key)
    let min_kernel = ($feature | get -o min_kernel)
    let max_kernel = ($feature | get -o max_kernel_exclusive)
    let max_kernel_source = ($feature | get -o max_kernel_exclusive_source)
    let source = ($feature | get -o source)

    if $key == null or $key == "" {
        fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
    }
    if $min_kernel == null or $min_kernel == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing min_kernel"
    }
    if $source == null or $source == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing source"
    }

    parse-kernel-version $min_kernel | ignore
    if $max_kernel != null and $max_kernel != "" {
        parse-kernel-version $max_kernel | ignore
        if $max_kernel_source == null or $max_kernel_source == "" {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) with max_kernel_exclusive=($max_kernel) missing max_kernel_exclusive_source"
        }
        if (kernel-version-compare $max_kernel $min_kernel) <= 0 {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) max_kernel_exclusive=($max_kernel) must be greater than min_kernel=($min_kernel)"
        }
    } else if $max_kernel_source != null and $max_kernel_source != "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) declares max_kernel_exclusive_source without max_kernel_exclusive"
    }
}

def validate-kernel-feature-metadata [fixture] {
    let features = (optional $fixture kernel_features [])
    let keys = ($features | each {|feature| $feature | get -o key })
    validate-kernel-feature-key-uniqueness $fixture.name "explicit kernel_features" $features

    for feature in $features {
        validate-kernel-feature-record $fixture.name "explicit kernel_features" $feature
    }

    for helper_name in (program-helper-names (fixture-program $fixture)) {
        let key = $"helper:($helper_name)"
        let known_feature = (helper-kernel-feature $helper_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls helper ($helper_name) without source-backed kernel metadata; add it to BPF_HELPER_IDS/HELPER_KERNEL_FEATURES or declare explicit kernel_features metadata"
        }
    }

    for kfunc_name in (program-kfunc-names (fixture-program $fixture)) {
        let key = $"kfunc:($kfunc_name)"
        let known_feature = (kfunc-kernel-feature $kfunc_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls kfunc ($kfunc_name) without source-backed kernel metadata; add it to KFUNC_KERNEL_FEATURES/KFUNC_KERNEL_FEATURE_FALLBACKS or declare explicit kernel_features metadata"
        }
    }

    let effective_features = (fixture-kernel-features $fixture)
    validate-kernel-feature-key-uniqueness $fixture.name "effective kernel_features" $effective_features
    for feature in $effective_features {
        validate-kernel-feature-record $fixture.name "effective kernel_features" $feature
    }

    $effective_features
}

def validate-fixture-metadata [fixtures] {
    let names = ($fixtures | each {|fixture| $fixture.name })

    for name in ($names | uniq --repeated) {
        fail $"duplicate verifier fixture name: ($name)"
    }

    $fixtures | each {|fixture|
        validate-tier-option $"fixture ($fixture.name)" ($fixture | get -o tier)
        validate-test-lane-option $"fixture ($fixture.name)" ($fixture | get -o default_test_lane)
        validate-status-option $"fixture ($fixture.name) local" $fixture.local
        validate-status-option $"fixture ($fixture.name) kernel" $fixture.kernel
        if $fixture.local != "accept" and $fixture.kernel != "skip" {
            fail $"fixture ($fixture.name) declares kernel=($fixture.kernel), but kernel checks only run after local accept; use kernel=skip for local ($fixture.local) fixtures"
        }
        validate-fixture-tags $fixture
        validate-host-features $fixture requires
        validate-host-features $fixture kernel_requires
        let kernel_features = (validate-kernel-feature-metadata $fixture)

        let min_kernel = ($fixture | get -o min_kernel)
        let min_kernel_source = ($fixture | get -o min_kernel_source)

        if $min_kernel != null and ($min_kernel_source == null or $min_kernel_source == "") {
            fail $"fixture ($fixture.name) declares min_kernel=($min_kernel) without min_kernel_source"
        }

        if $min_kernel == null and $min_kernel_source != null {
            fail $"fixture ($fixture.name) declares min_kernel_source without min_kernel"
        }

        if $min_kernel != null {
            parse-kernel-version $min_kernel | ignore
        }

        let derived = (fixture-derived-metadata $fixture $kernel_features)
        if $fixture.local == "accept" and $fixture.kernel == "skip" and $derived.default_test_lane == "host-safe" {
            fail $"fixture ($fixture.name) is local-accept/kernel-skip but defaults to host-safe; set default_test_lane to dry-run, host-gated, or vm-only"
        }
        $derived
    }
}
