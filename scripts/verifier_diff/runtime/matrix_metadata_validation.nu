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
