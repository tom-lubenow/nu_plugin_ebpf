def validate-kernel-feature-key-expectation [label: string expected_keys actual_keys] {
    let expected_keys = ($expected_keys | sort)
    let actual_keys = ($actual_keys | sort)
    let missing = ($expected_keys | where {|key| $key not-in $actual_keys })
    let unexpected = ($actual_keys | where {|key| $key not-in $expected_keys })

    if (($missing | length) > 0) or (($unexpected | length) > 0) {
        fail $"($label) drifted: missing=($missing | str join ',') unexpected=($unexpected | str join ',') actual=($actual_keys | str join ',')"
    }
}

def validate-program-target-kernel-feature-expectations [] {
    for expectation in $PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let actual_keys = (
            target-kernel-features $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"target-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-language-kernel-feature-expectations [] {
    for expectation in $PROGRAM_LANGUAGE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-language-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-language-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-reserved-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_RESERVED_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-reserved-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-reserved-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-value-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_VALUE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-value-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-value-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-global-kernel-feature-expectations [] {
    for expectation in $PROGRAM_GLOBAL_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-global-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-global-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-target-context-field-kernel-feature-expectations [] {
    for expectation in $TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-kernel-feature missing expected target-aware metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-field-helper-kernel-feature-expectations [] {
    for expectation in $CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-helper-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-helper-kernel-feature missing expected metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-helper-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-projection-kernel-feature-expectations [] {
    for expectation in $CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let raw_access = $expectation.raw_access
        let expected = $expectation.feature
        let actual = (context-projection-kernel-feature $raw_access $target)

        if $actual == null {
            fail $"context-projection-kernel-feature missing expected metadata for ($target) ctx.($raw_access)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-projection-kernel-feature drifted for ($target) ctx.($raw_access): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-context-field-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-context-field-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-context-field-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-surface-kernel-feature-expectations [] {
    for expectation in $PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-surface-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-surface-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-helper-kernel-feature-expectations [] {
    for expectation in $PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-helper-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-helper-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-kfunc-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-kfunc-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-detail-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let expected = $expectation.feature
        let expected_key = $expected.key
        let matches = (
            program-kfunc-kernel-features $program $target
            | where {|feature| $feature.key == $expected_key }
        )

        if ($matches | is-empty) {
            fail $"program-kfunc-kernel-features for ($target) missing expected metadata for ($expected_key)"
        }

        let actual = ($matches | first)
        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"program-kfunc-kernel-features for ($target) ($expected_key) drifted: ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-callback-btf-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-callback-btf-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-callback-btf-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-verifier-feature-expectations [] {
    validate-program-target-kernel-feature-expectations
    validate-program-language-kernel-feature-expectations
    validate-program-map-kernel-feature-expectations
    validate-program-reserved-map-kernel-feature-expectations
    validate-program-map-value-kernel-feature-expectations
    validate-program-global-kernel-feature-expectations
    validate-target-context-field-kernel-feature-expectations
    validate-context-field-helper-kernel-feature-expectations
    validate-context-projection-kernel-feature-expectations
    validate-program-context-field-kernel-feature-expectations
    validate-program-surface-kernel-feature-expectations
    validate-program-helper-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-detail-expectations
    validate-program-callback-btf-kernel-feature-expectations
}
