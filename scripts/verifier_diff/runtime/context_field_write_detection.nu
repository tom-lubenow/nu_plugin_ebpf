def context-field-access-is-assignment-lhs? [raw_access: string field: string] {
    let compact = ($raw_access | str trim | str replace --all " " "")
    if not ($compact | str contains "=") {
        return false
    }
    let parts = ($compact | split row "=")
    if ($parts | length) < 2 {
        return false
    }

    let rhs_after_first_equals = ($parts | skip 1 | first)
    if $rhs_after_first_equals == "" {
        return false
    }

    let lhs = ($parts | first)

    ($lhs == $field) or ($lhs | str starts-with $"($field).")
}

def line-assigns-context-field? [line: string context_names fields] {
    let trimmed = ($line | str trim)
    for context_name in $context_names {
        for field in $fields {
            let marker = $"$($context_name).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def line-assigns-record-context-field? [line: string aliases fields roots] {
    let trimmed = ($line | str trim)
    for alias in $aliases {
        let root = ($alias | get -o root | default "")
        if $root not-in $roots {
            continue
        }

        for field in $fields {
            let marker = $"$($alias.name).($alias.field).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}
