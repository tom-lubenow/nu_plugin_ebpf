def multi-param-user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (multi-param-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let args = (command-tail-positional-args $raw_tail)
                let arg = ($args | get -o $access.param_index)
                if $arg == null {
                    continue
                }

                let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def context-access-kernel-features [raw_access: string target] {
    mut features = []
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $features
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        $features = (append-missing-kernel-features $features [$feature])
    }
    let tracepoint_feature = (tracepoint-payload-field-kernel-feature $field $target)
    if $tracepoint_feature != null {
        $features = (append-missing-kernel-features $features [$tracepoint_feature])
    }
    if not (context-field-access-is-assignment-lhs? $raw_access $field) {
        let helper_feature = (context-field-helper-kernel-feature $field $target)
        if $helper_feature != null {
            $features = (append-missing-kernel-features $features [$helper_feature])
        }
    }
    let projection_feature = (context-projection-kernel-feature $raw_access $target)
    if $projection_feature != null {
        $features = (append-missing-kernel-features $features [$projection_feature])
    }
    let read_feature = (context-projection-kernel-read-feature $raw_access $target)
    if $read_feature != null {
        $features = (append-missing-kernel-features $features [$read_feature])
    }
    let task_pt_regs_feature = (context-task-pt-regs-kernel-feature $raw_access)
    if $task_pt_regs_feature != null {
        $features = (append-missing-kernel-features $features [$task_pt_regs_feature])
    }

    $features
}

def user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (user-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let arg = (normalize-context-path-token $raw_tail)
                let root = (context-root-from-value-token $arg $context_names $bound_aliases)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def program-record-context-aliases [source: string context_names] {
    mut aliases = []
    let bound_aliases = (program-bound-context-root-aliases-base $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    mut changed = true
    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let bindings = (
                (record-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line $context_names $bound_aliases $identity_wrappers $wrapper_defs)
                | append (record-upsert-context-bindings $line $context_names $bound_aliases)
                | append (record-pipeline-flow-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs $aliases)
                | append (record-spread-context-bindings $line $aliases)
            )
            for binding in $bindings {
                let existing = (
                    $aliases
                    | where {|alias|
                        (
                            $alias.name == $binding.name
                            and $alias.field == $binding.field
                            and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                        )
                    }
                )
                if ($existing | is-empty) {
                    $aliases = ($aliases | append $binding)
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def source-has-non-context-record-projection? [source: string context_names] {
    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.[A-Za-z_][A-Za-z0-9_-]*\.'
        ) {
            if $parsed.name not-in $context_names {
                return true
            }
        }
    }

    false
}

def program-bound-context-root-aliases [source: string context_names] {
    mut aliases = (program-bound-context-root-aliases-base $source $context_names)
    let may_extract_from_record = (
        (source-has-non-context-record-projection? $source $context_names)
        or (($source | str contains "get") and ($source | str contains "|"))
    )
    if not $may_extract_from_record {
        return $aliases
    }

    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let binding = (
                context-root-record-extraction-binding
                    $line
                    $record_aliases
                    $record_wrapper_defs
                    $context_names
                    $aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $binding == null {
                continue
            }

            let existing = ($aliases | where {|alias| $alias.name == $binding.name })
            if ($existing | is-empty) {
                $aliases = ($aliases | append $binding)
                $changed = true
            } else {
                let current = ($existing | first)
                if (($current | get -o root | default "") != ($binding | get -o root | default "")) {
                    $aliases = (
                        $aliases
                        | each {|alias|
                            if $alias.name == $binding.name { $binding } else { $alias }
                        }
                    )
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def record-context-projection-kernel-features [source: string target context_names] {
    if (
        not ($source | str contains "let")
        and not ($source | str contains "mut")
        and not ($source | str contains "def ")
    ) {
        return []
    }
    if not (source-has-non-context-record-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-record-context-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name).($alias.field)."
            let root = ($alias | get -o root | default "")
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root == "" {
                    $raw_tail
                } else {
                    $"($root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def context-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                continue
            }

            if $root == null {
                $root = (context-root-from-get-input $input $context_names $bound_aliases)
                if $root == null {
                    continue
                }
            }

            let field_path = (normalize-context-path-token $parsed.field)
            if $field_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $field_path $target)
                )
                $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def context-access-kernel-features-from-root-path [root path: string target] {
    let normalized_path = (normalize-context-path-token $path)
    let raw_access = if $normalized_path == "" {
        $root
    } else if $root == "" {
        $normalized_path
    } else {
        $"($root).($normalized_path)"
    }
    if $raw_access == "" {
        return []
    }

    context-access-kernel-features $raw_access $target
}

def record-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let may_carry_record_context = (
        ($source | str contains ": $")
        or ($source | str contains ": ($")
        or ($source | str contains "def ")
        or ($source | str contains "| insert")
        or ($source | str contains "| update")
        or ($source | str contains "| upsert")
        or ($source | str contains "| merge")
        or ($source | str contains "| rename")
        or ($source | str contains "| default")
        or ($source | str contains "| select")
        or ($source | str contains "| reject")
    )
    if not $may_carry_record_context {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if $root == null {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            if $root == null {
                $root = (
                    context-root-from-record-get
                        $input
                        $parsed.field
                        $record_aliases
                        $record_wrapper_defs
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root == null {
                    $root = (
                        context-root-from-record-pipeline-get
                            $input
                            $prefix_segments
                            $parsed.field
                            $record_aliases
                            $context_names
                            $bound_aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
                if $root == null {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root "" $target)
                )
            } else {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $parsed.field $target)
                )
                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
                }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def source-has-context-root-projection? [source: string context_names] {
    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_tail in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let root = (normalize-context-field-token $raw_tail)
                if (context-projection-root? $root) {
                    return true
                }
            }
        }
    }

    if ($source | str contains "get") and ($source | str contains "|") {
        let aliases = (program-bound-context-root-aliases-base $source $context_names)
        if not ($aliases | is-empty) {
            return true
        }

        for line in (record-get-candidate-lines $source) {
            let segments = (split-pipeline-segments ($line | str trim))
            if ($segments | length) < 2 {
                continue
            }

            mut input = (($segments | first) | str trim)
            if ($input | str contains "=") {
                $input = (($input | split row "=" | last) | str trim)
            }
            if (context-root-from-get-input $input $context_names $aliases) != null {
                return true
            }
        }
    }

    if ($source | str contains "def ") {
        let root_wrappers = (context-root-wrapper-definitions $source)
        if not ($root_wrappers | is-empty) {
            return true
        }
    }

    false
}

def bound-context-projection-kernel-features [source: string target context_names] {
    if not ($source | str contains "let") and not ($source | str contains "mut") {
        return []
    }
    let has_get_pipeline = (($source | str contains "get") and ($source | str contains "|"))
    if not $has_get_pipeline and not (source-has-non-context-record-projection? $source $context_names) {
        return []
    }
    if not (source-has-context-root-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-bound-context-root-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $alias.root == "" {
                    $raw_tail
                } else {
                    $"($alias.root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}
