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
