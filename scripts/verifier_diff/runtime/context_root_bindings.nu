def context-root-binding [line: string context_names bound_aliases identity_wrappers root_wrapper_defs multi_param_root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let direct_root = (context-root-from-value-token $rhs $context_names $bound_aliases)
        if $direct_root != null and $direct_root != "" {
            return { name: $assignment.name root: $direct_root }
        }

        let get_root = (context-root-from-get-pipeline $rhs $context_names $bound_aliases)
        if $get_root != null and $get_root != "" {
            return { name: $assignment.name root: $get_root }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                let root_path = (
                    context-root-from-record-value-token
                        $invocation.arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root_path != null and $root_path != "" {
                    return { name: $assignment.name root: $root_path }
                }
            }

            let wrapper_root = (
                context-root-from-wrapper-invocation
                    $invocation
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $wrapper_root != null {
                return { name: $assignment.name root: $wrapper_root }
            }
        }

        let multi_param_wrapper_root = (
            context-root-from-multi-param-wrapper-invocation
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $multi_param_root_wrapper_defs
        )
        if $multi_param_wrapper_root != null {
            return { name: $assignment.name root: $multi_param_wrapper_root }
        }

        for context_name in $context_names {
            let prefix = $"$($context_name)."
            if not ($rhs | str starts-with $prefix) {
                continue
            }

            let root_path = (normalize-context-path-token ($rhs | str substring ($prefix | str length)..))
            let root = ($root_path | split row "." | first)
            if (context-projection-root? $root) {
                return { name: $assignment.name root: $root_path }
            }
        }
    }

    null
}

def context-root-record-extraction-binding [line: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)

        for parsed in (
            $rhs
            | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)$'
        ) {
            for alias in (
                $record_aliases
                | where {|alias| $alias.name == $parsed.record and $alias.field == $parsed.field }
            ) {
                return {
                    name: $assignment.name
                    root: ($alias | get -o root | default "")
                }
            }
        }

        let segments = (split-pipeline-segments $rhs)
        if ($segments | length) < 2 {
            continue
        }
        let input = (($segments | first) | str trim)
        mut roots = []
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if ($roots | is-empty) {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            mut root = (
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

            $roots = ($roots | append $root)
        }

        if ($roots | length) == 1 {
            return {
                name: $assignment.name
                root: ($roots | first)
            }
        }
    }

    null
}

def context-root-from-record-get [input: string get_field: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let field_name = (normalize-context-path-token $get_field)
    if $field_name == "" {
        return null
    }
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let variable_input = (
        $normalized_input
        | str replace --all "(" ""
        | str replace --all ")" ""
        | str trim
    )

    for parsed in (
        $variable_input
        | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in (
            $record_aliases
            | where {|alias| $alias.name == $parsed.record and $alias.field == $field_name }
        ) {
            return ($alias | get -o root | default "")
        }
    }

    let invocation = (two-token-invocation $normalized_input)
    if $invocation != null {
        for wrapper in (
            $record_wrapper_defs
            | where {|wrapper| $wrapper.name == $invocation.callee and $wrapper.field == $field_name }
        ) {
            let root = (
                context-root-from-record-wrapper-invocation
                    $invocation
                    $wrapper
                    $context_names
                    $bound_aliases
                    $identity_wrappers
            )
            if $root == null {
                continue
            }
            return (combine-context-roots $root ($wrapper | get -o root | default ""))
        }
    }

    for field in (
        record-literal-context-fields
            $normalized_input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    for field in (record-literal-spread-context-fields $normalized_input $record_aliases) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}

def context-root-from-record-pipeline-get [input: string prefix_segments get_field: string record_aliases context_names bound_aliases identity_wrappers root_wrapper_defs] {
    if ($prefix_segments | is-empty) {
        return null
    }

    let raw = (
        [$input]
        | append $prefix_segments
        | str join " | "
    )
    let field_name = (normalize-context-path-token $get_field)
    for field in (
        record-pipeline-flow-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $record_aliases
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}
