def record-context-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let base_wrapper_defs = (record-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        mut aliases = []
        mut returned_names = []
        let root_aliases = (
            function-context-root-aliases
                $function.body
                $function.param
                $identity_wrappers
                $root_wrapper_defs
        )

        for line in $function.body {
            let trimmed = ($line | str trim)
            let bindings = (
                (record-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line [$function.param] $root_aliases $identity_wrappers $base_wrapper_defs)
                | append (record-upsert-context-bindings $line [$function.param] $root_aliases)
                | append (record-pipeline-flow-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
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
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*$'
            ) {
                $returned_names = ($returned_names | append $parsed.name)
            }

            mut returned_fields = (
                (record-literal-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-literal-spread-context-fields $trimmed $aliases)
                | append (record-pipeline-flow-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            )
            let invocation = (two-token-invocation $trimmed)
            if $invocation != null {
                for wrapper in ($base_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
                    let root = (context-root-from-value-token $invocation.arg [$function.param] $root_aliases)
                    if $root == null {
                        continue
                    }
                    $returned_fields = ($returned_fields | append {
                        field: $wrapper.field
                        root: (combine-context-roots $root ($wrapper | get -o root | default ""))
                    })
                }
            }
            for field in $returned_fields {
                if (
                    $wrappers
                    | any {|wrapper|
                        (
                            $wrapper.name == $function.name
                            and $wrapper.field == $field.field
                            and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                        )
                    }
                ) {
                    continue
                }
                $wrappers = ($wrappers | append {
                    name: $function.name
                    field: $field.field
                    root: ($field | get -o root | default "")
                })
            }
        }

        for alias in $aliases {
            if $alias.name not-in $returned_names {
                continue
            }
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.field == $alias.field
                        and (($wrapper | get -o root | default "") == ($alias | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $function.name
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $wrappers
}

def append-function-context-field-access [accesses function_name: string raw_access: string] {
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $accesses
    }
    if (
        $accesses
        | any {|access| $access.name == $function_name and $access.raw_access == $raw_access }
    ) {
        return $accesses
    }

    $accesses | append {
        name: $function_name
        raw_access: $raw_access
    }
}

def function-context-field-accesses [function identity_wrappers root_wrapper_defs] {
    mut accesses = []
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let roots = ([{ name: $param root: "" }] | append $aliases)

    for line in $function.body {
        for root in $roots {
            let prefix = $"$($root.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root.root == "" {
                    $raw_tail
                } else {
                    $"($root.root).($raw_tail)"
                }
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }
                $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
            }
        }

        for candidate in (record-get-candidate-lines $line) {
            let segments = (split-pipeline-segments ($candidate | str trim))
            if ($segments | length) < 2 {
                continue
            }

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
                    $root = (context-root-from-get-input $input [$param] $aliases)
                    if $root == null {
                        continue
                    }
                }

                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }

                let tail_path = (get-segment-cell-path-tail $parsed.tail)
                if $tail_path != "" {
                    let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }
            }
        }
    }

    $accesses
}

def user-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        $accesses = (
            $accesses
            | append (function-context-field-accesses $function $identity_wrappers $root_wrapper_defs)
        )
    }

    $accesses
}
