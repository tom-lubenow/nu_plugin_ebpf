def simple-function-param-names [raw_params: string] {
    let parts = (
        $raw_params
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if (
        $parts
        | any {|part|
            (
                ($part | str contains ":")
                or ($part | str starts-with "-")
                or ($part | str starts-with "...")
            )
        }
    ) {
        return []
    }

    $parts
    | each {|part|
        $part
        | str replace --all "," ""
        | str replace --all "?" ""
        | split row ":"
        | first
        | str trim
    }
    | where {|name| $name != "" and not ($name | str starts-with "-") }
}

def positional-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_params = []
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                let params = (simple-function-param-names $parsed.params)
                if not ($params | is-empty) {
                    $functions = ($functions | append {
                        name: $parsed.name
                        params: $params
                        body: [$parsed.body]
                    })
                }
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                let params = (simple-function-param-names $parsed.params)
                if ($params | is-empty) {
                    continue
                }
                $in_function = true
                $current_name = $parsed.name
                $current_params = $params
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                params: $current_params
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_params = []
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def multi-param-context-root-wrapper-definitions [source: string] {
    mut wrappers = []

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        let return_lines = (
            $function.body
            | each {|line| $line | str trim }
            | where {|line|
                (
                    $line != ""
                    and not ($line | str starts-with "#")
                    and not ($line | str contains "=")
                )
            }
        )
        if ($return_lines | is-empty) {
            continue
        }

        let returned = ($return_lines | last)
        for param in ($function.params | enumerate) {
            mut root = (context-root-from-get-pipeline $returned [$param.item] [])
            if $root == null {
                $root = (context-root-from-value-token $returned [$param.item] [])
            }
            if $root == null {
                continue
            }
            let final_root = $root
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.param_index == $param.index
                        and (($wrapper | get -o root | default "") == $final_root)
                    )
                }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                param_index: $param.index
                root: $final_root
            })
        }
    }

    $wrappers
}

def multi-param-record-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for line in $function.body {
            let trimmed = ($line | str trim)
            if $trimmed == "" or ($trimmed | str starts-with "#") {
                continue
            }

            for param in ($function.params | enumerate) {
                for field in (record-literal-context-fields $trimmed [$param.item] [] $identity_wrappers $root_wrapper_defs) {
                    if (
                        $wrappers
                        | any {|wrapper|
                            (
                                $wrapper.name == $function.name
                                and $wrapper.field == $field.field
                                and $wrapper.param_index == $param.index
                                and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                            )
                        }
                    ) {
                        continue
                    }

                    $wrappers = ($wrappers | append {
                        name: $function.name
                        field: $field.field
                        param_index: $param.index
                        root: ($field | get -o root | default "")
                    })
                }
            }
        }
    }

    $wrappers
}

def multi-param-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for param in ($function.params | enumerate) {
            let aliases = (
                function-context-root-aliases
                    $function.body
                    $param.item
                    $identity_wrappers
                    $root_wrapper_defs
            )
            let roots = ([{ name: $param.item root: "" }] | append $aliases)
            for line in $function.body {
                for root_info in $roots {
                    let prefix = $"$($root_info.name)."
                    for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                        let root_path = ($root_info | get -o root | default "")
                        let raw_access = if $root_path == "" {
                            $raw_tail
                        } else {
                            $"($root_path).($raw_tail)"
                        }
                        let field = (normalize-context-field-token $raw_access)
                        if $field == "" {
                            continue
                        }
                        if (
                            $accesses
                            | any {|access|
                                (
                                    $access.name == $function.name
                                    and $access.param_index == $param.index
                                    and $access.raw_access == $raw_access
                                )
                            }
                        ) {
                            continue
                        }
                        $accesses = ($accesses | append {
                            name: $function.name
                            param_index: $param.index
                            raw_access: $raw_access
                        })
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
                            $root = (context-root-from-get-input $input [$param.item] $aliases)
                            if $root == null {
                                continue
                            }
                        }

                        let field_path = (normalize-context-path-token $parsed.field)
                        if $field_path != "" {
                            let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }

                        let tail_path = (get-segment-cell-path-tail $parsed.tail)
                        if $tail_path != "" {
                            let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }
                    }
                }
            }
        }
    }

    $accesses
}
