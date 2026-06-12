def identity-wrapper-definitions [source: string] {
    mut identities = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<callee>[A-Za-z_][A-Za-z0-9_-]*)\s+\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.callee not-in $identities {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }
        }
    }

    $identities
}

def function-record-context-aliases [body param: string identity_wrappers root_wrapper_defs root_aliases] {
    mut aliases = []

    for line in $body {
        let bindings = (
            (record-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs)
            | append (record-upsert-context-bindings $line [$param] $root_aliases)
            | append (record-pipeline-flow-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            | append (record-spread-context-bindings $line $aliases)
        )
        for binding in $bindings {
            if (
                $aliases
                | any {|alias|
                    (
                        $alias.name == $binding.name
                        and $alias.field == $binding.field
                        and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $aliases = ($aliases | append $binding)
        }
    }

    $aliases
}

def context-root-from-returned-record-get-pipeline [returned: string record_aliases param: string root_aliases identity_wrappers root_wrapper_defs] {
    let segments = (split-pipeline-segments $returned)
    if ($segments | length) < 2 {
        return null
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
                []
                [$param]
                $root_aliases
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
                    [$param]
                    $root_aliases
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
        return ($roots | first)
    }

    null
}

def function-return-context-root [function identity_wrappers root_wrapper_defs] {
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let record_aliases = (
        function-record-context-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
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
        return null
    }

    let returned = ($return_lines | last)
    if ($returned | str contains "|") {
        let root = (context-root-from-get-pipeline $returned [$param] $aliases)
        if $root != null {
            return $root
        }

        let record_root = (
            context-root-from-returned-record-get-pipeline
                $returned
                $record_aliases
                $param
                $aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $record_root != null {
            return $record_root
        }

        return null
    }

    mut root = (context-root-from-value-token $returned [$param] $aliases)
    if $root != null {
        return $root
    }

    let invocation = (two-token-invocation $returned)
    if $invocation == null {
        return null
    }

    if $invocation.callee in $identity_wrappers {
        $root = (context-root-from-get-pipeline $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }

        $root = (context-root-from-value-token $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }
    }

    context-root-from-wrapper-invocation $invocation [$param] $aliases $identity_wrappers $root_wrapper_defs
}

def context-root-wrapper-definitions [source: string] {
    let identity_wrappers = (identity-wrapper-definitions $source)
    mut wrappers = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for function in (one-param-user-functions $source) {
            let root = (function-return-context-root $function $identity_wrappers $wrappers)
            if $root == null {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $function.name and (($wrapper | get -o root | default "") == $root) }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                root: $root
            })
            $changed = true
        }
    }

    $wrappers
}

def one-param-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_param = ""
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                $functions = ($functions | append {
                    name: $parsed.name
                    param: $parsed.param
                    body: [$parsed.body]
                })
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                $in_function = true
                $current_name = $parsed.name
                $current_param = $parsed.param
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                param: $current_param
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_param = ""
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def upsert-context-root-alias [aliases name: string root: string] {
    if ($aliases | any {|alias| $alias.name == $name }) {
        $aliases | each {|alias|
            if $alias.name == $name {
                { name: $name root: $root }
            } else {
                $alias
            }
        }
    } else {
        $aliases | append { name: $name root: $root }
    }
}

def function-context-root-aliases [body param: string identity_wrappers root_wrapper_defs] {
    mut aliases = []

    for line in $body {
        for assignment in (declaration-assignments $line) {
            let rhs = (declaration-rhs-token $assignment)
            mut root = (context-root-from-argument-token $rhs [$param] $aliases $identity_wrappers)
            if $root == null {
                let invocation = (two-token-invocation $rhs)
                if $invocation != null {
                    $root = (
                        context-root-from-wrapper-invocation
                            $invocation
                            [$param]
                            $aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
            }

            if $root != null {
                $aliases = (upsert-context-root-alias $aliases $assignment.name $root)
            }
        }
    }

    $aliases
}
