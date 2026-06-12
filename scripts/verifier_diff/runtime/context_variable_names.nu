def context-variable-binding [line: string context_names identity_wrappers] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        for context_name in $context_names {
            if $rhs == $"$($context_name)" {
                return $assignment.name
            }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                for context_name in $context_names {
                    if $invocation.arg == $"$($context_name)" {
                        return $assignment.name
                    }
                }
            }
        }
    }

    null
}

def source-may-bind-derived-context-variable? [source: string] {
    (
        ($source | str contains "def ")
        or ($source | str contains " get ")
        or ($source | str contains "| get")
        or (($source | str contains "= $") and ($source | str contains "."))
        or (($source | str contains "= ($") and ($source | str contains "."))
    )
}

def program-context-variable-names [source: string] {
    mut names = ["ctx"]
    mut found_closure = false
    let identity_wrappers = if ($source | str contains "def ") {
        identity-wrapper-definitions $source
    } else {
        []
    }

    for line in ($source | lines) {
        if $found_closure {
            continue
        }

        let parts = ($line | split row "{|")
        if ($parts | length) <= 1 {
            continue
        }

        let raw_closure = ($parts | skip 1 | first)
        let closure_parts = ($raw_closure | split row "|")
        if ($closure_parts | length) == 0 {
            continue
        }

        let raw_params = ($closure_parts | first)
        for raw_param in ($raw_params | split row ",") {
            let name = (
                $raw_param
                | str trim
                | split row ":"
                | first
                | str trim
                | split row " "
                | first
                | str trim
            )
            $names = (append-unique-name $names $name)
        }
        $found_closure = true
    }

    let may_bind_direct_context = (
        ($source | str contains "= $")
        or (($source | str contains "= (") and ($source | str contains "$"))
    )
    if $may_bind_direct_context {
        for line in ($source | lines) {
            let binding = (context-variable-binding $line $names $identity_wrappers)
            if $binding != null {
                $names = (append-unique-name $names $binding)
            }
        }
    }

    if $may_bind_direct_context {
        for alias in (program-bound-context-root-aliases-base $source $names) {
            if (($alias | get -o root | default "") == "") {
                $names = (append-unique-name $names $alias.name)
            }
        }
    }

    $names
}

def program-bound-context-root-aliases-base [source: string context_names] {
    mut aliases = []
    let source_has_defs = ($source | str contains "def ")
    let identity_wrappers = if $source_has_defs { identity-wrapper-definitions $source } else { [] }
    let root_wrapper_defs = if $source_has_defs { context-root-wrapper-definitions $source } else { [] }
    let multi_param_root_wrapper_defs = if $source_has_defs { multi-param-context-root-wrapper-definitions $source } else { [] }

    for line in ($source | lines) {
        let binding = (
            context-root-binding
                $line
                $context_names
                $aliases
                $identity_wrappers
                $root_wrapper_defs
                $multi_param_root_wrapper_defs
        )
        if $binding == null {
            continue
        }

        let existing = ($aliases | where {|alias| $alias.name == $binding.name })
        if ($existing | is-empty) {
            $aliases = ($aliases | append $binding)
        } else {
            $aliases = (
                $aliases
                | each {|alias|
                    if $alias.name == $binding.name { $binding } else { $alias }
                }
            )
        }
    }

    $aliases
}
