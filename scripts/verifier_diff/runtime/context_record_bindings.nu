def record-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let order = (record-literal-field-names $rhs)
        for field in (
            record-literal-context-fields
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: $field.root
                order: $order
            })
        }
    }

    $bindings
}

def record-wrapper-definitions [source: string] {
    mut wrappers = []

    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\{\s*(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\s*\}\s*$'
        ) {
            if $parsed.param != $parsed.value {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $parsed.name and $wrapper.field == $parsed.field }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $parsed.name
                field: $parsed.field
            })
        }
    }

    $wrappers
}

def record-wrapper-context-bindings [line: string context_names bound_aliases identity_wrappers wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let invocation = (two-token-invocation $rhs)
        if $invocation == null {
            continue
        }

        for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
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
            let wrapper_root = ($wrapper | get -o root | default "")
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $wrapper.field
                root: (combine-context-roots $root $wrapper_root)
            })
        }
    }

    $bindings
}
