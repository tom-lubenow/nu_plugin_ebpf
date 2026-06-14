def context-root-from-record-value-token [raw_value: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let direct_root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    if $direct_root != null {
        return $direct_root
    }

    let get_root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $get_root != null {
        return $get_root
    }

    let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
    if $invocation != null and $invocation.callee in $identity_wrappers {
        let root = (context-root-from-get-pipeline $invocation.arg $context_names $bound_aliases)
        if $root != null {
            return $root
        }

        return (context-root-from-value-token $invocation.arg $context_names $bound_aliases)
    }
    if $invocation != null {
        return (
            context-root-from-wrapper-invocation
                $invocation
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
    }

    null
}

def record-literal-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    let inner = ($trimmed | str substring 1..-2)
    mut fields = []
    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?|\(?[A-Za-z_][A-Za-z0-9_-]*\s+\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\([^)]*\|\s*get\s+[^)]*\))'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?[A-Za-z_][A-Za-z0-9_-]*\s+\([^)]*\|\s*get\s+[^)]*\)\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    $fields
}
