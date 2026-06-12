const VERIFIER_DIFF_CONTEXT_ROOTS_RUNTIME_DIR = (path self | path dirname)
source ($VERIFIER_DIFF_CONTEXT_ROOTS_RUNTIME_DIR | path join context_record_flows.nu)
source ($VERIFIER_DIFF_CONTEXT_ROOTS_RUNTIME_DIR | path join context_function_wrappers.nu)

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

def context-root-from-wrapper-invocation [invocation context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for wrapper in ($root_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
        let root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

def context-root-from-multi-param-wrapper-invocation [raw_value: string context_names bound_aliases identity_wrappers wrapper_defs] {
    let trimmed = (trim-simple-parentheses ($raw_value | str trim))
    let callee = (
        $trimmed
        | split row " "
        | first
        | str trim
    )
    if $callee == "" {
        return null
    }

    let tail = (
        $trimmed
        | str substring ($callee | str length)..
        | str trim
    )
    let args = (command-tail-positional-args $tail)
    for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $callee }) {
        let arg = ($args | get -o $wrapper.param_index)
        if $arg == null {
            continue
        }

        let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

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

source ($VERIFIER_DIFF_CONTEXT_ROOTS_RUNTIME_DIR | path join context_multi_param_functions.nu)

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

def context-root-from-record-wrapper-invocation [invocation wrapper context_names bound_aliases identity_wrappers] {
    let param_index = ($wrapper | get -o param_index)
    if $param_index == null {
        return (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
    }

    let args = (command-tail-positional-args $invocation.arg)
    let arg = ($args | get -o $param_index)
    if $arg == null {
        return null
    }

    context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers
}

def context-root-from-value-token [raw_value: string context_names bound_aliases] {
    let field_value = (trim-simple-parentheses ($raw_value | str trim))
    for context_name in $context_names {
        let context_token = (["$" $context_name] | str join "")
        if $field_value == $context_token {
            return ""
        }

        let context_prefix = $"($context_token)."
        if not ($field_value | str starts-with $context_prefix) {
            continue
        }

        let root_path = (
            normalize-context-path-token (
                $field_value | str substring ($context_prefix | str length)..
            )
        )
        let root = ($root_path | split row "." | first)
        if (context-projection-root? $root) {
            return $root_path
        }
    }

    for alias in $bound_aliases {
        let alias_token = (["$" $alias.name] | str join "")
        if $field_value == $alias_token {
            return $alias.root
        }

        let alias_prefix = $"($alias_token)."
        if not ($field_value | str starts-with $alias_prefix) {
            continue
        }

        let tail = (
            normalize-context-path-token (
                $field_value | str substring ($alias_prefix | str length)..
            )
        )
        return $"($alias.root).($tail)"
    }

    null
}

def context-root-from-get-input [input: string context_names bound_aliases] {
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let root = (context-root-from-value-token $normalized_input $context_names $bound_aliases)
    if $root != null {
        return $root
    }

    null
}

def context-root-from-argument-token [raw_value: string context_names bound_aliases identity_wrappers] {
    mut root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $root == null {
        $root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    }
    if $root == null {
        let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
        if $invocation != null and $invocation.callee in $identity_wrappers {
            $root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        }
    }

    $root
}

def combine-context-roots [base: string wrapper: string] {
    if $wrapper == "" {
        return $base
    }
    if $base == "" {
        return $wrapper
    }

    $"($base).($wrapper)"
}

def context-root-from-get-pipeline [raw: string context_names bound_aliases] {
    let trimmed = (trim-simple-parentheses ($raw | str trim))
    if (not ($trimmed | str contains "get")) or (not ($trimmed | str contains "|")) {
        return null
    }

    let segments = (split-pipeline-segments $trimmed)
    if ($segments | length) < 2 {
        return null
    }

    mut root = (
        context-root-from-value-token
            (($segments | first) | str trim)
            $context_names
            $bound_aliases
    )
    if $root == null {
        return null
    }

    mut saw_get = false
    for segment in ($segments | skip 1) {
        let parsed = (get-command-field-tail $segment)
        if $parsed == null {
            return null
        }

        let field_path = (normalize-context-path-token $parsed.field)
        if $field_path == "" {
            return null
        }
        $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
        $saw_get = true

        let tail_path = (get-segment-cell-path-tail $parsed.tail)
        if $tail_path != "" {
            $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
        }
    }

    if $saw_get { $root } else { null }
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

def strip-leading-closure-header [line: string] {
    let trimmed = ($line | str trim)
    if not ($trimmed | str starts-with "{|") {
        return $trimmed
    }

    let parts = (($trimmed | str substring 2..) | split row "|")
    if ($parts | length) < 2 {
        return $trimmed
    }

    $parts | skip 1 | str join "|" | str trim
}

def record-get-candidate-lines [source: string] {
    mut candidates = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }
        let pipeline_line = (strip-leading-closure-header $trimmed)
        if (not ($pipeline_line | str contains "get")) or (not ($pipeline_line | str contains "|")) {
            continue
        }
        if not (line-invokes-command? $pipeline_line "get") {
            continue
        }

        let segments = (split-pipeline-segments $pipeline_line)
        if ($segments | length) < 2 {
            continue
        }

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        let normalized_input = (trim-simple-parentheses $input)
        if (
            ($normalized_input | str starts-with "$")
            or ($normalized_input | str starts-with "($")
            or ($normalized_input | str starts-with "{")
            or ($normalized_input | str starts-with "({")
            or not ((two-token-invocation $normalized_input) == null)
        ) {
            $candidates = ($candidates | append $pipeline_line)
        }
    }

    $candidates
}
