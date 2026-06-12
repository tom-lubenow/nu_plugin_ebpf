const VERIFIER_DIFF_CONTEXT_ROOTS_RUNTIME_DIR = (path self | path dirname)

def append-unique-name [names name: string] {
    if $name == "" or $name in $names {
        $names
    } else {
        $names | append $name
    }
}
def trim-simple-parentheses [text: string] {
    mut value = ($text | str trim)

    loop {
        if ($value | str length) < 2 {
            break
        }
        if not (($value | str starts-with "(") and ($value | str ends-with ")")) {
            break
        }

        $value = ($value | str substring 1..-2 | str trim)
    }

    $value
}

def split-pipeline-segments [raw: string] {
    let text = (trim-simple-parentheses ($raw | str trim))
    mut segments = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        if (
            $ch == "|"
            and (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        ) {
            $segments = ($segments | append ($current | str trim))
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" {
                if $paren_depth > 0 {
                    $paren_depth = $paren_depth - 1
                }
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" {
                if $brace_depth > 0 {
                    $brace_depth = $brace_depth - 1
                }
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" {
                if $bracket_depth > 0 {
                    $bracket_depth = $bracket_depth - 1
                }
            }
        }

        $current = $"($current)($ch)"
    }

    $segments | append ($current | str trim)
}

def declaration-binding-name [raw_name: string] {
    $raw_name
    | str trim
    | split row ":"
    | first
    | str trim
    | split row " "
    | first
    | str trim
}

def declaration-assignment-from-body [body: string] {
    let assignment_parts = ($body | split row "=")
    if ($assignment_parts | length) < 2 {
        return null
    }

    let name = (declaration-binding-name ($assignment_parts | first))
    if $name == "" {
        return null
    }

    {
        name: $name
        rhs: ($assignment_parts | skip 1 | str join "=" | str trim)
    }
}

def declaration-assignments [line: string] {
    let trimmed = ($line | str trim)
    mut assignments = []

    for command in ["let" "mut"] {
        for tail in (command-invocation-tails $trimmed $command) {
            let assignment = (declaration-assignment-from-body ($tail | str trim))
            if $assignment != null {
                $assignments = ($assignments | append $assignment)
            }
        }
    }

    $assignments
}

def declaration-assignment [line: string] {
    declaration-assignments $line | first
}

def declaration-rhs-token [assignment] {
    trim-simple-parentheses (($assignment.rhs | split row ";" | first) | str trim)
}

def two-token-invocation [raw: string] {
    let tokens = (
        $raw
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($tokens | length) < 2 {
        return null
    }

    {
        callee: ($tokens | get 0)
        arg: (trim-simple-parentheses ($tokens | skip 1 | str join " "))
    }
}

def command-tail-positional-args [raw_tail: string] {
    let text = ($raw_tail | str trim)
    if $text == "" {
        return []
    }

    mut args = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        let at_top = (
            (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        )
        if $at_top and $ch == ";" {
            break
        }
        if $at_top and ($ch == " " or $ch == "\t") {
            let arg = ($current | str trim)
            if $arg != "" {
                $args = ($args | append $arg)
            }
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" and $paren_depth > 0 {
                $paren_depth = $paren_depth - 1
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" and $brace_depth > 0 {
                $brace_depth = $brace_depth - 1
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" and $bracket_depth > 0 {
                $bracket_depth = $bracket_depth - 1
            }
        }

        $current = $"($current)($ch)"
    }

    let arg = ($current | str trim)
    if $arg != "" {
        $args = ($args | append $arg)
    }

    $args
}

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

def record-upsert-context-bindings [line: string context_names bound_aliases] {
    mut bindings = []

    for parsed in (
        $line
        | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?)'
    ) {
        let root = (context-root-from-value-token $parsed.value $context_names $bound_aliases)
        if $root != null {
            $bindings = ($bindings | append {
                name: $parsed.name
                field: $parsed.field
                root: $root
            })
        }
    }

    $bindings
}

def record-command-field-value [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s+(?P<value>.+)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let result = ($parsed | first)
    {
        field: ($result.field | str trim)
        value: ($result.value | str trim)
    }
}

def record-default-field-value [tail: string] {
    let parts = (
        $tail
        | str trim
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($parts | length) < 2 {
        return null
    }

    let field = (normalize-context-path-token ($parts | last))
    let value = (
        $parts
        | first (($parts | length) - 1)
        | str join " "
        | str trim
    )
    if $field == "" or $value == "" {
        return null
    }

    {
        field: $field
        value: $value
    }
}

def record-pipeline-input-token [raw: string] {
    let input = (
        split-pipeline-segments $raw
        | first
        | str trim
    )
    trim-simple-parentheses $input
}

def unique-record-context-fields [fields] {
    mut unique = []

    for field in $fields {
        if (
            $unique
            | any {|existing|
                (
                    $existing.field == $field.field
                    and (($existing | get -o root | default "") == ($field | get -o root | default ""))
                )
            }
        ) {
            continue
        }
        $unique = ($unique | append {
            field: $field.field
            root: ($field | get -o root | default "")
        })
    }

    $unique
}

def record-literal-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-literal-spread-field-names [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            if $alias.field not-in $names {
                $names = ($names | append $alias.field)
            }
        }
    }

    $names
}

def record-literal-null-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*null(?:\s|,|$)'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-field-name-list [raw: string] {
    mut names = []

    for token in (
        $raw
        | str trim
        | split row " "
        | each {|part| normalize-context-path-token $part }
        | where {|part| $part != "" }
    ) {
        let name = ($token | split row "." | first)
        if $name != "" and $name not-in $names {
            $names = ($names | append $name)
        }
    }

    $names
}

def record-literal-argument [raw: string] {
    let parsed = (
        $raw
        | str trim
        | parse --regex '^(?P<record>\{.*\})\s*\)*$'
    )
    if ($parsed | is-empty) {
        return null
    }

    ($parsed | first).record
}

def record-pipeline-input-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let input = (record-pipeline-input-token $raw)
    mut fields = (
        record-literal-context-fields
            $input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    )
    $fields = (
        $fields
        | append (record-literal-spread-context-fields $input $aliases)
    )

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-input-field-order [raw: string aliases] {
    let input = (record-pipeline-input-token $raw)
    let literal_order = (record-literal-field-names $input)
    let spread_order = (record-literal-spread-field-names $input $aliases)

    if ($spread_order | is-empty) and not ($literal_order | is-empty) {
        return $literal_order
    }
    if ($literal_order | is-empty) and not ($spread_order | is-empty) {
        return $spread_order
    }

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            let order = ($alias | get -o order | default [])
            if not ($order | is-empty) {
                return $order
            }
        }
    }

    null
}

def record-pipeline-input-null-fields [raw: string] {
    let input = (record-pipeline-input-token $raw)
    let literal_nulls = (record-literal-null-field-names $input)
    if not ($literal_nulls | is-empty) {
        return $literal_nulls
    }

    []
}

def remove-record-context-field [fields field_name: string] {
    $fields | where {|field| $field.field != $field_name }
}

def remove-field-name [fields field_name: string] {
    $fields | where {|field| $field != $field_name }
}

def append-field-name [fields field_name: string] {
    if $field_name in $fields {
        return $fields
    }

    $fields | append $field_name
}

def value-token-null? [raw: string] {
    (normalize-context-path-token (trim-simple-parentheses ($raw | str trim))) == "null"
}

def append-record-context-field [fields field_name: string root: string] {
    unique-record-context-fields (
        $fields
        | append {
            field: $field_name
            root: $root
        }
    )
}

def replace-record-context-field [fields field_name: string root] {
    mut next = (remove-record-context-field $fields $field_name)
    if $root != null {
        $next = (append-record-context-field $next $field_name $root)
    }

    $next
}

def has-record-context-field? [fields field_name: string] {
    $fields | any {|field| $field.field == $field_name }
}

def record-field-index [order field_name: string] {
    if $order == null {
        return null
    }

    for entry in ($order | enumerate) {
        if $entry.item == $field_name {
            return $entry.index
        }
    }

    null
}

def record-field-name-at-index [names index: int fallback: string] {
    if $index < ($names | length) {
        return ($names | get $index)
    }

    $fallback
}

def rename-record-context-fields [fields order rename_names] {
    if $order == null {
        return $fields
    }

    mut renamed = []
    for field in $fields {
        let index = (record-field-index $order $field.field)
        let next_name = if $index == null {
            $field.field
        } else {
            record-field-name-at-index $rename_names $index $field.field
        }
        $renamed = ($renamed | append {
            field: $next_name
            root: ($field | get -o root | default "")
        })
    }

    unique-record-context-fields $renamed
}

def rename-record-field-order [order rename_names] {
    if $order == null {
        return null
    }

    mut renamed = []
    for field in ($order | enumerate) {
        let next_name = (record-field-name-at-index $rename_names $field.index $field.item)
        $renamed = ($renamed | append $next_name)
    }

    $renamed
}

def merge-record-field-order [order merge_fields] {
    if $order == null {
        return null
    }

    mut next = $order
    for field in $merge_fields {
        if $field not-in $next {
            $next = ($next | append $field)
        }
    }

    $next
}

def upsert-record-field-order [order field_name: string] {
    if $order == null {
        return null
    }
    if $field_name in $order {
        return $order
    }

    $order | append $field_name
}

def record-pipeline-flow-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let parts = (split-pipeline-segments $raw)
    if ($parts | length) <= 1 {
        return []
    }

    mut fields = (
        record-pipeline-input-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    mut field_order = (record-pipeline-input-field-order $raw $aliases)
    mut null_fields = (record-pipeline-input-null-fields $raw)

    for segment in ($parts | skip 1) {
        let trimmed = ($segment | str trim)

        for command in [insert update upsert] {
            if not (($trimmed == $command) or ($trimmed | str starts-with $"($command) ")) {
                continue
            }

            let tail = ($trimmed | str substring ($command | str length).. | str trim)
            let field_value = (record-command-field-value $tail)
            if $field_value == null {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }

        if ($trimmed | str starts-with "merge ") {
            let merge_arg = (record-literal-argument ($trimmed | str substring 5.. | str trim))
            if $merge_arg == null {
                continue
            }

            let merge_fields = (record-literal-field-names $merge_arg)
            for field in $merge_fields {
                $fields = (remove-record-context-field $fields $field)
                $null_fields = (remove-field-name $null_fields $field)
            }
            $fields = (unique-record-context-fields (
                $fields
                | append (
                    record-literal-context-fields
                        $merge_arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            ))
            for field in (record-literal-null-field-names $merge_arg) {
                $null_fields = (append-field-name $null_fields $field)
            }
            $field_order = (merge-record-field-order $field_order $merge_fields)
        }

        if ($trimmed | str starts-with "select ") {
            let selected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field in $selected })
            $field_order = $selected
            $null_fields = ($null_fields | where {|field| $field in $selected })
        }

        if ($trimmed | str starts-with "reject ") {
            let rejected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field not-in $rejected })
            $null_fields = ($null_fields | where {|field| $field not-in $rejected })
            if $field_order != null {
                $field_order = ($field_order | where {|field| $field not-in $rejected })
            }
        }

        if ($trimmed | str starts-with "rename ") {
            let rename_names = (record-field-name-list ($trimmed | str substring 6..))
            $fields = (rename-record-context-fields $fields $field_order $rename_names)
            $null_fields = (rename-record-field-order $null_fields $rename_names)
            $field_order = (rename-record-field-order $field_order $rename_names)
        }

        if ($trimmed | str starts-with "default ") {
            let field_value = (record-default-field-value ($trimmed | str substring 7..))
            if $field_value == null {
                continue
            }

            let field_exists = ($field_order != null and $field_value.field in $field_order)
            let can_fill_field = (
                not (has-record-context-field? $fields $field_value.field)
                and (not $field_exists or $field_value.field in $null_fields)
            )
            if not $can_fill_field {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-flow-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    mut bindings = []

    for assignment in (declaration-assignments $line) {
        for field in (
            record-pipeline-flow-context-fields
                (declaration-rhs-token $assignment)
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
                $aliases
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

def record-literal-spread-context-fields [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut fields = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $fields
}

def record-spread-context-bindings [line: string aliases] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        for field in (record-literal-spread-context-fields (declaration-rhs-token $assignment) $aliases) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

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

def get-command-field-tail [segment: string] {
    let parsed = (
        $segment
        | str trim
        | parse --regex '^get\s+(?P<field>[A-Za-z_][A-Za-z0-9_-]*)(?P<tail>.*)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let row = ($parsed | first)
    {
        field: ($row.field | str trim)
        tail: ($row.tail | str trim)
    }
}

def context-root-from-get-input [input: string context_names bound_aliases] {
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let root = (context-root-from-value-token $normalized_input $context_names $bound_aliases)
    if $root != null {
        return $root
    }

    null
}

def get-segment-cell-path-tail [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^[\)\s]*\.(?P<path>[A-Za-z_][A-Za-z0-9_.-]*)'
    )
    if ($parsed | is-empty) {
        return ""
    }

    normalize-context-path-token (($parsed | first).path)
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
