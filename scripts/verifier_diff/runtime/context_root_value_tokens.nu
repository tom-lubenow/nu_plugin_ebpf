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
