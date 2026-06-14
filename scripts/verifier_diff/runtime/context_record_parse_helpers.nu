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
