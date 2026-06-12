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
