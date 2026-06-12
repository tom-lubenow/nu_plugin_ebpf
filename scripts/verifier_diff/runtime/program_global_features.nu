def variable-token-used-outside-simple-string? [text: string name: string] {
    for tail in (marker-tails-outside-simple-string $text $"$($name)") {
        if $tail == "" {
            return true
        }
        let first = ($tail | str substring 0..0)
        if $first in [" " "\t" "." "," ":" ")" "}" "]" "|" ";"] {
            return true
        }
    }

    false
}

def aggregate-rhs-contains-context-token? [rhs: string context_names context_root_aliases] {
    for context_name in $context_names {
        if (variable-token-used-outside-simple-string? $rhs $context_name) {
            return true
        }
    }

    for alias in $context_root_aliases {
        let name = ($alias | get -o name)
        if $name != null and (variable-token-used-outside-simple-string? $rhs $name) {
            return true
        }
    }

    false
}

def line-declares-readonly-aggregate-constant? [line: string context_names context_root_aliases] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let rhs = (declaration-rhs-token $assignment)
        let aggregate_rhs = (trim-simple-parentheses $rhs)
        if (aggregate-rhs-contains-context-token? $aggregate_rhs $context_names $context_root_aliases) {
            continue
        }
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal-with-variable? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (
            (($compact | str starts-with "{") and $compact != "{}")
            or (($compact | str starts-with "[") and $compact != "[]")
            or (($compact | str starts-with "0x[") and $compact != "0x[]")
        ) and (line-contains-code-marker? $aggregate_rhs "$") {
            return true
        }
    }

    false
}

def line-invokes-global-command? [line: string] {
    for command in ["global-define" "global-get" "global-set"] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def line-declares-annotated-mut-global? [line: string] {
    for tail in (command-invocation-tails $line "mut") {
        let lhs = ($tail | split row "=" | first | str trim)
        if ($lhs | str contains ":") {
            return true
        }
    }

    false
}

def program-global-kernel-features [source: string] {
    mut variable_aggregate_lines = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-global-command? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if (line-declares-annotated-mut-global? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if not (line-declares-aggregate-literal? $trimmed) {
            continue
        }

        if not (line-declares-aggregate-literal-with-variable? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        $variable_aggregate_lines = ($variable_aggregate_lines | append $trimmed)
    }

    if ($variable_aggregate_lines | is-empty) {
        return []
    }

    let context_names = (program-context-variable-names $source)
    let context_root_aliases = (program-bound-context-root-aliases $source $context_names)
    mut context_aliases = $context_root_aliases
    mut record_context_aliases_loaded = false

    for trimmed in $variable_aggregate_lines {
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        if not $record_context_aliases_loaded {
            $context_aliases = (
                $context_aliases
                | append (program-record-context-aliases $source $context_names)
            )
            $record_context_aliases_loaded = true
        }
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
    }

    []
}
