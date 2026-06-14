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
