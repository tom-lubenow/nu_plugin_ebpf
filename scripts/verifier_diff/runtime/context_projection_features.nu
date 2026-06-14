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
