def program-kfunc-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "kfunc-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let kfunc_name = (normalize-kfunc-name-token $raw_name)
            if $kfunc_name not-in $names {
                $names = ($names | append $kfunc_name)
            }
        }
    }

    $names
}

def program-helper-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "helper-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let helper_name = (normalize-helper-name-token $raw_name)
            if $helper_name not-in $names {
                $names = ($names | append $helper_name)
            }
        }
    }

    $names
}

def program-map-kernel-features [source: string] {
    mut features = []
    mut map_kind_bindings = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-command? $trimmed "helper-call") {
            let feature = (helper-call-map-kind-kernel-feature $trimmed $map_kind_bindings)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
            $map_kind_bindings = (update-helper-call-map-kind-bindings-for-line $map_kind_bindings $trimmed)
            continue
        }

        if not (line-invokes-map-kind-surface? $trimmed) {
            continue
        }

        let kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        if $kind != null and $kind != "" {
            let feature = (map-kind-kernel-feature $kind)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PROG_ARRAY])
    }

    $features
}

def program-reserved-map-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (
            (line-invokes-command? $trimmed "emit")
            or (line-contains-code-marker? $trimmed " events")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_RINGBUF])
        }
        if (
            (line-invokes-command? $trimmed "count")
            or (line-invokes-command? $trimmed "histogram")
            or (line-invokes-command? $trimmed "start-timer")
            or (line-invokes-command? $trimmed "stop-timer")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_HASH])
        }
        if (line-contains-code-marker? $trimmed " user_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_USER_RINGBUF])
        }
        if (line-contains-code-marker? $trimmed " perf_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY])
        }
        if (
            (line-contains-code-marker? $trimmed " kstacks")
            or (line-contains-code-marker? $trimmed " ustacks")
            or (line-contains-code-marker? $trimmed ".kstack")
            or (line-contains-code-marker? $trimmed ".ustack")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_STACK_TRACE])
        }
    }

    $features
}

def program-map-value-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if not ((line-invokes-command? $trimmed "map-define") and (line-contains-code-marker? $trimmed "--value-type")) {
            continue
        }

        for entry in $MAP_VALUE_KERNEL_FEATURES {
            if ($trimmed | str contains $entry.token) {
                $features = (append-missing-kernel-features $features [$entry.feature])
            }
        }
        if ($trimmed | str contains "bpf_list_head:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE])
        }
        if ($trimmed | str contains "bpf_rb_root:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE])
        }
    }

    $features
}

const VERIFIER_DIFF_PROGRAM_FEATURES_RUNTIME_DIR = (path self | path dirname)
source ($VERIFIER_DIFF_PROGRAM_FEATURES_RUNTIME_DIR | path join program_global_features.nu)

def program-helper-kernel-features [source: string] {
    mut features = []

    for helper_name in (program-helper-names $source) {
        let feature = (helper-kernel-feature $helper_name)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    $features
}

def program-kfunc-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let cgroup_sock_addr_hook = if ($target_text | str starts-with "cgroup_sock_addr:") {
        $target_text | split row ":" | last
    } else {
        ""
    }
    let has_kfunc_call = ($source | str contains "kfunc-call")
    let may_assign_unix_sun_path = (
        ($target_text | str starts-with "cgroup_sock_addr:")
        and ($cgroup_sock_addr_hook | str ends-with "_unix")
        and ($source | str contains "sun_path")
    )

    if not $has_kfunc_call and not $may_assign_unix_sun_path {
        return []
    }

    if $has_kfunc_call {
        for kfunc_name in (program-kfunc-names $source) {
            let feature = (program-kfunc-kernel-feature $kfunc_name $target_text)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
    }

    if not $may_assign_unix_sun_path {
        return $features
    }

    let context_names = (program-context-variable-names $source)
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let record_context_aliases = (program-record-context-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if (
            (line-assigns-context-field? $trimmed $context_names ["sun_path"])
            or (line-assigns-bound-context-root-field? $trimmed $bound_aliases ["sun_path"])
            or (line-assigns-record-context-field? $trimmed $record_context_aliases ["sun_path"] [""])
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH])
        }
    }

    $features
}

def callback-trusted-btf-param-indexes [helper_name: string] {
    if $helper_name in ["bpf_timer_set_callback" "bpf_for_each_map_elem"] {
        return [0]
    }
    if $helper_name == "bpf_find_vma" {
        return [0 1]
    }

    []
}

def helper-call-name-from-line [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    normalize-helper-name-token (($tails | first | str trim | split row " " | first))
}

def closure-param-names-from-line [line: string] {
    let closure_parts = ($line | split row "{|")
    if ($closure_parts | length) <= 1 {
        return []
    }

    let raw_closure = ($closure_parts | skip 1 | first)
    let param_parts = ($raw_closure | split row "|")
    if ($param_parts | length) == 0 {
        return []
    }

    $param_parts
    | first
    | str replace --all "," " "
    | split row " "
    | each {|param| $param | str trim }
    | where {|param| $param != "" }
}

def helper-call-trusted-btf-callback-roots [line: string] {
    let helper_name = (helper-call-name-from-line $line)
    if $helper_name == null {
        return []
    }

    let trusted_indexes = (callback-trusted-btf-param-indexes $helper_name)
    if ($trusted_indexes | is-empty) {
        return []
    }

    let params = (closure-param-names-from-line $line)
    if ($params | is-empty) {
        return []
    }

    mut roots = []
    for idx in $trusted_indexes {
        if $idx < ($params | length) {
            let param = ($params | get $idx)
            if $param not-in $roots {
                $roots = ($roots | append $param)
            }
        }
    }

    $roots
}

def program-callback-btf-kernel-features [source: string] {
    mut features = []
    mut trusted_roots = []

    for line in ($source | lines) {
        let callback_roots = (helper-call-trusted-btf-callback-roots $line)
        if not ($callback_roots | is-empty) {
            $trusted_roots = $callback_roots
        }

        for root in $trusted_roots {
            let prefix = $"$($root)."
            let parts = ($line | split row $prefix)
            if ($parts | length) <= 1 {
                continue
            }

            for raw_tail in ($parts | skip 1) {
                let field = (normalize-context-field-token $raw_tail)
                if $field != "" {
                    # Trusted-BTF callback scalar projections lower as direct
                    # loads, not probe_read_kernel helper calls.
                    continue
                }
            }
        }

        let trimmed = ($line | str trim)
        if not ($trusted_roots | is-empty) and ($trimmed | str starts-with "}") {
            $trusted_roots = []
        }
    }

    $features
}

def source-uses-context-variable? [source: string context_names] {
    for context_name in $context_names {
        if ($source | str contains $"$($context_name)") {
            return true
        }
    }

    false
}

def line-assigns-bound-context-root-field? [line: string aliases fields] {
    let trimmed = ($line | str trim)
    for alias in $aliases {
        let root = ($alias | get -o root | default "")
        if $root != "" {
            continue
        }

        for field in $fields {
            let marker = $"$($alias.name).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def program-context-field-kernel-features [source: string target] {
    mut features = []
    let context_names = (program-context-variable-names $source)
    if not (source-uses-context-variable? $source $context_names) {
        return []
    }
    if not ($source | str contains ".") and not (($source | str contains "get") and ($source | str contains "|")) {
        return []
    }
    let may_have_bound_aliases = (source-may-bind-derived-context-variable? $source)
    mut bound_aliases = []
    mut bound_aliases_loaded = false

    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_access in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }

        if $may_have_bound_aliases and not $bound_aliases_loaded and ($line | str contains ".") {
            $bound_aliases = (program-bound-context-root-aliases $source $context_names)
            $bound_aliases_loaded = true
        }
        if ($bound_aliases | is-empty) {
            continue
        }

        for alias in $bound_aliases {
            let prefix = $"$($alias.name)."
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

    $features = (append-missing-kernel-features $features (user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (multi-param-user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (bound-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (context-get-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-get-projection-kernel-features $source $target $context_names))

    $features
}

source ($VERIFIER_DIFF_PROGRAM_FEATURES_RUNTIME_DIR | path join program_surface_features.nu)

def source-statement-lines [source: string] {
    $source
    | lines
    | each {|line| $line | str trim }
    | where {|line| $line != "" and not ($line | str starts-with "#") }
}

def line-has-statement-keyword? [line: string keyword: string] {
    not ((command-invocation-tails $line $keyword) | is-empty)
}

def line-has-callback-subprogram-literal? [line: string] {
    for command in ["helper-call" "kfunc-call"] {
        for raw_call in (command-invocation-tails $line $command) {
            if (line-contains-code-marker? $raw_call "{|") {
                return true
            }
        }
    }

    false
}

def program-language-kernel-features [source: string] {
    mut features = []

    for line in (source-statement-lines $source) {
        if (line-has-statement-keyword? $line "def") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-callback-subprogram-literal? $line) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-statement-keyword? $line "for") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BOUNDED_LOOPS])
        }
    }

    $features
}

def fixture-kernel-features [fixture] {
    mut features = (optional $fixture kernel_features [])
    $features = (append-missing-kernel-features $features (target-kernel-features ($fixture | get -o target)))
    let program = (fixture-program $fixture)
    $features = (append-missing-kernel-features $features (program-language-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-reserved-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-value-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-global-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-helper-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-kfunc-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-callback-btf-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-context-field-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-surface-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-struct-ops-kernel-features $program ($fixture | get -o target)))

    let legacy_min_kernel = ($fixture | get -o min_kernel)
    let legacy_min_kernel_source = ($fixture | get -o min_kernel_source)
    if $legacy_min_kernel != null {
        $features = (
            $features
            | append {
                key: "fixture"
                min_kernel: $legacy_min_kernel
                source: $legacy_min_kernel_source
            }
        )
    }

    $features
}
