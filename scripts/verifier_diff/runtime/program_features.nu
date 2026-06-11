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

def program-surface-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let context_names = (program-context-variable-names $source)
    let source_uses_context = (source-uses-context-variable? $source $context_names)
    mut bound_aliases = []
    mut bound_aliases_loaded = false
    mut record_context_aliases = []
    mut record_context_aliases_loaded = false
    mut map_kind_bindings = []
    let target_uses_skb_cgroup_helper = (
        ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "lwt_in:")
        or ($target_text | str starts-with "lwt_out:")
        or ($target_text | str starts-with "lwt_xmit:")
        or ($target_text | str starts-with "lwt_seg6local:")
    )

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_TAIL_CALL])
    }
    if (source-invokes-command-with-tail-prefix? $source "random" "int") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_GET_PRANDOM_U32])
    }
    if (source-invokes-command? $source "read-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_USER_STR])
    }
    if (source-invokes-command? $source "read-kernel-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR])
    }
    if (source-invokes-command? $source "emit") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_RINGBUF_OUTPUT])
    }
    if ((source-invokes-command? $source "count") or (source-invokes-command? $source "histogram")) {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "start-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "stop-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM
        ])
    }
    for line in ($source | lines) {
        if (line-invokes-command? $line "helper-call") {
            $map_kind_bindings = (
                update-helper-call-map-kind-bindings-for-line
                    $map_kind_bindings
                    ($line | str trim)
            )
            continue
        }

        let trimmed = ($line | str trim)
        let target_supports_ctx_sk_assign = (
            ($target_text | str starts-with "sk_lookup:")
            or ($target_text | str starts-with "tc_action:")
            or (($target_text | str starts-with "tc:") and ($target_text | str contains ":ingress"))
            or (($target_text | str starts-with "tcx:") and ($target_text | str contains ":ingress"))
        )
        let may_have_bound_context_helper_write = (
            $source_uses_context
            and ((($target_text | str starts-with "cgroup_sysctl:") and (
                ($trimmed | str contains ".new_value")
                or ($trimmed | str contains ".sysctl_new_value")
            ))
            or ($target_supports_ctx_sk_assign and (
                ($trimmed | str contains ".sk")
                or ($trimmed | str contains ".sock")
                or ($trimmed | str contains ".socket")
            ))
            or (($target_text | str starts-with "sock_ops:") and ($trimmed | str contains ".cb_flags")))
        )
        if $may_have_bound_context_helper_write and not $bound_aliases_loaded {
            $bound_aliases = (program-bound-context-root-aliases $source $context_names)
            $bound_aliases_loaded = true
        }
        let assigns_sysctl_new_value = (
            $source_uses_context
            and (
                (line-assigns-context-field? $trimmed $context_names ["new_value" "sysctl_new_value"])
                or (line-assigns-bound-context-root-field? $trimmed $bound_aliases ["new_value" "sysctl_new_value"])
            )
        )
        let may_have_record_context_helper_write = (
            $source_uses_context
            and ((($target_text | str starts-with "cgroup_sysctl:") and (
                ($trimmed | str contains ".new_value")
                or ($trimmed | str contains ".sysctl_new_value")
            ))
            or ($target_supports_ctx_sk_assign and (
                ($trimmed | str contains ".sk")
                or ($trimmed | str contains ".sock")
                or ($trimmed | str contains ".socket")
            ))
            or (($target_text | str starts-with "sock_ops:") and ($trimmed | str contains ".cb_flags")))
        )
        if $may_have_record_context_helper_write and not $record_context_aliases_loaded {
            $record_context_aliases = (program-record-context-aliases $source $context_names)
            $record_context_aliases_loaded = true
        }
        let assigns_ctx_sk = (
            $source_uses_context
            and $target_supports_ctx_sk_assign
            and (
                (line-assigns-context-field? $trimmed $context_names ["sk" "sock" "socket"])
                or (line-assigns-bound-context-root-field? $trimmed $bound_aliases ["sk" "sock" "socket"])
            )
        )
        let assigns_record_ctx_sk = (
            $source_uses_context
            and
            $target_supports_ctx_sk_assign
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["sk" "sock" "socket"] [""])
        )
        let assigns_record_sysctl_new_value = (
            $source_uses_context
            and
            ($target_text | str starts-with "cgroup_sysctl:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["new_value" "sysctl_new_value"] [""])
        )
        let assigns_record_sock_ops_cb_flags = (
            $source_uses_context
            and
            ($target_text | str starts-with "sock_ops:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["cb_flags"] [""])
        )
        let inferred_map_kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        let map_kind = if $inferred_map_kind == null { "hash" } else { $inferred_map_kind }
        if (line-invokes-command? $trimmed "map-get") and (generic-map-lookup-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-put") and (generic-map-update-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM])
        }
        if ($target_text | str starts-with "sock_ops:") and (line-invokes-command? $trimmed "map-put") {
            if $map_kind == "sockmap" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE])
            } else if $map_kind == "sockhash" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") and (generic-map-delete-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_DELETE_ELEM])
        }
        if ((line-invokes-command? $trimmed "map-get") or (line-invokes-command? $trimmed "map-contains")) {
            let local_storage_feature = (local-storage-get-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") {
            let local_storage_feature = (local-storage-delete-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-push") and ($map_kind in ["queue" "stack" "bloom-filter"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PUSH_ELEM])
        }
        if (line-invokes-command? $trimmed "map-peek") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
        }
        if (line-invokes-command? $trimmed "map-pop") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_POP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-contains") {
            if $map_kind == "bloom-filter" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
            } else if (generic-map-lookup-kind? $map_kind) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
            }
        }
        if (line-invokes-command? $trimmed "redirect-map") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_MAP])
        }
        if (line-invokes-command? $trimmed "map-contains") and ($map_kind == "cgroup-array") {
            if $target_uses_skb_cgroup_helper {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP])
            } else {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP])
            }
        }
        if (line-invokes-command? $trimmed "assign-socket") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
            let socket_context_feature = (context-field-kernel-feature "sk" $target)
            if $socket_context_feature != null {
                $features = (append-missing-kernel-features $features [$socket_context_feature])
            }
        }
        if ($target_text | str starts-with "cgroup_sysctl:") and ($assigns_sysctl_new_value or $assigns_record_sysctl_new_value) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE])
        }
        if $target_supports_ctx_sk_assign and ($assigns_ctx_sk or $assigns_record_ctx_sk) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--apply") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_APPLY_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--cork") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_CORK_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PULL_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--push") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PUSH_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pop") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_POP_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_PULL_DATA])
        }
        if (line-invokes-command? $trimmed "redirect-socket") {
            if ($target_text | str starts-with "sk_msg:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_skb:") or ($target_text | str starts-with "sk_skb_parser:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_reuseport:") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT])
            }
        }
        if ($target_text | str starts-with "sock_ops:") and (
            ($source_uses_context and (line-assigns-context-field? $trimmed $context_names ["cb_flags"]))
            or (line-assigns-bound-context-root-field? $trimmed $bound_aliases ["cb_flags"])
            or $assigns_record_sock_ops_cb_flags
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET])
        }
        if ($target_text | str starts-with "xdp:") {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--meta") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_META])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL])
            }
        } else {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--room") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM])
            }
        }
        if (line-invokes-command? $trimmed "redirect") {
            if ($trimmed | str contains "--peer") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_PEER])
            } else if ($trimmed | str contains "--neigh") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_NEIGH])
            } else if (
                ($target_text | str starts-with "xdp:")
                or ($target_text | str starts-with "tc_action:")
                or ($target_text | str starts-with "tc:")
                or ($target_text | str starts-with "tcx:")
                or ($target_text | str starts-with "netkit:")
                or ($target_text | str starts-with "lwt_xmit:")
            ) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    $features
}

def struct-ops-target-sleepable? [target: string] {
    if not ($target | str starts-with "struct_ops:sched_ext_ops.") {
        return false
    }

    let callback = (
        $target
        | split row "struct_ops:sched_ext_ops."
        | get 1
        | split row ":"
        | first
    )

    $callback in $SCHED_EXT_SLEEPABLE_CALLBACKS
}

def program-struct-ops-kernel-features [source: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "struct_ops:sched_ext_ops") {
        return []
    }

    mut features = []
    if (struct-ops-target-sleepable? $target_text) {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
    }

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        for callback in $SCHED_EXT_SLEEPABLE_CALLBACKS {
            if ($trimmed | str starts-with $"($callback):") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
            }
        }
    }

    $features
}

def target-kernel-features [target] {
    if $target == null {
        return []
    }

    mut features = []

    if ($target | str starts-with "fentry.s:") or ($target | str starts-with "fexit.s:") or ($target | str starts-with "fmod_ret.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "fentry:") or ($target | str starts-with "fexit:") or ($target | str starts-with "fmod_ret:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
    } else if ($target | str starts-with "tp_btf:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
    } else if ($target | str starts-with "lsm_cgroup:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM_CGROUP)
    } else if ($target | str starts-with "lsm.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "lsm:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
    } else if ($target | str starts-with "struct_ops:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_STRUCT_OPS)
        if ($target | str contains "tcp_congestion_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION)
        }
        if ($target | str contains "hid_bpf_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_HID_BPF)
        }
        if ($target | str contains "sched_ext_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT)
        }
        if ($target | str contains "Qdisc_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_QDISC)
        }
        if (struct-ops-target-sleepable? $target) {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "kprobe.multi:") or ($target | str starts-with "kretprobe.multi:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_KPROBE_MULTI)
    } else if ($target | str starts-with "kprobe:") or ($target | str starts-with "kretprobe:") or ($target | str starts-with "ksyscall:") or ($target | str starts-with "kretsyscall:") or ($target | str starts-with "uprobe:") or ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe:") or ($target | str starts-with "uretprobe.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        if ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "uprobe.multi:") or ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi:") or ($target | str starts-with "uretprobe.multi.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_UPROBE_MULTI)
        if ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "raw_tracepoint.w:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE)
    } else if ($target | str starts-with "raw_tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
    } else if ($target | str starts-with "tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACEPOINT)
    } else if ($target | str starts-with "perf_event:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_PERF_EVENT)
    } else if ($target | str starts-with "xdp:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_XDP)
        let xdp_parts = ($target | split row ":")
        if ("devmap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DEVMAP)
        } else if ("cpumap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_CPUMAP)
        } else if ("hw" in $xdp_parts) or ("hardware" in $xdp_parts) or ("offload" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_HW)
        } else if ("drv" in $xdp_parts) or ("driver" in $xdp_parts) or ("native" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DRV)
        } else {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_SKB)
        }
        if ("frags" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_MULTI_BUFFER)
        }
    } else if ($target | str starts-with "socket_filter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCKET_FILTER)
    } else if ($target | str starts-with "tc:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_CLS)
    } else if ($target | str starts-with "tc_action:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_ACT)
    } else if ($target | str starts-with "tcx:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_TCX)
    } else if ($target | str starts-with "netkit:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_NETKIT)
    } else if ($target | str starts-with "flow_dissector:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_FLOW_DISSECTOR)
    } else if ($target | str starts-with "netfilter:") {
        $features = ($features | append $KERNEL_FEATURE_NETFILTER_LINK)
        let netfilter_parts = ($target | split row ":")
        if ("defrag" in $netfilter_parts) {
            $features = ($features | append $KERNEL_FEATURE_NETFILTER_DEFRAG)
        }
    } else if ($target | str starts-with "lwt_seg6local:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT_SEG6LOCAL)
    } else if ($target | str starts-with "lwt_in:") or ($target | str starts-with "lwt_out:") or ($target | str starts-with "lwt_xmit:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
    } else if ($target | str starts-with "sk_lookup:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_LOOKUP)
    } else if ($target | str starts-with "sk_msg:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_MSG)
    } else if ($target | str starts-with "sk_skb:") or ($target | str starts-with "sk_skb_parser:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_SKB)
    } else if ($target | str starts-with "sk_reuseport:") {
        $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_ATTACH)
        let sk_reuseport_parts = ($target | split row ":")
        if ("migrate" in $sk_reuseport_parts) {
            $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_MIGRATION)
        }
    } else if ($target | str starts-with "cgroup_skb:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SKB)
    } else if ($target | str starts-with "cgroup_sock_addr:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR)
        let cgroup_sock_addr_hook = ($target | split row ":" | last)
        if ($cgroup_sock_addr_hook | str ends-with "_unix") {
            $features = ($features | append $KERNEL_FEATURE_ATTACH_CGROUP_UNIX_SOCK_ADDR)
        }
    } else if ($target | str starts-with "cgroup_sockopt:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCKOPT)
    } else if ($target | str starts-with "cgroup_sock:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK)
    } else if ($target | str starts-with "cgroup_device:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_DEVICE)
    } else if ($target | str starts-with "cgroup_sysctl:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SYSCTL)
    } else if ($target | str starts-with "sock_ops:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCK_OPS)
    } else if ($target | str starts-with "lirc_mode2:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LIRC_MODE2)
    } else if ($target | str starts-with "iter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_ITER)
        let iter_target = ($target | split row ":" | get 1)
        let iter_feature = (iter-target-kernel-feature $iter_target)
        if $iter_feature != null {
            $features = ($features | append $iter_feature)
        }
    } else if ($target | str starts-with "syscall:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SYSCALL)
    } else if ($target | str starts-with "freplace:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_EXTENSION)
    }

    $features
}

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
