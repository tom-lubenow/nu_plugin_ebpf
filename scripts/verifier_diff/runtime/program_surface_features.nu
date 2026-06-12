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
