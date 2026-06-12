const VERIFIER_DIFF_CONTEXT_FIELDS_RUNTIME_DIR = (path self | path dirname)
source ($VERIFIER_DIFF_CONTEXT_FIELDS_RUNTIME_DIR | path join context_target_fields.nu)
source ($VERIFIER_DIFF_CONTEXT_FIELDS_RUNTIME_DIR | path join context_projection_roots.nu)

def context-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }

    let target_alias = (target-context-field-alias-kernel-feature $field $target)
    if $target_alias.matched {
        return $target_alias.feature
    }

    let matches = ($CONTEXT_FIELD_KERNEL_FEATURES | where {|entry| $entry.field == $field })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def context-field-helper-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }
    if $field in ["pid" "tid" "tgid" "pid_tgid" "current_pid_tgid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
    }
    if $field == "current_task" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "task" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "current_cgroup" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "cgroup" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field in ["uid" "gid" "uid_gid" "current_uid_gid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID
    }
    if $field == "comm" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_COMM
    }
    if $field in ["cpu" "processor_id" "smp_processor_id"] {
        return $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID
    }
    if $field in ["numa_node" "numa_node_id"] {
        return $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID
    }
    if $field in ["random" "prandom_u32"] {
        return $KERNEL_FEATURE_BPF_GET_PRANDOM_U32
    }
    if $field == "cgroup_classid" {
        return $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID
    }
    if $field == "route_realm" {
        return $KERNEL_FEATURE_BPF_GET_ROUTE_REALM
    }
    if $field == "csum_level" {
        return $KERNEL_FEATURE_BPF_CSUM_LEVEL
    }
    if $field in ["hash_recalc" "recalc_hash"] {
        return $KERNEL_FEATURE_BPF_GET_HASH_RECALC
    }
    if $field == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID
    }
    if $field == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_ANCESTOR_CGROUP_ID
    }
    if $field == "skb_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_CGROUP_ID
    }
    if $field == "skb_ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID
    }
    if $field == "socket_cookie" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE
    }
    if $field == "socket_uid" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_UID
    }
    if $field == "netns_cookie" {
        return $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE
    }
    if $field == "ktime" or $field == "timestamp" {
        return $KERNEL_FEATURE_BPF_KTIME_GET_NS
    }
    if $field in ["ktime_boot" "boot_ktime" "boot_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS
    }
    if $field in ["ktime_coarse" "coarse_ktime" "coarse_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS
    }
    if $field in ["ktime_tai" "tai_ktime" "tai_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS
    }
    if $field == "jiffies" {
        return $KERNEL_FEATURE_BPF_JIFFIES64
    }
    if $field in ["func_ip" "function_ip"] {
        return $KERNEL_FEATURE_BPF_GET_FUNC_IP
    }
    if $field in ["attach_cookie" "bpf_cookie"] {
        return $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE
    }
    if $field in ["perf_counter" "perf_enabled" "perf_running"] {
        return $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE
    }
    if $field in ["xdp_buff_len" "xdp_buffer_len"] {
        return $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field in ["sysctl_name" "name" "sysctl_base_name" "base_name"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME
        }
        if $field in ["sysctl_current_value" "current_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE
        }
        if $field in ["sysctl_new_value" "new_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE
        }
    }
    if $field == "arg_count" {
        return $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT
    }
    if $field in ["kstack" "ustack"] {
        return $KERNEL_FEATURE_BPF_GET_STACKID
    }

    null
}

def iter-target-kernel-feature [target: string] {
    let matches = ($ITER_TARGET_KERNEL_FEATURES | where {|entry| $entry.target == $target })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def context-field-access-is-assignment-lhs? [raw_access: string field: string] {
    let compact = ($raw_access | str trim | str replace --all " " "")
    if not ($compact | str contains "=") {
        return false
    }
    let parts = ($compact | split row "=")
    if ($parts | length) < 2 {
        return false
    }

    let rhs_after_first_equals = ($parts | skip 1 | first)
    if $rhs_after_first_equals == "" {
        return false
    }

    let lhs = ($parts | first)

    ($lhs == $field) or ($lhs | str starts-with $"($field).")
}

def line-assigns-context-field? [line: string context_names fields] {
    let trimmed = ($line | str trim)
    for context_name in $context_names {
        for field in $fields {
            let marker = $"$($context_name).($field)"
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

def line-assigns-record-context-field? [line: string aliases fields roots] {
    let trimmed = ($line | str trim)
    for alias in $aliases {
        let root = ($alias | get -o root | default "")
        if $root not-in $roots {
            continue
        }

        for field in $fields {
            let marker = $"$($alias.name).($alias.field).($field)"
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

def context-projection-kernel-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }
    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    let socket_projection_root = (
        ($root in ["sk" "sock" "socket" "migrating_sk" "migrating_socket"])
        and not ($target_text | str starts-with "iter:")
    )

    if $socket_projection_root and $member == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_CGROUP_ID
    }
    if $socket_projection_root and $member == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID
    }
    if $socket_projection_root and ($member in ["tcp" "tcp_sock"]) {
        return $KERNEL_FEATURE_BPF_TCP_SOCK
    }
    if $socket_projection_root and ($member in ["full" "fullsock" "full_sock"]) {
        return $KERNEL_FEATURE_BPF_SK_FULLSOCK
    }
    if $socket_projection_root and $member == "listener" {
        return $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK
    }
    if $root == "flow_keys" {
        return (context-field-kernel-feature "flow_keys" $target)
    }
    if not $socket_projection_root {
        return null
    }

    let field = (bpf-sock-projection-context-field $member)
    if $field == null {
        return null
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        return $feature
    }
    if $field == "rx_queue_mapping" {
        return $KERNEL_FEATURE_CTX_BPF_SOCK_RX_QUEUE_MAPPING
    }

    null
}

def trusted-btf-projection-kernel-read? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    let root = ($parts | first)
    let first_member = ($parts | get 1)

    if ($target_text | str starts-with "iter:") and (iter-trusted-btf-context-projection-root? $root) {
        return true
    }
    if $root in ["current_task" "current_cgroup"] {
        return true
    }
    if $root in ["task" "cgroup"] {
        if ($target_text | str starts-with "tracepoint:") {
            return false
        }
        if $root == "task" and $first_member == "pt_regs" {
            return false
        }
        return true
    }
    if ($target_text | str starts-with "netfilter:") and ($root in ["state" "nf_state" "skb"]) {
        return true
    }
    if (target-uses-trusted-btf-context-args? $target_text) {
        if $root == "arg" and ($parts | length) >= 3 {
            return true
        }
        if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
            return true
        }
    }

    false
}

def btf-context-arg-projection? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    if not (target-uses-btf-context-args? $target_text) {
        return false
    }

    let root = ($parts | first)
    if $root == "arg" and ($parts | length) >= 3 {
        return true
    }
    if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
        return true
    }

    false
}

def context-projection-kernel-read-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }

    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    if (bpf-sock-projection-context-field $member) != null {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    let helper_backed_socket_projection = (
        ($parts | length) >= 3
        and ($member in ["tcp" "tcp_sock" "full" "fullsock" "full_sock" "listener"])
    )
    if $helper_backed_socket_projection {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (
        ($target_text | str starts-with "iter:")
        and (iter-btf-context-projection-root? $root)
        and not (iter-trusted-btf-context-projection-root? $root)
    ) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (trusted-btf-projection-kernel-read? $parts $target) {
        # Trusted kernel-BTF scalar projections lower as direct loads. Aggregate
        # projections that still need a helper should declare that explicitly.
        return null
    }
    if (btf-context-arg-projection? $parts $target) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }

    null
}

def context-task-pt-regs-kernel-feature [raw_access: string] {
    let cleaned = (
        $raw_access
        | str trim
        | split row " "
        | first
        | str replace --all ")" ""
        | str replace --all "(" ""
        | str replace --all "," ""
        | str replace --all "\"" ""
        | str replace --all "'" ""
        | str replace --all "}" ""
        | str replace --all "]" ""
        | str replace --all ";" ""
    )
    let parts = ($cleaned | split row ".")
    if ($parts | length) < 3 {
        return null
    }

    let root = ($parts | first)
    if $root not-in ["task" "current_task"] {
        return null
    }
    if ($parts | get 1) != "pt_regs" {
        return null
    }
    if ($parts | get 2) not-in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"] {
        return null
    }

    $KERNEL_FEATURE_BPF_TASK_PT_REGS
}
