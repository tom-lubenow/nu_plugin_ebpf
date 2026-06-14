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
