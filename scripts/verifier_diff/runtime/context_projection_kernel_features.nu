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
