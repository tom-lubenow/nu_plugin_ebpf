def iter-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
        "task"
        "iter_task"
        "file"
        "iter_file"
        "vma"
        "iter_vma"
        "cgroup"
        "iter_cgroup"
        "map"
        "iter_map"
        "prog"
        "iter_prog"
        "link"
        "iter_link"
        "sk_common"
        "sock_common"
        "iter_sk_common"
        "udp_sk"
        "iter_udp_sk"
        "unix_sk"
        "iter_unix_sk"
        "rt"
        "route"
        "ipv6_route"
        "iter_ipv6_route"
        "cache"
        "kmem_cache"
        "iter_kmem_cache"
        "ksym"
        "iter_ksym"
        "netlink_sk"
        "iter_netlink_sk"
        "dmabuf"
        "iter_dmabuf"
        "sk"
        "sock"
        "socket"
        "iter_sock"
    ]
}

def iter-trusted-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
    ]
}

def context-projection-root? [root: string] {
    if (iter-btf-context-projection-root? $root) {
        return true
    }

    $root in [
        "sk"
        "sock"
        "socket"
        "migrating_sk"
        "migrating_socket"
        "arg"
        "arg0"
        "arg1"
        "arg2"
        "arg3"
        "arg4"
        "arg5"
        "retval"
        "task"
        "current_task"
        "cgroup"
        "current_cgroup"
        "state"
        "nf_state"
        "skb"
        "flow_keys"
    ]
}

def target-uses-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "tp_btf:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def target-uses-trusted-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def context-projection-parts [token: string] {
    let cleaned = (
        $token
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
    if ($parts | length) < 2 {
        return []
    }

    let root = ($parts | first)
    if not (context-projection-root? $root) {
        return []
    }

    $parts
}

def tracepoint-built-in-context-field? [field: string] {
    $field in [
        "pid"
        "tid"
        "tgid"
        "pid_tgid"
        "current_pid_tgid"
        "uid"
        "gid"
        "uid_gid"
        "current_uid_gid"
        "comm"
        "current_task"
        "current_cgroup"
        "cpu"
        "numa_node"
        "numa_node_id"
        "random"
        "prandom_u32"
        "ktime"
        "timestamp"
        "ktime_boot"
        "boot_ktime"
        "boot_time"
        "ktime_coarse"
        "coarse_ktime"
        "coarse_time"
        "ktime_tai"
        "tai_ktime"
        "tai_time"
        "jiffies"
        "func_ip"
        "function_ip"
        "attach_cookie"
        "bpf_cookie"
        "cgroup_id"
        "kstack"
        "ustack"
    ]
}

def bpf-sock-projection-context-field [member: string] {
    if $member == "bound_dev_if" {
        return "bound_dev_if"
    }
    if $member == "family" {
        return "family"
    }
    if $member == "type" or $member == "sock_type" {
        return "sock_type"
    }
    if $member == "protocol" or $member == "ip_protocol" {
        return "protocol"
    }
    if $member == "mark" {
        return "mark"
    }
    if $member == "priority" {
        return "priority"
    }
    if $member == "src_ip4" or $member == "local_ip4" {
        return "local_ip4"
    }
    if $member == "src_ip6" or $member == "local_ip6" {
        return "local_ip6"
    }
    if $member == "src_port" or $member == "local_port" {
        return "local_port"
    }
    if $member == "dst_ip4" or $member == "remote_ip4" {
        return "remote_ip4"
    }
    if $member == "dst_ip6" or $member == "remote_ip6" {
        return "remote_ip6"
    }
    if $member == "dst_port" or $member == "remote_port" {
        return "remote_port"
    }
    if $member == "state" {
        return "state"
    }
    if $member == "rx_queue_mapping" {
        return "rx_queue_mapping"
    }

    null
}
