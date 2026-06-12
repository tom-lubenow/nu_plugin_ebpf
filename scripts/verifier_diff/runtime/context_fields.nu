def target-uses-bpf-tracing-prog-type [target] {
    let target_text = ($target | default "")
    [
        ($target_text | str starts-with "fentry:")
        ($target_text | str starts-with "fentry.s:")
        ($target_text | str starts-with "fexit:")
        ($target_text | str starts-with "fexit.s:")
        ($target_text | str starts-with "fmod_ret:")
        ($target_text | str starts-with "fmod_ret.s:")
        ($target_text | str starts-with "tp_btf:")
    ] | any {|matches| $matches }
}

def program-kfunc-kernel-feature [name: string target] {
    if $name == "bpf_dynptr_from_skb" and (target-uses-bpf-tracing-prog-type $target) {
        return {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }

    kfunc-kernel-feature $name
}

def sock-ops-context-field-kernel-feature [field: string] {
    if $field in ["op" "reply" "replylong"] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.14"
            source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
        }
    }

    if $field in [
        "args"
        "is_fullsock"
        "snd_cwnd"
        "srtt_us"
        "cb_flags"
        "state"
        "rtt_min"
        "snd_ssthresh"
        "rcv_nxt"
        "snd_nxt"
        "snd_una"
        "mss_cache"
        "ecn_flags"
        "rate_delivered"
        "rate_interval_us"
        "packets_out"
        "retrans_out"
        "total_retrans"
        "segs_in"
        "data_segs_in"
        "segs_out"
        "data_segs_out"
        "lost_out"
        "sacked_out"
        "sk_txhash"
        "bytes_received"
        "bytes_acked"
    ] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.16"
            source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
        }
    }

    if $field in ["sk" "sock" "socket"] {
        return {
            key: "ctx:sk"
            min_kernel: "5.3"
            source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
        }
    }

    null
}

def target-context-field-alias-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if $field == "retval" {
        if (
            ($target_text | str starts-with "kretprobe:")
            or ($target_text | str starts-with "kretprobe.multi:")
            or ($target_text | str starts-with "kretsyscall:")
            or ($target_text | str starts-with "uretprobe:")
            or ($target_text | str starts-with "uretprobe.s:")
            or ($target_text | str starts-with "uretprobe.multi:")
            or ($target_text | str starts-with "uretprobe.multi.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
        }
        if (
            ($target_text | str starts-with "fexit:")
            or ($target_text | str starts-with "fexit.s:")
            or ($target_text | str starts-with "fmod_ret:")
            or ($target_text | str starts-with "fmod_ret.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
        }
    }

    if ($target_text | str starts-with "xdp:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA_END }
        }
        if $field == "ingress_ifindex" or $field == "ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX }
        }
        if $field == "rx_queue_index" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX }
        }
    }
    if ($target_text | str starts-with "sk_msg:") {
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA_END }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_FAMILY }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_PORT }
        }
        if $field == "size" or $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
        }
    }
    if (
        ($target_text | str starts-with "sk_skb:")
        or ($target_text | str starts-with "sk_skb_parser:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    }
    if (
        ($target_text | str starts-with "socket_filter:")
        or ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "cgroup_skb:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SKB_SK }
    }
    if ($target_text | str starts-with "sk_reuseport:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END }
        }
        if $field == "eth_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_ETH_PROTOCOL }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL }
        }
        if $field == "bind_inany" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY }
        }
        if $field == "hash" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_HASH }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_SK }
        }
        if $field == "migrating_sk" or $field == "migrating_socket" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
        }
    }
    if ($target_text | str starts-with "sock_ops:") {
        let sock_ops_feature = (sock-ops-context-field-kernel-feature $field)
        if $sock_ops_feature != null {
            return { matched: true, feature: $sock_ops_feature }
        }
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END }
        }
    }
    if ($target_text | str starts-with "netfilter:") {
        if $field == "state" or $field == "nf_state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_STATE }
        }
        if $field == "skb" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_SKB }
        }
        if $field == "hook" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
        }
        if $field == "pf" or $field == "protocol_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY }
        }
    }
    if ($target_text | str starts-with "lirc_mode2:") {
        if $field == "sample" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
        }
        if $field == "value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_VALUE }
        }
        if $field == "mode" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_MODE }
        }
    }
    if ($target_text | str starts-with "perf_event:") {
        if $field == "sample_period" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD }
        }
        if $field == "addr" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
        }
    }
    if ($target_text | str starts-with "cgroup_device:") {
        if $field == "access_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE }
        }
        if $field == "device_access" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS }
        }
        if $field == "device_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_TYPE }
        }
        if $field == "major" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
        }
        if $field == "minor" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MINOR }
        }
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field == "name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NAME }
        }
        if $field == "base_name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
        }
        if $field == "current_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_CURRENT_VALUE }
        }
        if $field == "new_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NEW_VALUE }
        }
        if $field == "write" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
        }
        if $field == "file_pos" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_FILE_POS }
        }
    }
    if ($target_text | str starts-with "cgroup_sockopt:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK }
        }
        if $field == "level" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_LEVEL }
        }
        if $field == "optname" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTNAME }
        }
        if $field == "optlen" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTLEN }
        }
        if $field == "optval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
        }
        if $field == "optval_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END }
        }
        if $field == "retval" or $field == "sockopt_retval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_RETVAL }
        }
    }
    if ($target_text | str starts-with "cgroup_sock:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SK }
        }
        if $field == "bound_dev_if" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PROTOCOL }
        }
        if $field == "mark" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_MARK }
        }
        if $field == "priority" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PRIORITY }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
        }
        if $field == "state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
        }
        if $field == "rx_queue_mapping" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING }
        }
    }
    if ($target_text | str starts-with "sk_lookup:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_PROTOCOL }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_PORT }
        }
        if $field == "cookie" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
        }
        if $field == "ingress_ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX }
        }
    }
    if ($target_text | str starts-with "cgroup_sock_addr:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_PROTOCOL }
        }
        if $field == "user_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_FAMILY }
        }
        if $field == "user_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
        }
        if $field == "user_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP6 }
        }
        if $field == "user_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            if ($target_text | str ends-with ":sendmsg4") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip4"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            if ($target_text | str ends-with ":sendmsg6") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip6"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_PORT }
        }
        if $field == "msg_src_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 }
        }
        if $field == "msg_src_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 }
        }
    }

    if ($target_text | str starts-with "iter:") {
        let iter_target = ($target_text | split row ":" | get 1)

        if $field == "meta" or $field == "iter_meta" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_META }
        }
        if $field == "task" or $field == "iter_task" {
            if $iter_target == "task_vma" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
            }
            if $iter_target in ["task" "task_file"] {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK }
            }
        }
        if ($field == "fd" or $field == "iter_fd") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FD }
        }
        if ($field == "file" or $field == "iter_file") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FILE }
        }
        if ($field == "vma" or $field == "iter_vma") and $iter_target == "task_vma" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_VMA }
        }
        if ($field == "cgroup" or $field == "iter_cgroup") and $iter_target == "cgroup" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_CGROUP }
        }
        if $field == "map" or $field == "iter_map" {
            if $iter_target == "bpf_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP }
            }
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_MAP }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_MAP }
            }
        }
        if $field == "key" or $field == "iter_key" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_KEY }
            }
        }
        if $field == "value" or $field == "iter_value" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_VALUE }
            }
        }
        if $field == "sk" or $field == "sock" or $field == "iter_sock" {
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_SOCK }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
            }
        }
        if ($field == "prog" or $field == "iter_prog") and $iter_target == "bpf_prog" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_PROG }
        }
        if ($field == "link" or $field == "iter_link") and $iter_target == "bpf_link" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_LINK }
        }
        if ($field == "sk_common" or $field == "sock_common" or $field == "iter_sk_common") and $iter_target == "tcp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_SK_COMMON }
        }
        if ($field == "udp_sk" or $field == "iter_udp_sk") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_SK }
        }
        if ($field == "unix_sk" or $field == "iter_unix_sk") and $iter_target == "unix" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_SK }
        }
        if $field == "uid" or $field == "iter_uid" {
            if $iter_target == "tcp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_UID }
            }
            if $iter_target == "udp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_UID }
            }
            if $iter_target == "unix" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
            }
        }
        if ($field == "bucket" or $field == "iter_bucket") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
        }
        if ($field == "rt" or $field == "route" or $field == "ipv6_route" or $field == "iter_ipv6_route") and $iter_target == "ipv6_route" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_IPV6_ROUTE }
        }
        if ($field == "ksym" or $field == "iter_ksym") and $iter_target == "ksym" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KSYM }
        }
        if ($field == "netlink_sk" or $field == "iter_netlink_sk") and $iter_target == "netlink" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_NETLINK_SK }
        }
        if ($field == "cache" or $field == "kmem_cache" or $field == "iter_kmem_cache") and $iter_target == "kmem_cache" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KMEM_CACHE }
        }
        if ($field == "dmabuf" or $field == "iter_dmabuf") and $iter_target == "dmabuf" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
        }
    }

    { matched: false, feature: null }
}

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
