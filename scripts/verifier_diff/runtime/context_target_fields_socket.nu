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

def target-socket-context-field-alias-kernel-feature [field: string target_text: string] {
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

    { matched: false, feature: null }
}
