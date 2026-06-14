const ITER_TARGET_KERNEL_FEATURES = [
    { target: "task", feature: $KERNEL_FEATURE_ITER_TARGET_TASK }
    { target: "task_file", feature: $KERNEL_FEATURE_ITER_TARGET_TASK_FILE }
    { target: "task_vma", feature: $KERNEL_FEATURE_ITER_TARGET_TASK_VMA }
    { target: "bpf_map", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_MAP }
    { target: "cgroup", feature: $KERNEL_FEATURE_ITER_TARGET_CGROUP }
    { target: "bpf_map_elem", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_MAP_ELEM }
    { target: "bpf_sk_storage_map", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_SK_STORAGE_MAP }
    { target: "sockmap", feature: $KERNEL_FEATURE_ITER_TARGET_SOCKMAP }
    { target: "bpf_prog", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_PROG }
    { target: "bpf_link", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_LINK }
    { target: "tcp", feature: $KERNEL_FEATURE_ITER_TARGET_TCP }
    { target: "udp", feature: $KERNEL_FEATURE_ITER_TARGET_UDP }
    { target: "unix", feature: $KERNEL_FEATURE_ITER_TARGET_UNIX }
    { target: "ipv6_route", feature: $KERNEL_FEATURE_ITER_TARGET_IPV6_ROUTE }
    { target: "ksym", feature: $KERNEL_FEATURE_ITER_TARGET_KSYM }
    { target: "netlink", feature: $KERNEL_FEATURE_ITER_TARGET_NETLINK }
    { target: "kmem_cache", feature: $KERNEL_FEATURE_ITER_TARGET_KMEM_CACHE }
    { target: "dmabuf", feature: $KERNEL_FEATURE_ITER_TARGET_DMABUF }
]

let CONTEXT_FIELD_KERNEL_FEATURES = (
    [
    { field: "packet_len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "pkt_type", feature: $KERNEL_FEATURE_CTX_PKT_TYPE }
    { field: "queue_mapping", feature: $KERNEL_FEATURE_CTX_QUEUE_MAPPING }
    { field: "eth_protocol", feature: $KERNEL_FEATURE_CTX_ETH_PROTOCOL }
    { field: "protocol", feature: $KERNEL_FEATURE_CTX_PROTOCOL }
    { field: "ip_protocol", feature: $KERNEL_FEATURE_CTX_PROTOCOL }
    { field: "vlan_present", feature: $KERNEL_FEATURE_CTX_VLAN_PRESENT }
    { field: "vlan_tci", feature: $KERNEL_FEATURE_CTX_VLAN_TCI }
    { field: "vlan_proto", feature: $KERNEL_FEATURE_CTX_VLAN_PROTO }
    { field: "mark", feature: $KERNEL_FEATURE_CTX_MARK }
    { field: "priority", feature: $KERNEL_FEATURE_CTX_PRIORITY }
    { field: "ifindex", feature: $KERNEL_FEATURE_CTX_IFINDEX }
    { field: "ingress_ifindex", feature: $KERNEL_FEATURE_CTX_INGRESS_IFINDEX }
    { field: "tc_index", feature: $KERNEL_FEATURE_CTX_TC_INDEX }
    { field: "hash", feature: $KERNEL_FEATURE_CTX_HASH }
    { field: "cb", feature: $KERNEL_FEATURE_CTX_CB }
    { field: "tc_classid", feature: $KERNEL_FEATURE_CTX_TC_CLASSID }
    { field: "data", feature: $KERNEL_FEATURE_CTX_DATA }
    { field: "data_end", feature: $KERNEL_FEATURE_CTX_DATA_END }
    { field: "family", feature: $KERNEL_FEATURE_CTX_FAMILY }
    { field: "napi_id", feature: $KERNEL_FEATURE_CTX_NAPI_ID }
    { field: "remote_ip4", feature: $KERNEL_FEATURE_CTX_REMOTE_IP4 }
    { field: "remote_ip6", feature: $KERNEL_FEATURE_CTX_REMOTE_IP6 }
    { field: "remote_port", feature: $KERNEL_FEATURE_CTX_REMOTE_PORT }
    { field: "local_ip4", feature: $KERNEL_FEATURE_CTX_LOCAL_IP4 }
    { field: "local_ip6", feature: $KERNEL_FEATURE_CTX_LOCAL_IP6 }
    { field: "local_port", feature: $KERNEL_FEATURE_CTX_LOCAL_PORT }
    { field: "data_meta", feature: $KERNEL_FEATURE_CTX_DATA_META }
    { field: "rx_queue_index", feature: $KERNEL_FEATURE_CTX_RX_QUEUE_INDEX }
    { field: "flow_keys", feature: $KERNEL_FEATURE_CTX_FLOW_KEYS }
    { field: "tstamp", feature: $KERNEL_FEATURE_CTX_TSTAMP }
    { field: "wire_len", feature: $KERNEL_FEATURE_CTX_WIRE_LEN }
    { field: "gso_segs", feature: $KERNEL_FEATURE_CTX_GSO_SEGS }
    { field: "gso_size", feature: $KERNEL_FEATURE_CTX_GSO_SIZE }
    { field: "egress_ifindex", feature: $KERNEL_FEATURE_CTX_EGRESS_IFINDEX }
    { field: "skb_len", feature: $KERNEL_FEATURE_CTX_SOCK_OPS_SKB_LEN }
    { field: "skb_tcp_flags", feature: $KERNEL_FEATURE_CTX_SOCK_OPS_SKB_TCP_FLAGS }
    { field: "hwtstamp", feature: $KERNEL_FEATURE_CTX_HWTSTAMP }
    { field: "tstamp_type", feature: $KERNEL_FEATURE_CTX_TSTAMP_TYPE }
    { field: "skb_hwtstamp", feature: $KERNEL_FEATURE_CTX_SKB_HWTSTAMP }
    ]
    | append $CONTEXT_IDENTITY_FIELD_KERNEL_FEATURES
)
