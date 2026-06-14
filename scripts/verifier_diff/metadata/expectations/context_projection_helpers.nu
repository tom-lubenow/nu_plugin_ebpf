const CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.cgroup_id" helper: "bpf_sk_cgroup_id" feature: $KERNEL_FEATURE_BPF_SK_CGROUP_ID }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.ancestor_cgroup_id.0" helper: "bpf_sk_ancestor_cgroup_id" feature: $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID }
    { target: "tc:lo:ingress" raw_access: "sk.full" helper: "bpf_sk_fullsock" feature: $KERNEL_FEATURE_BPF_SK_FULLSOCK }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.tcp" helper: "bpf_tcp_sock" feature: $KERNEL_FEATURE_BPF_TCP_SOCK }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.listener" helper: "bpf_get_listener_sock" feature: $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK }
    { target: "cgroup_sock:/sys/fs/cgroup:post_bind4" raw_access: "sk.local_ip4" helper: "" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" raw_access: "sk.remote_port" helper: "" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
    { target: "flow_dissector:/proc/self/ns/net" raw_access: "flow_keys.ip_proto" helper: "" feature: $KERNEL_FEATURE_CTX_FLOW_KEYS }
]
