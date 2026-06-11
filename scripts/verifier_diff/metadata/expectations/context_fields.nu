const TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "kretprobe:ksys_read" field: "retval" feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
    { target: "fexit:ksys_read" field: "retval" feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
    { target: "xdp:lo" field: "packet_len" feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
    { target: "xdp:lo" field: "data" feature: $KERNEL_FEATURE_CTX_XDP_DATA }
    { target: "xdp:lo" field: "data_end" feature: $KERNEL_FEATURE_CTX_XDP_DATA_END }
    { target: "xdp:lo" field: "ifindex" feature: $KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX }
    { target: "xdp:lo" field: "rx_queue_index" feature: $KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "data" feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "data_end" feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA_END }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "family" feature: $KERNEL_FEATURE_CTX_SK_MSG_FAMILY }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "size" feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    { target: "tc:lo:ingress" field: "sk" feature: $KERNEL_FEATURE_CTX_SKB_SK }
    { target: "sk_reuseport:select" field: "data" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA }
    { target: "sk_reuseport:select" field: "data_end" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END }
    { target: "sk_reuseport:select" field: "protocol" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL }
    { target: "sk_reuseport:select" field: "bind_inany" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY }
    { target: "sk_reuseport:migrate" field: "migrating_sk" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
    { target: "sock_ops:/sys/fs/cgroup" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
    { target: "sock_ops:/sys/fs/cgroup" field: "data" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA }
    { target: "sock_ops:/sys/fs/cgroup" field: "data_end" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "state" feature: $KERNEL_FEATURE_CTX_NETFILTER_STATE }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "skb" feature: $KERNEL_FEATURE_CTX_NETFILTER_SKB }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "hook" feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "pf" feature: $KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY }
    { target: "lirc_mode2:/dev/lirc0" field: "sample" feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
    { target: "lirc_mode2:/dev/lirc0" field: "value" feature: $KERNEL_FEATURE_CTX_LIRC_VALUE }
    { target: "lirc_mode2:/dev/lirc0" field: "mode" feature: $KERNEL_FEATURE_CTX_LIRC_MODE }
    { target: "perf_event:software:cpu-clock:period=100000" field: "sample_period" feature: $KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD }
    { target: "perf_event:software:cpu-clock:period=100000" field: "addr" feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
    { target: "cgroup_device:/sys/fs/cgroup" field: "access_type" feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE }
    { target: "cgroup_device:/sys/fs/cgroup" field: "device_type" feature: $KERNEL_FEATURE_CTX_DEVICE_TYPE }
    { target: "cgroup_device:/sys/fs/cgroup" field: "major" feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
    { target: "cgroup_device:/sys/fs/cgroup" field: "minor" feature: $KERNEL_FEATURE_CTX_DEVICE_MINOR }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "write" feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "file_pos" feature: $KERNEL_FEATURE_CTX_SYSCTL_FILE_POS }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "base_name" feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "optval" feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "optval_end" feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "retval" feature: $KERNEL_FEATURE_CTX_SOCKOPT_RETVAL }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "socket" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "bound_dev_if" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "family" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "remote_port" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "state" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "rx_queue_mapping" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "sock" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SK }
    { target: "sk_lookup:/proc/self/ns/net" field: "family" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY }
    { target: "sk_lookup:/proc/self/ns/net" field: "ingress_ifindex" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX }
    { target: "sk_lookup:/proc/self/ns/net" field: "cookie" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
    { target: "sk_lookup:/proc/self/ns/net" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_SK }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "family" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "user_ip4" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "remote_port" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "sock" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK }
    { target: "iter:task_vma" field: "task" feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
    { target: "iter:bpf_map_elem" field: "map" feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
    { target: "iter:bpf_map_elem" field: "key" feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
    { target: "iter:bpf_map_elem" field: "value" feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
    { target: "iter:task_file" field: "fd" feature: $KERNEL_FEATURE_CTX_ITER_FD }
    { target: "iter:task_file" field: "file" feature: $KERNEL_FEATURE_CTX_ITER_FILE }
    { target: "iter:sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
    { target: "iter:udp" field: "bucket" feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
    { target: "iter:unix" field: "uid" feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
    { target: "iter:dmabuf" field: "dmabuf" feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
]

const CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "raw_tracepoint:sys_enter" field: "pid" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID }
    { target: "raw_tracepoint:sys_enter" field: "task" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "current_task" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "cgroup" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "current_cgroup" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "uid" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID }
    { target: "raw_tracepoint:sys_enter" field: "comm" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_COMM }
    { target: "raw_tracepoint:sys_enter" field: "cpu" feature: $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID }
    { target: "raw_tracepoint:sys_enter" field: "numa_node" feature: $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID }
    { target: "raw_tracepoint:sys_enter" field: "random" feature: $KERNEL_FEATURE_BPF_GET_PRANDOM_U32 }
    { target: "tc:lo:ingress" field: "cgroup_classid" feature: $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID }
    { target: "tc:lo:ingress" field: "route_realm" feature: $KERNEL_FEATURE_BPF_GET_ROUTE_REALM }
    { target: "tc:lo:ingress" field: "csum_level" feature: $KERNEL_FEATURE_BPF_CSUM_LEVEL }
    { target: "tc:lo:ingress" field: "hash_recalc" feature: $KERNEL_FEATURE_BPF_GET_HASH_RECALC }
    { target: "raw_tracepoint:sys_enter" field: "cgroup_id" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID }
    { target: "tc:lo:ingress" field: "skb_cgroup_id" feature: $KERNEL_FEATURE_BPF_SKB_CGROUP_ID }
    { target: "tc:lo:ingress" field: "socket_cookie" feature: $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE }
    { target: "tc:lo:ingress" field: "socket_uid" feature: $KERNEL_FEATURE_BPF_GET_SOCKET_UID }
    { target: "sk_lookup:/proc/self/ns/net" field: "netns_cookie" feature: $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE }
    { target: "raw_tracepoint:sys_enter" field: "ktime" feature: $KERNEL_FEATURE_BPF_KTIME_GET_NS }
    { target: "raw_tracepoint:sys_enter" field: "ktime_boot" feature: $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS }
    { target: "tc:lo:ingress" field: "ktime_coarse" feature: $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS }
    { target: "raw_tracepoint:sys_enter" field: "ktime_tai" feature: $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS }
    { target: "raw_tracepoint:sys_enter" field: "jiffies" feature: $KERNEL_FEATURE_BPF_JIFFIES64 }
    { target: "fentry:security_file_open" field: "func_ip" feature: $KERNEL_FEATURE_BPF_GET_FUNC_IP }
    { target: "fentry:security_file_open" field: "attach_cookie" feature: $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE }
    { target: "perf_event:software:cpu-clock:period=100000" field: "perf_counter" feature: $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE }
    { target: "xdp:lo" field: "xdp_buff_len" feature: $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "name" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "current_value" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "new_value" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE }
    { target: "fentry:security_file_open" field: "arg_count" feature: $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT }
    { target: "raw_tracepoint:sys_enter" field: "kstack" feature: $KERNEL_FEATURE_BPF_GET_STACKID }
    { target: "raw_tracepoint:sys_enter" field: "ustack" feature: $KERNEL_FEATURE_BPF_GET_STACKID }
]

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
