
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

const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let docs = "$ctx.pid $ctx.sk.family"'
            '  # $ctx.pid $ctx.sk.family'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { root: $ctx }'
            '  let docs = "$sk.family $rec.root.sk.family"'
            '  # $sk.family $rec.root.sk.family'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | insert socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: ($ctx | get sk) } | rename sock)'
            '  $rec | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | merge { socket: ($ctx | get sk) })'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default ($ctx | get sk) socket)'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk } | update socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx | get sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [c] { $c | get sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [c] { { socket: ($c | get sk) } }'
            '  wrap $ctx | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_packet [event] {'
            '    $event | get packet_len | count'
            '    0'
            '  }'
            '  read_packet $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [event] {'
            '    let sk = ($event | get sk)'
            '    $sk | get family | count'
            '    0'
            '  }'
            '  read_family $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx| $ctx | get sk | get family | count; 0}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let event = (id $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { ($x) }'
            '  let event = (id ($ctx))'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def read_pid [event] {'
            '    $event.pid | count'
            '    0'
            '  }'
            '  let seen = (read_pid $ctx)'
            '  $seen | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  let event = (passthrough $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { event: $ctx }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { event: (id $ctx) }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let rec = { event: $event }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let base = { event: $event }; let rec = { ok: true, ...$base }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = { event: null }'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = { event: null }'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = {}'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    let rec = { ok: true, ...$base }'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def read_pid [c] {'
            '    let actual = (id $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id $x }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id ($x) }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "ctx:timestamp" "helper:bpf_get_current_pid_tgid" "helper:bpf_ktime_get_ns"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        feature_keys: ["ctx:rx_queue_mapping" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let sk = (id $ctx.sk)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let sk = $ctx.sk'
            '  let same = (id $sk)'
            '  $same.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [ignored event] { { socket: ($event | get sk) } }'
            '  let rec = (wrap 0 $ctx)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [sk] {'
            '    $sk.family | count'
            '    0'
            '  }'
            '  let sk = $ctx.sk'
            '  let seen = (read_family $sk)'
            '  $seen | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { socket: (id $ctx.sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx.sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap_socket [sock] { { socket: $sock } }'
            '  def wrap_event [event] {'
            '    let sock = $event.sk'
            '    let base = (wrap_socket $sock)'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap_event $ctx)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let inserted = ({ ok: true } | insert socket $ctx.sk)'
            '  let base = { socket: null }'
            '  let updated = ($base | update socket $ctx.sk)'
            '  let upserted = ({ ok: true } | upsert socket $ctx.sk)'
            '  $inserted.socket.family | count'
            '  $updated.socket.family | count'
            '  $upserted.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ($base | upsert ok true)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { ok: true } | upsert socket $sock }'
            '  let rec = (wrap $ctx.sk)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp { $rec.tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sockopt_retval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  $ctx.optname = 2'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:level" "ctx:optname" "ctx:optlen"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:remote_ip4"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:msg_src_ip6" "ctx:local_ip6"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full { $full.family | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_fullsock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener { $listener.family | count }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_get_listener_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf" "helper:bpf_task_pt_regs"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cgroup" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.current_task.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:filename"
            "tracepoint:syscalls/sys_enter_openat:field:dfd"
            "tracepoint:syscalls/sys_enter_openat:field:flags"
            "tracepoint:syscalls/sys_enter_openat:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat2"
        program: [
            '{|ctx|'
            '  let how = $ctx.how'
            '  if $how { 1 | count }'
            '  ($ctx.dfd + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat2:field:how"
            "tracepoint:syscalls/sys_enter_openat2:field:dfd"
            "tracepoint:syscalls/sys_enter_openat2:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_open"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_open:field:filename"
            "tracepoint:syscalls/sys_enter_open:field:flags"
            "tracepoint:syscalls/sys_enter_open:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchmodat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchmodat2:field:filename"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:dfd"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:mode"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_utimensat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let utimes = $ctx.utimes'
            '  if $filename { 1 | count }'
            '  if $utimes { 1 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_utimensat:field:filename"
            "tracepoint:syscalls/sys_enter_utimensat:field:utimes"
            "tracepoint:syscalls/sys_enter_utimensat:field:dfd"
            "tracepoint:syscalls/sys_enter_utimensat:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ppoll"
        program: [
            '{|ctx|'
            '  let ufds = $ctx.ufds'
            '  let tsp = $ctx.tsp'
            '  let sigmask = $ctx.sigmask'
            '  if $ufds { 1 | count }'
            '  if $tsp { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.nfds + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ppoll:field:ufds"
            "tracepoint:syscalls/sys_enter_ppoll:field:tsp"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigmask"
            "tracepoint:syscalls/sys_enter_ppoll:field:nfds"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigsetsize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_epoll_pwait2"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let sigmask = $ctx.sigmask'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.epfd + $ctx.maxevents + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:events"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:timeout"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigmask"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:epfd"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:maxevents"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigsetsize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fanotify_mark"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  ($ctx.fanotify_fd + $ctx.flags + $ctx.mask + $ctx.dfd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:pathname"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:fanotify_fd"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:flags"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:mask"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:dfd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_sync_file_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.offset + $ctx.nbytes + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sync_file_range:field:fd"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:offset"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:nbytes"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioctl"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioctl:field:fd"
            "tracepoint:syscalls/sys_enter_ioctl:field:cmd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_readlinkat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  let buf = $ctx.buf'
            '  if $pathname { 1 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.dfd + $ctx.bufsiz) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readlinkat:field:pathname"
            "tracepoint:syscalls/sys_enter_readlinkat:field:buf"
            "tracepoint:syscalls/sys_enter_readlinkat:field:dfd"
            "tracepoint:syscalls/sys_enter_readlinkat:field:bufsiz"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_name_to_handle_at"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  let handle = $ctx.handle'
            '  let mnt_id = $ctx.mnt_id'
            '  if $name { 1 | count }'
            '  if $handle { 1 | count }'
            '  if $mnt_id { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:name"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:handle"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:mnt_id"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:dfd"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchownat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.user + $ctx.group + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchownat:field:filename"
            "tracepoint:syscalls/sys_enter_fchownat:field:dfd"
            "tracepoint:syscalls/sys_enter_fchownat:field:user"
            "tracepoint:syscalls/sys_enter_fchownat:field:group"
            "tracepoint:syscalls/sys_enter_fchownat:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mknod"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.mode + $ctx.dev) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mknod:field:filename"
            "tracepoint:syscalls/sys_enter_mknod:field:mode"
            "tracepoint:syscalls/sys_enter_mknod:field:dev"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_read"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_read:field:buf"
            "tracepoint:syscalls/sys_enter_read:field:fd"
            "tracepoint:syscalls/sys_enter_read:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_write"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_write:field:buf"
            "tracepoint:syscalls/sys_enter_write:field:fd"
            "tracepoint:syscalls/sys_enter_write:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pread64"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count + $ctx.pos) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pread64:field:buf"
            "tracepoint:syscalls/sys_enter_pread64:field:fd"
            "tracepoint:syscalls/sys_enter_pread64:field:count"
            "tracepoint:syscalls/sys_enter_pread64:field:pos"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_readv"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readv:field:vec"
            "tracepoint:syscalls/sys_enter_readv:field:fd"
            "tracepoint:syscalls/sys_enter_readv:field:vlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_preadv2"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.pos_l + $ctx.pos_h + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_preadv2:field:vec"
            "tracepoint:syscalls/sys_enter_preadv2:field:fd"
            "tracepoint:syscalls/sys_enter_preadv2:field:vlen"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_l"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_h"
            "tracepoint:syscalls/sys_enter_preadv2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_copy_file_range"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:len"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_splice"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_splice:field:off_in"
            "tracepoint:syscalls/sys_enter_splice:field:off_out"
            "tracepoint:syscalls/sys_enter_splice:field:fd_in"
            "tracepoint:syscalls/sys_enter_splice:field:fd_out"
            "tracepoint:syscalls/sys_enter_splice:field:len"
            "tracepoint:syscalls/sys_enter_splice:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattr:field:name"
            "tracepoint:syscalls/sys_enter_setxattr:field:value"
            "tracepoint:syscalls/sys_enter_setxattr:field:size"
            "tracepoint:syscalls/sys_enter_setxattr:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fgetxattr"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fgetxattr:field:name"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:value"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:fd"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  $ctx.size | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattr:field:list"
            "tracepoint:syscalls/sys_enter_listxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattrat:field:name"
            "tracepoint:syscalls/sys_enter_setxattrat:field:uargs"
            "tracepoint:syscalls/sys_enter_setxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_setxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_setxattrat:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattrat:field:list"
            "tracepoint:syscalls/sys_enter_listxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_listxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_listxattrat:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_close"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_close:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let event = $ctx'
            '  let rec = { root: $ctx }'
            '  $event.filename | count'
            '  $rec.root.argv | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  def read_env [event] {'
            '    $event.envp | count'
            '    0'
            '  }'
            '  read_env $ctx'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_connect"
        program: [
            '{|ctx|'
            '  let addr = $ctx.uservaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_connect:field:uservaddr"
            "tracepoint:syscalls/sys_enter_connect:field:fd"
            "tracepoint:syscalls/sys_enter_connect:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_sendto"
        program: [
            '{|ctx|'
            '  let buff = $ctx.buff'
            '  if $buff { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.len + $ctx.flags + $ctx.addr_len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sendto:field:buff"
            "tracepoint:syscalls/sys_enter_sendto:field:addr"
            "tracepoint:syscalls/sys_enter_sendto:field:fd"
            "tracepoint:syscalls/sys_enter_sendto:field:len"
            "tracepoint:syscalls/sys_enter_sendto:field:flags"
            "tracepoint:syscalls/sys_enter_sendto:field:addr_len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_recvfrom"
        program: [
            '{|ctx|'
            '  let ubuf = $ctx.ubuf'
            '  if $ubuf { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  let addr_len = $ctx.addr_len'
            '  if $addr_len { 1 | count }'
            '  ($ctx.fd + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvfrom:field:ubuf"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr_len"
            "tracepoint:syscalls/sys_enter_recvfrom:field:fd"
            "tracepoint:syscalls/sys_enter_recvfrom:field:size"
            "tracepoint:syscalls/sys_enter_recvfrom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_accept4"
        program: [
            '{|ctx|'
            '  let sockaddr = $ctx.upeer_sockaddr'
            '  if $sockaddr { 1 | count }'
            '  let addrlen = $ctx.upeer_addrlen'
            '  if $addrlen { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_sockaddr"
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_addrlen"
            "tracepoint:syscalls/sys_enter_accept4:field:fd"
            "tracepoint:syscalls/sys_enter_accept4:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_socket"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.type + $ctx.protocol) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_socket:field:family"
            "tracepoint:syscalls/sys_enter_socket:field:type"
            "tracepoint:syscalls/sys_enter_socket:field:protocol"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bind:field:umyaddr"
            "tracepoint:syscalls/sys_enter_bind:field:fd"
            "tracepoint:syscalls/sys_enter_bind:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setsockopt:field:optval"
            "tracepoint:syscalls/sys_enter_setsockopt:field:fd"
            "tracepoint:syscalls/sys_enter_setsockopt:field:level"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optname"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_recvmmsg"
        program: [
            '{|ctx|'
            '  let mmsg = $ctx.mmsg'
            '  if $mmsg { 1 | count }'
            '  let timeout = $ctx.timeout'
            '  if $timeout { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvmmsg:field:mmsg"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:timeout"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:fd"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:vlen"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getpeername"
        program: [
            '{|ctx|'
            '  let usockaddr = $ctx.usockaddr'
            '  let usockaddr_len = $ctx.usockaddr_len'
            '  if $usockaddr { 1 | count }'
            '  if $usockaddr_len { 1 | count }'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr"
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr_len"
            "tracepoint:syscalls/sys_enter_getpeername:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getrandom:field:buf"
            "tracepoint:syscalls/sys_enter_getrandom:field:count"
            "tracepoint:syscalls/sys_enter_getrandom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_signalfd4:field:user_mask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:ufd"
            "tracepoint:syscalls/sys_enter_signalfd4:field:sizemask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_io_pgetevents"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let usig = $ctx.usig'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $usig { 1 | count }'
            '  ($ctx.ctx_id + $ctx.min_nr + $ctx.nr) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:events"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:timeout"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:usig"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:ctx_id"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:min_nr"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:nr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioprio_set:field:which"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:who"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:ioprio"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_add_key"
        program: [
            '{|ctx|'
            '  let key_type = $ctx._type'
            '  let description = $ctx._description'
            '  let payload = $ctx._payload'
            '  if $key_type { 1 | count }'
            '  if $description { 1 | count }'
            '  if $payload { 1 | count }'
            '  ($ctx.plen + $ctx.ringid) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_add_key:field:_type"
            "tracepoint:syscalls/sys_enter_add_key:field:_description"
            "tracepoint:syscalls/sys_enter_add_key:field:_payload"
            "tracepoint:syscalls/sys_enter_add_key:field:plen"
            "tracepoint:syscalls/sys_enter_add_key:field:ringid"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mbind:field:nmask"
            "tracepoint:syscalls/sys_enter_mbind:field:start"
            "tracepoint:syscalls/sys_enter_mbind:field:len"
            "tracepoint:syscalls/sys_enter_mbind:field:mode"
            "tracepoint:syscalls/sys_enter_mbind:field:maxnode"
            "tracepoint:syscalls/sys_enter_mbind:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_move_pages"
        program: [
            '{|ctx|'
            '  let pages = $ctx.pages'
            '  let nodes = $ctx.nodes'
            '  let status = $ctx.status'
            '  if $pages { 1 | count }'
            '  if $nodes { 1 | count }'
            '  if $status { 1 | count }'
            '  ($ctx.nr_pages + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_move_pages:field:pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:nodes"
            "tracepoint:syscalls/sys_enter_move_pages:field:status"
            "tracepoint:syscalls/sys_enter_move_pages:field:nr_pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_set_mempolicy_home_node"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.home_node + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:start"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:len"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:home_node"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_open"
        program: [
            '{|ctx|'
            '  let name = $ctx.u_name'
            '  let attr = $ctx.u_attr'
            '  if $name { 1 | count }'
            '  if $attr { 1 | count }'
            '  ($ctx.oflag + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_open:field:u_name"
            "tracepoint:syscalls/sys_enter_mq_open:field:u_attr"
            "tracepoint:syscalls/sys_enter_mq_open:field:oflag"
            "tracepoint:syscalls/sys_enter_mq_open:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_timedreceive"
        program: [
            '{|ctx|'
            '  let msg = $ctx.u_msg_ptr'
            '  let prio = $ctx.u_msg_prio'
            '  let timeout = $ctx.u_abs_timeout'
            '  if $msg { 1 | count }'
            '  if $prio { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.mqdes + $ctx.msg_len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_ptr"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_prio"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_abs_timeout"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:mqdes"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:msg_len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_getsetattr"
        program: [
            '{|ctx|'
            '  let mqstat = $ctx.u_mqstat'
            '  let omqstat = $ctx.u_omqstat'
            '  if $mqstat { 1 | count }'
            '  if $omqstat { 1 | count }'
            '  $ctx.mqdes | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_mqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_omqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:mqdes"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_process_vm_readv"
        program: [
            '{|ctx|'
            '  let lvec = $ctx.lvec'
            '  let rvec = $ctx.rvec'
            '  if $lvec { 1 | count }'
            '  if $rvec { 1 | count }'
            '  ($ctx.liovcnt + $ctx.riovcnt + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:lvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:rvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:liovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:riovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pkey_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot + $ctx.pkey) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:start"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:len"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:prot"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:pkey"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_prlimit64"
        program: [
            '{|ctx|'
            '  let new_rlim = $ctx.new_rlim'
            '  let old_rlim = $ctx.old_rlim'
            '  if $new_rlim { 1 | count }'
            '  if $old_rlim { 1 | count }'
            '  $ctx.resource | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_prlimit64:field:new_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:old_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:resource"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_get_robust_list"
        program: [
            '{|ctx|'
            '  let head_ptr = $ctx.head_ptr'
            '  let len_ptr = $ctx.len_ptr'
            '  if $head_ptr { 1 | count }'
            '  if $len_ptr { 1 | count }'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_get_robust_list:field:head_ptr"
            "tracepoint:syscalls/sys_enter_get_robust_list:field:len_ptr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_rseq"
        program: [
            '{|ctx|'
            '  let user_rseq = $ctx.rseq'
            '  if $user_rseq { 1 | count }'
            '  ($ctx.rseq_len + $ctx.flags + $ctx.sig) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_rseq:field:rseq"
            "tracepoint:syscalls/sys_enter_rseq:field:rseq_len"
            "tracepoint:syscalls/sys_enter_rseq:field:flags"
            "tracepoint:syscalls/sys_enter_rseq:field:sig"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_init_module"
        program: [
            '{|ctx|'
            '  let umod = $ctx.umod'
            '  let uargs = $ctx.uargs'
            '  if $umod { 1 | count }'
            '  if $uargs { 1 | count }'
            '  $ctx.len | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_init_module:field:umod"
            "tracepoint:syscalls/sys_enter_init_module:field:uargs"
            "tracepoint:syscalls/sys_enter_init_module:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_kexec_file_load"
        program: [
            '{|ctx|'
            '  let cmdline = $ctx.cmdline_ptr'
            '  if $cmdline { 1 | count }'
            '  ($ctx.kernel_fd + $ctx.initrd_fd + $ctx.cmdline_len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_ptr"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:kernel_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:initrd_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_len"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_swapon"
        program: [
            '{|ctx|'
            '  let specialfile = $ctx.specialfile'
            '  if $specialfile { 1 | count }'
            '  $ctx.swap_flags | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_swapon:field:specialfile"
            "tracepoint:syscalls/sys_enter_swapon:field:swap_flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_bpf"
        program: [
            '{|ctx|'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  ($ctx.cmd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bpf:field:uattr"
            "tracepoint:syscalls/sys_enter_bpf:field:cmd"
            "tracepoint:syscalls/sys_enter_bpf:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_perf_event_open"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr_uptr'
            '  if $attr { 1 | count }'
            '  ($ctx.group_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_perf_event_open:field:attr_uptr"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:group_fd"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_seccomp"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.op + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_seccomp:field:uargs"
            "tracepoint:syscalls/sys_enter_seccomp:field:op"
            "tracepoint:syscalls/sys_enter_seccomp:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_clone"
        program: [
            '{|ctx|'
            '  let parent_tidptr = $ctx.parent_tidptr'
            '  let child_tidptr = $ctx.child_tidptr'
            '  if $parent_tidptr { 1 | count }'
            '  if $child_tidptr { 1 | count }'
            '  ($ctx.clone_flags + $ctx.newsp + $ctx.tls) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_clone:field:parent_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:child_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:clone_flags"
            "tracepoint:syscalls/sys_enter_clone:field:newsp"
            "tracepoint:syscalls/sys_enter_clone:field:tls"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_syslog:field:buf"
            "tracepoint:syscalls/sys_enter_syslog:field:type"
            "tracepoint:syscalls/sys_enter_syslog:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_personality:field:personality"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:id"
            "tracepoint:syscalls/sys_enter_openat:field:args"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_exit_openat2:field:id"
            "tracepoint:syscalls/sys_exit_openat2:field:ret"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.ifindex | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "fallback"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def wrap [keys] { { keys: $keys } }'
            '  let keys = $ctx.flow_keys'
            '  mut rec = (wrap $keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.state.in.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let input = $ctx.state.in'
            '  $input.ifindex | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  $file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let regs = $ctx.arg0'
            '  $regs.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:access_type" "ctx:device_access" "ctx:device_type" "ctx:major" "ctx:minor"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:bound_dev_if"
            "ctx:family"
            "ctx:mark"
            "ctx:netns_cookie"
            "ctx:priority"
            "ctx:protocol"
            "ctx:rx_queue_mapping"
            "ctx:sk"
            "ctx:sock_type"
            "ctx:socket_cookie"
            "ctx:state"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6" "ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_ip4" "ctx:remote_port" "ctx:sk" "ctx:user_ip4" "ctx:user_port" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:level"
            "ctx:netns_cookie"
            "ctx:optlen"
            "ctx:optname"
            "ctx:optval"
            "ctx:optval_end"
            "ctx:sockopt_retval"
            "helper:bpf_get_netns_cookie"
        ]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:file_pos" "ctx:sysctl_name" "ctx:sysctl_new_value" "helper:bpf_sysctl_get_name"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  $ctx.current_value | count'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:file_pos"
            "ctx:sysctl_base_name"
            "ctx:sysctl_current_value"
            "ctx:sysctl_new_value"
            "ctx:write"
            "helper:bpf_sysctl_get_current_value"
            "helper:bpf_sysctl_get_name"
            "helper:bpf_sysctl_get_new_value"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:args"
            "ctx:cb_flags"
            "ctx:family"
            "ctx:netns_cookie"
            "ctx:op"
            "ctx:remote_port"
            "ctx:reply"
            "ctx:replylong"
            "ctx:sk"
            "ctx:sk_txhash"
            "ctx:socket_cookie"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:bytes_acked"
            "ctx:bytes_received"
            "ctx:data_segs_in"
            "ctx:data_segs_out"
            "ctx:ecn_flags"
            "ctx:is_fullsock"
            "ctx:lost_out"
            "ctx:mss_cache"
            "ctx:packets_out"
            "ctx:rate_delivered"
            "ctx:rate_interval_us"
            "ctx:rcv_nxt"
            "ctx:retrans_out"
            "ctx:rtt_min"
            "ctx:sacked_out"
            "ctx:segs_in"
            "ctx:segs_out"
            "ctx:snd_cwnd"
            "ctx:snd_nxt"
            "ctx:snd_ssthresh"
            "ctx:snd_una"
            "ctx:srtt_us"
            "ctx:state"
            "ctx:total_retrans"
        ]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.protocol + $ctx.ip_protocol + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.cookie + $ctx.ingress_ifindex) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 3)) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "ctx:cookie"
            "ctx:family"
            "ctx:ingress_ifindex"
            "ctx:local_ip4"
            "ctx:local_ip6"
            "ctx:local_port"
            "ctx:protocol"
            "ctx:remote_ip4"
            "ctx:remote_ip6"
            "ctx:remote_port"
        ]
    }
    {
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  $ctx.arg.address.sa_family | count'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value" "helper:bpf_sysctl_get_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value"]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data" "ctx:packet_len" "ctx:eth_protocol" "ctx:protocol" "ctx:hash" "ctx:bind_inany" "ctx:socket_cookie" "ctx:sk" "ctx:family" "ctx:mark" "ctx:priority" "ctx:rx_queue_mapping" "helper:bpf_get_socket_cookie" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = ($ctx | get data)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event | get data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { data: ($ctx | get data) })'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get data) data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: null } | update data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: ($ctx | get data), keep: 1 } | select data keep | reject keep | rename packet)'
            '  $rec.packet.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: ($ctx | get data) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  mut rec = { data: (id ($ctx | get data)) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  let data = $ctx.data'
            '  mut rec = (wrap $data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: $ctx.data_meta }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: ($ctx | get data_meta) }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert meta ($ctx | get data_meta))'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut meta = ($ctx | get data_meta)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event | get data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let base = { meta: $ctx.data_meta }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def wrap [meta] { { meta: $meta } }'
            '  let meta = $ctx.data_meta'
            '  mut rec = (wrap $meta)'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.2) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:socket_cookie" "ctx:socket_uid" "ctx:sk" "ctx:family" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_socket_cookie" "helper:bpf_get_socket_uid" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.cb.3) | count'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:cgroup_classid" "ctx:route_realm" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_cgroup_classid" "helper:bpf_get_route_realm"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.queue_mapping = 1'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:queue_mapping" "ctx:cb" "ctx:tc_classid" "ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = (if $ctx.pid == 0 { 7 } else { 1 })'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|event|'
            '  mut event = $event'
            '  $event.mark = 7'
            '  $event.priority = 3'
            '  $event.cb.1 = 9'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:priority" "ctx:cb"]
    }
    {
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_meta" "ctx:iter_task" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_file" "helper:bpf_probe_read_kernel"]
    }
]

const PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let text = "tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer"'
            '  # tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer'
            '  let ignored = 0 # | tail-call prog 0 | emit | count | histogram | start-timer | stop-timer | adjust-message --pull 0 1 | adjust-packet --head 0 | redirect-socket peers 0 --kind sockhash | redirect --peer'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_redirect_map"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  adjust-packet --meta 0'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_xdp_adjust_head"
            "helper:bpf_xdp_adjust_meta"
            "helper:bpf_xdp_adjust_tail"
        ]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  adjust-packet --head 0'
            '  adjust-packet --tail 0'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_skb_pull_data"
            "helper:bpf_skb_change_head"
            "helper:bpf_skb_change_tail"
            "helper:bpf_skb_adjust_room"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  adjust-message --cork 8'
            '  adjust-message --pull 0 1'
            '  adjust-message --push 0 1'
            '  adjust-message --pop 0 1'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_msg_apply_bytes"
            "helper:bpf_msg_cork_bytes"
            "helper:bpf_msg_pull_data"
            "helper:bpf_msg_push_data"
            "helper:bpf_msg_pop_data"
            "helper:bpf_msg_redirect_map"
            "helper:bpf_msg_redirect_hash"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket hash_peers 1'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0'
            '  redirect-socket hash_peers "peer-b"'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_sk_redirect_map"
            "helper:bpf_sk_redirect_hash"
        ]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  "select"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_select_reuseport"]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|event|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let text = "$ctx.sk = 0; $ctx.sk == 0"'
            '  # $ctx.sk = 0'
            '  if $ctx.sk == 0 { 0 }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|event|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut writable = (passthrough $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let text = "$ctx.new_value = 1"'
            '  # $ctx.new_value = 1'
            '  if $ctx.new_value == 1 { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc_action:demo"
        program: [
            '{|event|'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  let text = "$event.cb_flags = 1"'
            '  # $event.cb_flags = 1'
            '  if $event.cb_flags == 1 { 0 }'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_state --kind task-storage --value-type "record{hits:u64}"'
            '  $ctx.task | map-get task_state --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-contains task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_get"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-delete sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_delete"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_get"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_delete"]
    }
]

const PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "helper-call \"bpf_trace_printk\" \"ignored\" 7"'
            '  # helper-call "bpf_map_lookup_elem" ignored key'
            '  let ignored = 0 # | helper-call "bpf_ktime_get_ns"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_get_func_arg"
            "helper:bpf_get_func_ret"
            "helper:bpf_get_func_arg_cnt"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define nsdata --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_get_ns_current_pid_tgid"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_classid" $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_skb_cgroup_classid"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_fib_lookup"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_check_mtu"]
    }
    {
        program: [
            '{|ctx|'
            '  let key = "01234567"'
            '  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values $key 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_map_lookup_percpu_elem"]
    }
    {
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_lookup_tcp" "helper:bpf_sk_release"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}'
            '    helper-call "bpf_timer_start" $entry.timer 1000 0'
            '    helper-call "bpf_timer_cancel" $entry.timer'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_timer_init"
            "helper:bpf_timer_set_callback"
            "helper:bpf_timer_start"
            "helper:bpf_timer_cancel"
        ]
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let text = "kfunc-call \"bpf_task_from_pid\" 1"'
            '  # kfunc-call "bpf_task_from_pid" 1'
            '  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_rcu_read_lock" "kfunc:bpf_rcu_read_unlock"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_preempt_disable" "kfunc:bpf_preempt_enable"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_local_irq_save" "kfunc:bpf_local_irq_restore"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        feature_keys: [
            "kfunc:bpf_res_spin_lock"
            "kfunc:bpf_res_spin_unlock"
            "kfunc:bpf_res_spin_lock_irqsave"
            "kfunc:bpf_res_spin_unlock_irqrestore"
        ]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  let text = "$event.sun_path = /tmp/nu-ebpf.sock"'
            '  # $event.sun_path = /tmp/nu-ebpf.sock'
            '  if $event.sun_path == "/tmp/nu-ebpf.sock" { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.4"
            source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c"
        }
    }
    {
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }
]

const PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $timer.id | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $m.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $vma.vm_start | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]
