[
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
]
