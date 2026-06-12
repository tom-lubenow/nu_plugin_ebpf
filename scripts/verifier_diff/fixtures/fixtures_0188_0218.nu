const VERIFIER_DIFF_FIXTURES_0188_0218 = [
    {
        name: "fentry-array-element-context"
        category: "tracing"
        tags: [fentry context array]
        requires: [kernel-btf]
        target: "fentry:wake_up_new_task"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.comm.0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-sleepable-context"
        category: "tracing"
        tags: [fentry sleepable context]
        requires: [kernel-btf]
        target: "fentry.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-context"
        category: "tracing"
        tags: [fexit context]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-func-arg-ret-helper-calls"
        category: "tracing"
        tags: [fexit helper-call context source metadata]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-func-ret-helper-reject"
        category: "tracing"
        tags: [fentry helper-call context reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let retval = "01234567"'
            '  helper-call "bpf_get_func_ret" $ctx $retval'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ret' is only valid in fexit and fmod_ret programs"
    }
    {
        name: "fentry-missing-target-help-reject"
        category: "tracing"
        tags: [fentry context diagnostic reject]
        requires: [kernel-btf]
        target: "fentry:nu_plugin_ebpf_missing_function_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "target signature"
    }
    {
        name: "fexit-sleepable-context"
        category: "tracing"
        tags: [fexit sleepable context]
        requires: [kernel-btf]
        target: "fexit.s:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-context"
        category: "tracing"
        tags: [fmod-ret context]
        requires: [kernel-btf]
        target: "fmod_ret:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-sleepable-context"
        category: "tracing"
        tags: [fmod-ret sleepable context]
        requires: [kernel-btf]
        target: "fmod_ret.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-context"
        category: "tracing"
        tags: [lsm context]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-sleepable-context"
        category: "tracing"
        tags: [lsm sleepable context]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bound-arg-context"
        category: "tracing"
        tags: [lsm context alias]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  ($file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-missing-target-help-reject"
        category: "tracing"
        tags: [lsm context diagnostic reject]
        requires: [kernel-btf]
        target: "lsm:nu_plugin_ebpf_missing_hook_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "LSM hook name"
    }
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg_count is only available on BTF-backed tracing contexts with bpf_get_func_arg_cnt support"
    }
    {
        name: "lsm-cgroup-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-cgroup-live-target-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg cgroup-path source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:/sys/fs/cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-helper-context"
        category: "tracing"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  helper-call "bpf_sys_close" 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-context"
        category: "tracing"
        tags: [freplace context]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-rejects-context-field"
        category: "context-policy"
        tags: [syscall context reject]
        target: "syscall:demo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on syscall programs"
    }
    {
        name: "freplace-rejects-arg-context"
        category: "context-policy"
        tags: [freplace context reject]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg0 is only available on contexts with argument access"
    }
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-derived-header-fields"
        category: "packet"
        tags: [xdp packet header bitfield source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = ($ctx.data.eth.ipv4.version + $ctx.data.eth.ipv4.ihl + $ctx.data.eth.ipv4.dscp + $ctx.data.eth.ipv4.ecn + $ctx.data.eth.ipv4.flags + $ctx.data.eth.ipv4.dont_fragment + $ctx.data.eth.ipv4.more_fragments + $ctx.data.eth.ipv4.fragment_offset)'
            '  let ip6 = ($ctx.data.eth.ipv6.version + $ctx.data.eth.ipv6.traffic_class + $ctx.data.eth.ipv6.flow_label)'
            '  let tcp = ($ctx.data.eth.ipv4.tcp.data_offset + $ctx.data.eth.ipv4.tcp.flags + $ctx.data.eth.ipv4.tcp.syn)'
            '  ($ip4 + $ip6 + $tcp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-bitfield-writes"
        category: "packet"
        tags: [xdp packet header bitfield write source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.ipv4.version = 4'
            '  $ctx.data.eth.ipv4.flags = 2'
            '  $ctx.data.eth.ipv4.tcp.syn = 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-arp-header-fields"
        category: "packet"
        tags: [xdp packet header arp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let arp = ($ctx.data.eth.arp.hardware_type + $ctx.data.eth.arp.protocol_type + $ctx.data.eth.arp.hardware_len + $ctx.data.eth.arp.protocol_len + $ctx.data.eth.arp.opcode)'
            '  $arp | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-header-field-aliases"
        category: "packet"
        tags: [xdp packet header alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let eth = $ctx.data.eth.h_proto'
            '  let ip4 = ($ctx.data.eth.ipv4.tot_len + $ctx.data.eth.ipv4.saddr.0 + $ctx.data.eth.ipv4.daddr.0)'
            '  let udp = ($ctx.data.eth.ipv4.udp.source + $ctx.data.eth.ipv4.udp.dest)'
            '  ($eth + $ip4 + $udp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-icmp-echo-fields"
        category: "packet"
        tags: [xdp packet header icmp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let icmp4 = ($ctx.data.eth.ipv4.icmp.rest_of_header + $ctx.data.eth.ipv4.icmp.echo_id + $ctx.data.eth.ipv4.icmp.echo_sequence)'
            '  let icmp6 = ($ctx.data.eth.ipv6.icmpv6.rest + $ctx.data.eth.ipv6.icmpv6.identifier + $ctx.data.eth.ipv6.icmpv6.sequence)'
            '  ($icmp4 + $icmp6) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-frags-driver-context"
        category: "context-surface"
        tags: [xdp context frags]
        requires: [loopback-interface]
        target: "xdp:lo:drv:frags"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.rx_queue_index + $ctx.xdp_buff_len + $ctx.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-devmap-secondary-context"
        category: "program-model"
        tags: [xdp devmap context]
        target: "xdp:devmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.egress_ifindex) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-cpumap-secondary-context"
        category: "program-model"
        tags: [xdp cpumap context]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.rx_queue_index) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-target-metadata"
        category: "program-model"
        tags: [tcx metadata]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-peer-target-metadata"
        category: "program-model"
        tags: [netkit metadata]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-target-metadata"
        category: "program-model"
        tags: [flow-dissector metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
