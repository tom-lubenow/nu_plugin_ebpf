const VERIFIER_DIFF_FIXTURES_0188_0218_B = [
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
