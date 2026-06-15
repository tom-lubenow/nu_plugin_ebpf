const VERIFIER_DIFF_FIXTURES_0782_0812_B_B = [
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-interface"
        category: "context-policy"
        tags: [xdp reject devmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-cpumap"
        category: "context-policy"
        tags: [xdp reject cpumap devmap]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "socket-filter-tcp6-context"
        category: "context-surface"
        tags: [socket-filter context ipv6]
        target: "socket_filter:tcp6:[::1]:8080"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rich-skb-context"
        category: "context-surface"
        tags: [socket-filter context packet source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.pkt_type + $ctx.queue_mapping + $ctx.protocol + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.hash + $ctx.mark + $ctx.priority) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.0) | count'
            '  "keep"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
