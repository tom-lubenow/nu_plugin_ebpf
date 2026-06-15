const VERIFIER_DIFF_FIXTURES_0188_0218_B_C = [
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
]
