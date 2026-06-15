const VERIFIER_DIFF_FIXTURES_2219_2250_B = [
    {
        name: "redirect-lwt-xmit-ifindex"
        category: "language-surface"
        tags: [redirect lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-map-xdp-devmap"
        category: "language-surface"
        tags: [redirect-map xdp map]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-devmap-hash"
        category: "language-surface"
        tags: [redirect-map xdp map devmap-hash]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap-hash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-cpumap"
        category: "language-surface"
        tags: [redirect-map xdp map cpumap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-xskmap"
        category: "language-surface"
        tags: [redirect-map xdp map xskmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map xsks 0 --kind xskmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-prog-array"
        category: "language-surface"
        tags: [tail-call prog-array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-helper-xdp-rejects-stale-data"
        category: "language-surface"
        tags: [tail-call xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_tail_call" $ctx jumps 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
]
