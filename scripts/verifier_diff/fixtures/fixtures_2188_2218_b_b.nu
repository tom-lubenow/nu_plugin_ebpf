const VERIFIER_DIFF_FIXTURES_2188_2218_B_B = [
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-head-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --head 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-head-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --meta 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
