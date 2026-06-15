const VERIFIER_DIFF_FIXTURES_2219_2250_A = [
    {
        name: "adjust-packet-xdp-meta-subfn-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  shift'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-subfn-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  shift'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --tail 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-tail-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
