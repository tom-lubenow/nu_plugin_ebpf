const VERIFIER_DIFF_FIXTURES_0626_0656_B_B = [
    {
        name: "tc-context-get-scalar"
        category: "context-surface"
        tags: [tc context get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-packet-data-read"
        category: "context-surface"
        tags: [tc context packet get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-chain"
        category: "context-surface"
        tags: [tc context socket get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-bound-root"
        category: "context-surface"
        tags: [tc context socket get alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
