const VERIFIER_DIFF_FIXTURES_3046_3053 = [
    {
        name: "redirect-map-rejects-empty-map-name"
        category: "language-surface"
        tags: [redirect-map xdp diagnostics reject maps]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map "" 0 --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map map name must not be empty"
    }
    {
        name: "redirect-map-rejects-invalid-map-name"
        category: "language-surface"
        tags: [redirect-map xdp diagnostics reject maps]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map "bad-name" 0 --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map map name 'bad-name' must match [A-Za-z_][A-Za-z0-9_]*"
    }
    {
        name: "redirect-map-rejects-missing-kind"
        category: "language-surface"
        tags: [redirect-map xdp diagnostics reject maps]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap"
    }
    {
        name: "redirect-map-rejects-non-redirect-kind"
        category: "language-surface"
        tags: [redirect-map xdp diagnostics reject maps]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind hash'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap, got hash"
    }
    {
        name: "redirect-socket-rejects-invalid-map-name"
        category: "language-surface"
        tags: [redirect-socket sk-msg diagnostics reject maps]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  redirect-socket "bad-name" 0 --kind sockmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket map name 'bad-name' must match [A-Za-z_][A-Za-z0-9_]*"
    }
    {
        name: "redirect-socket-rejects-missing-kind"
        category: "language-surface"
        tags: [redirect-socket sk-msg diagnostics reject maps]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  redirect-socket socks 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket requires --kind sockmap, --kind sockhash, or --kind reuseport-sockarray"
    }
    {
        name: "redirect-socket-rejects-non-socket-kind"
        category: "language-surface"
        tags: [redirect-socket sk-msg diagnostics reject maps]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  redirect-socket socks 0 --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket requires --kind sockmap, --kind sockhash, or --kind reuseport-sockarray, got devmap"
    }
    {
        name: "redirect-socket-rejects-dynamic-flags"
        category: "language-surface"
        tags: [redirect-socket sk-msg diagnostics reject flags]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  redirect-socket socks 0 --kind sockmap --flags $ctx.size'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --flags must be a compile-time integer literal"
    }
]
