const VERIFIER_DIFF_FIXTURES_3025_3034 = [
    {
        name: "adjust-packet-head-rejects-mode"
        category: "language-surface"
        tags: [adjust-packet xdp diagnostics reject flags]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head --mode 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet --head does not accept --mode"
    }
    {
        name: "adjust-packet-head-rejects-flags"
        category: "language-surface"
        tags: [adjust-packet xdp diagnostics reject flags]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet --head does not accept --flags"
    }
    {
        name: "adjust-packet-room-rejects-missing-mode"
        category: "language-surface"
        tags: [adjust-packet tc diagnostics reject flags]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  adjust-packet --room 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet --room requires --mode"
    }
    {
        name: "adjust-packet-head-rejects-missing-delta"
        category: "language-surface"
        tags: [adjust-packet xdp diagnostics reject arguments]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet --head requires a delta from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-apply-rejects-flags"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject flags]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --apply --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --apply does not accept --flags"
    }
    {
        name: "adjust-message-pull-rejects-missing-start"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --pull'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --pull requires start from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-pull-rejects-missing-end"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --pull requires a end as the second positional argument"
    }
    {
        name: "redirect-rejects-missing-ifindex"
        category: "language-surface"
        tags: [redirect xdp diagnostics reject arguments]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect requires an ifindex from pipeline input or a first positional argument"
    }
    {
        name: "redirect-map-rejects-missing-key"
        category: "language-surface"
        tags: [redirect-map xdp diagnostics reject arguments]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map requires a key from pipeline input or a second positional argument"
    }
    {
        name: "redirect-socket-rejects-missing-key"
        category: "language-surface"
        tags: [redirect-socket sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  redirect-socket socks --kind sockmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket requires a key from pipeline input or a second positional argument"
    }
]
