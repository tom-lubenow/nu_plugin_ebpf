const VERIFIER_DIFF_FIXTURES_2219_2250_A_C = [
    {
        name: "redirect-xdp-ifindex"
        category: "language-surface"
        tags: [redirect xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-ifindex"
        category: "language-surface"
        tags: [redirect tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer"
        category: "language-surface"
        tags: [redirect peer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-neigh"
        category: "language-surface"
        tags: [redirect neigh tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tc]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-tcx-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tcx]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
]
