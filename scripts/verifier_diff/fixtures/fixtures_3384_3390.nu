export const VERIFIER_DIFF_FIXTURES_3384_3390 = [
    {
        name: "redirect-xdp-ifindex-flags-zero"
        category: "language-surface"
        tags: [redirect xdp flags accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect --flags 0 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-xdp-rejects-nonzero-flags"
        category: "language-surface"
        tags: [redirect xdp flags reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect' requires arg1 = 0 in xdp programs"
    }
    {
        name: "redirect-tc-action-ingress-flag"
        category: "language-surface"
        tags: [redirect tc-action flags accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --flags 1 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer-flags-zero"
        category: "language-surface"
        tags: [redirect peer tc-action flags accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer --flags 0 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer-rejects-nonzero-flags"
        category: "language-surface"
        tags: [redirect peer tc-action flags reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
    {
        name: "redirect-tc-action-neigh-flags-zero"
        category: "language-surface"
        tags: [redirect neigh tc-action flags accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh --flags 0 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-neigh-rejects-nonzero-flags"
        category: "language-surface"
        tags: [redirect neigh tc-action flags reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg3 = 0"
    }
]
