export const VERIFIER_DIFF_FIXTURES_3378_3383 = [
    {
        name: "redirect-map-xdp-devmap-flags-zero"
        category: "language-surface"
        tags: [redirect-map xdp map flags accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap --flags 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-rejects-invalid-flags"
        category: "language-surface"
        tags: [redirect-map xdp map flags reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap --flags 32'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_map' requires arg2 flags"
    }
    {
        name: "redirect-socket-sk-msg-sockmap-flags-zero"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap flags accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap --flags 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-rejects-invalid-flags"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap --flags 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-socket-sk-reuseport-flags-zero"
        category: "language-surface"
        tags: [redirect-socket sk-reuseport reuseport-sockarray flags accept]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray --flags 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-tc-ingress-flags-zero"
        category: "language-surface"
        tags: [assign-socket tc flags accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  assign-socket 0 --flags 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
