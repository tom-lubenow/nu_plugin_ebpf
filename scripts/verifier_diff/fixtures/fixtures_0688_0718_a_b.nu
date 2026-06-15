const VERIFIER_DIFF_FIXTURES_0688_0718_A_B = [
    {
        name: "tc-skb-change-proto-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-proto-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-proto-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
]
