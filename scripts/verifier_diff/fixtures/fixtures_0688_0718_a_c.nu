const VERIFIER_DIFF_FIXTURES_0688_0718_A_C = [
    {
        name: "tc-skb-change-tail-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-change-tail-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-tail-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_tail" $ctx 64 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_tail' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_head" $ctx 14 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_head" $ctx 14 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-adjust-room-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
