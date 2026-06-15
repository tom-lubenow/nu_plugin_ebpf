const VERIFIER_DIFF_FIXTURES_0688_0718_B = [
    {
        name: "tc-skb-adjust-room-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags"
    }
    {
        name: "tc-skb-change-type-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_type" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-ecn-set-ce-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_ecn_set_ce" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-rejects-invalid-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-dynamic-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstype = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 $tstype'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-nonzero-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-dynamic-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstamp = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx $tstamp 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
]
