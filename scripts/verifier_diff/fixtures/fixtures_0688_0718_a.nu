const VERIFIER_DIFF_FIXTURES_0688_0718_A = [
    {
        name: "tc-skb-get-xfrm-state-helper"
        category: "helper-state"
        tags: [tc helper xfrm accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdefghijklmnopqr"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 28 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-xfrm-state-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-vlan-push-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-pop-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_pop" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-push-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-vlan-push-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
