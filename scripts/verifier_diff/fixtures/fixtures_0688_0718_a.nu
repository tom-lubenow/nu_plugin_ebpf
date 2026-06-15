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
]
