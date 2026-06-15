const VERIFIER_DIFF_FIXTURES_0782_0812_A_B = [
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-non-tc"
        category: "helper-state"
        tags: [helper xfrm reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states --kind array)'
            '  if $state { helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds dynamic reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states_dyn_short --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states_dyn_short --kind array)'
            '  if $state {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state $size 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-egress-helper-backed-context"
        category: "context-surface"
        tags: [tc context helper-backed egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
