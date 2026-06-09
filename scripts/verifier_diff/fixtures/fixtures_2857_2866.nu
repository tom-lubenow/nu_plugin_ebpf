const VERIFIER_DIFF_FIXTURES_2857_2866 = [
    {
        name: "cgroup-skb-sk-ancestor-cgroup-id-rejects-missing-level"
        category: "context-policy"
        tags: [cgroup-skb socket context diagnostics reject cgroup path]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  $ctx.sk.ancestor_cgroup_id'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'sk.ancestor_cgroup_id' requires a constant numeric ancestor level"
    }
    {
        name: "cgroup-skb-sk-ancestor-cgroup-id-rejects-negative-level"
        category: "context-policy"
        tags: [cgroup-skb socket context diagnostics reject cgroup path bounds]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  $ctx.sk.ancestor_cgroup_id.-1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'sk.ancestor_cgroup_id.18446744073709551615' requires ancestor level 0..2147483647"
    }
    {
        name: "sk-msg-sk-ancestor-cgroup-id-rejects-helper-policy"
        category: "context-policy"
        tags: [sk-msg socket context diagnostics reject cgroup helper]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.sk.ancestor_cgroup_id.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_ancestor_cgroup_id' is only valid in cgroup_skb programs"
    }
    {
        name: "tc-ingress-skb-ancestor-cgroup-id-rejects-helper-policy"
        category: "context-policy"
        tags: [tc context diagnostics reject cgroup helper ingress]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_ancestor_cgroup_id.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_ancestor_cgroup_id' is only valid in tc/tcx egress programs"
    }
    {
        name: "tc-egress-skb-ancestor-cgroup-id-rejects-missing-level"
        category: "context-policy"
        tags: [tc context diagnostics reject cgroup path egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  $ctx.skb_ancestor_cgroup_id'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_ancestor_cgroup_id requires a constant numeric ancestor level"
    }
    {
        name: "tc-egress-skb-ancestor-cgroup-id-rejects-negative-level"
        category: "context-policy"
        tags: [tc context diagnostics reject cgroup path bounds egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  $ctx.skb_ancestor_cgroup_id.-1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_ancestor_cgroup_id requires ancestor level 0..2147483647"
    }
    {
        name: "sk-lookup-sk-tcp-projection-rejects-helper-policy"
        category: "context-policy"
        tags: [sk-lookup socket context diagnostics reject tcp helper]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.sk.tcp.snd_cwnd'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_tcp_sock' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sockopt, and sock_ops programs"
    }
    {
        name: "sk-lookup-sk-listener-projection-rejects-helper-policy"
        category: "context-policy"
        tags: [sk-lookup socket context diagnostics reject listener helper]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.sk.listener.family'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_listener_sock' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "xdp-current-cgroup-short-alias-rejects-context-policy"
        category: "context-policy"
        tags: [xdp context diagnostics reject cgroup alias]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.cgroup'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.cgroup is not available on xdp programs"
    }
    {
        name: "xdp-current-cgroup-long-alias-rejects-context-policy"
        category: "context-policy"
        tags: [xdp context diagnostics reject cgroup alias]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.current_cgroup is not available on xdp programs"
    }
]
