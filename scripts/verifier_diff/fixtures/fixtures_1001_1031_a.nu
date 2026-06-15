const VERIFIER_DIFF_FIXTURES_1001_1031_A = [
    {
        name: "sk-reuseport-rejects-migrating-sk-on-packet-context"
        category: "context-policy"
        tags: [sk-reuseport reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.migrating_sk | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.migrating_sk is only available on sk_reuseport programs"
    }
    {
        name: "sk-reuseport-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-reuseport reject context writable]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-reuseport-rejects-skb-pkt-type-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.pkt_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pkt_type is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-reuseport-rejects-skb-vlan-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.vlan_tci | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.vlan_tci is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
]
