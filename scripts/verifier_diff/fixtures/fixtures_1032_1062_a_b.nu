const VERIFIER_DIFF_FIXTURES_1032_1062_A_B = [
    {
        name: "sk-skb-parser-rejects-mark-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.mark | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-tstamp-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-skb-parser reject context writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-skb-parser-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser reject]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs"
    }
]
