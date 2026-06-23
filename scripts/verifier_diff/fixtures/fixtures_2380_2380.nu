const VERIFIER_DIFF_FIXTURES_2380_2380 = [
    {
        name: "sockhash-map-delete-rejects-socket-map-kind"
        category: "maps"
        tags: [maps sockhash map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete sockets --kind sockhash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-put from sock_ops for updates or redirect-socket from sk_msg/sk_skb"
    }
]
