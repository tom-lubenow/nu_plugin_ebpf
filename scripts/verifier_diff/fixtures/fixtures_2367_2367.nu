const VERIFIER_DIFF_FIXTURES_2367_2367 = [
    {
        name: "sockhash-map-put-rejects-non-sock-ops-target"
        category: "maps"
        tags: [maps sockhash map-put diagnostics reject program-policy]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put active_sockhash $ctx.pid --kind sockhash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-put from sock_ops for socket-map updates or redirect-socket from sk_msg/sk_skb"
    }
]
