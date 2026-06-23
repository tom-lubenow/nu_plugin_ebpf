export const VERIFIER_DIFF_FIXTURES_3867_3867 = [
    {
        name: "sockmap-map-push-rejects-socket-map-kind"
        category: "maps"
        tags: [maps sockmap map-push diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push active_sockmap --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-put from sock_ops for updates or redirect-socket from sk_msg/sk_skb"
    }
]
