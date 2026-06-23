export const VERIFIER_DIFF_FIXTURES_3866_3866 = [
    {
        name: "sockmap-map-contains-rejects-socket-map-kind"
        category: "maps"
        tags: [maps sockmap map-contains diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  if (0 | map-contains active_sockmap --kind sockmap) { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-put from sock_ops for updates or redirect-socket from sk_msg/sk_skb"
    }
]
