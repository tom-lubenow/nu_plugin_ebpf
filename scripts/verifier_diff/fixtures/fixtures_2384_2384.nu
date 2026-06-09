const VERIFIER_DIFF_FIXTURES_2384_2384 = [
    {
        name: "reuseport-sockarray-map-delete-rejects-socket-selection-kind"
        category: "maps"
        tags: [maps reuseport-sockarray map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete sockets --kind reuseport-sockarray'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind reuseport-sockarray is reserved for sk_reuseport socket selection"
    }
]
