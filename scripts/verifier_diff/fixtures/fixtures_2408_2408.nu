const VERIFIER_DIFF_FIXTURES_2408_2408 = [
    {
        name: "reuseport-sockarray-map-define-rejects-socket-selection-kind"
        category: "maps"
        tags: [maps reuseport-sockarray map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sockets --kind reuseport-sockarray'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind reuseport-sockarray is reserved for sk_reuseport socket selection"
    }
]
