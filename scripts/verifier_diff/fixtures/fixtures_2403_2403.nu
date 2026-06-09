const VERIFIER_DIFF_FIXTURES_2403_2403 = [
    {
        name: "sockmap-map-define-rejects-socket-map-kind"
        category: "maps"
        tags: [maps sockmap map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sockets --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind sockmap names a socket map"
    }
]
