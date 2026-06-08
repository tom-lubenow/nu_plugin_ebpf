const VERIFIER_DIFF_FIXTURES_2356_2356 = [
    {
        name: "sockmap-map-delete-rejects-kind"
        category: "maps"
        tags: [maps sockmap map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete sockets --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete is not supported for socket map kind"
    }
]
