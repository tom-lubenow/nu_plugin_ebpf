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
        error_contains: "map-delete is not supported for socket map kind sockhash"
    }
]
