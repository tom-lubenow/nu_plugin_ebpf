const VERIFIER_DIFF_FIXTURES_2352_2352 = [
    {
        name: "queue-map-delete-rejects-kind"
        category: "maps"
        tags: [maps queue map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete recent_args --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map delete is not supported for map kind"
    }
]
