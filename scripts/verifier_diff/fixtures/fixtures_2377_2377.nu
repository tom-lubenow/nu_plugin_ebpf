const VERIFIER_DIFF_FIXTURES_2377_2377 = [
    {
        name: "stack-map-delete-rejects-kind"
        category: "maps"
        tags: [maps stack map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete recent_args --kind stack'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map delete is not supported for map kind stack"
    }
]
