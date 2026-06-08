const VERIFIER_DIFF_FIXTURES_2351_2351 = [
    {
        name: "array-map-delete-rejects-kind"
        category: "maps"
        tags: [maps array map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete counters --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map delete is not supported for array map kind"
    }
]
