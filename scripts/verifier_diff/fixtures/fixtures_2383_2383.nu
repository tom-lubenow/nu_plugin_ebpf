const VERIFIER_DIFF_FIXTURES_2383_2383 = [
    {
        name: "prog-array-map-delete-rejects-tail-call-map-kind"
        category: "maps"
        tags: [maps prog-array map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete jumps --kind prog-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind prog-array is reserved for program-array maps"
    }
]
