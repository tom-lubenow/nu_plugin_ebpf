const VERIFIER_DIFF_FIXTURES_2359_2359 = [
    {
        name: "prog-array-map-put-rejects-kind"
        category: "maps"
        tags: [maps prog-array map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put programs 0 --kind prog-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put --kind prog-array is reserved for program-array maps"
    }
]
