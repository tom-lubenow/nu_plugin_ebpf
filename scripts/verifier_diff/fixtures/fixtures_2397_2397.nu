const VERIFIER_DIFF_FIXTURES_2397_2397 = [
    {
        name: "map-contains-rejects-unknown-kind"
        category: "maps"
        tags: [maps map-contains diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-contains seen 0 --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-contains --kind must be one of"
    }
]
