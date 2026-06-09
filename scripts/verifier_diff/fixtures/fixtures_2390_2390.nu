const VERIFIER_DIFF_FIXTURES_2390_2390 = [
    {
        name: "map-delete-rejects-unknown-kind"
        category: "maps"
        tags: [maps map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete seen --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind must name a recognized map family"
    }
]
