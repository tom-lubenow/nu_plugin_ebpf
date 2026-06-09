const VERIFIER_DIFF_FIXTURES_2399_2399 = [
    {
        name: "map-define-rejects-unknown-kind"
        category: "maps"
        tags: [maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind must name a recognized value-carrying map family"
    }
]
