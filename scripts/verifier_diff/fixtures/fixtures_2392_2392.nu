const VERIFIER_DIFF_FIXTURES_2392_2392 = [
    {
        name: "map-get-rejects-unknown-kind"
        category: "maps"
        tags: [maps map-get diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = (0 | map-get seen --kind mystery-map-kind)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind must name a recognized map family"
    }
]
