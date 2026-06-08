const VERIFIER_DIFF_FIXTURES_2350_2350 = [
    {
        name: "bloom-filter-map-pop-rejects-kind"
        category: "maps"
        tags: [maps bloom-filter map-pop diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-pop seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-pop requires --kind queue or --kind stack, got bloom-filter"
    }
]
