const VERIFIER_DIFF_FIXTURES_2353_2353 = [
    {
        name: "bloom-filter-map-delete-rejects-kind"
        category: "maps"
        tags: [maps bloom-filter map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind bloom-filter is not deletable"
    }
]
