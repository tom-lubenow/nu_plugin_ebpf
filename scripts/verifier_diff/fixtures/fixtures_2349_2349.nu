const VERIFIER_DIFF_FIXTURES_2349_2349 = [
    {
        name: "bloom-filter-map-peek-rejects-kind"
        category: "maps"
        tags: [maps bloom-filter map-peek diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter'
            '  map-peek seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-push to insert values and map-contains --kind bloom-filter"
    }
]
